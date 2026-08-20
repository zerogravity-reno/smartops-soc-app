"""The Bedrock imported-model client for the domain analysts.

Foundation-Sec-8B-Reasoning is a *custom-imported* Bedrock model (Llama-3.1-8B),
so it is driven by raw `invoke_model` with a text `prompt` -- not the Converse API
the rest of the app uses, and with no tool-calling or structured output. The
prompt template and payload here are the single source of truth, confirmed from
the model's own `tokenizer_config.json` / `special_tokens_map.json`:

- special tokens `<|system|>`, `<|user|>`, `<|assistant|>`, `<think>`, `</think>`
- the generation prompt seeds `<|assistant|>\n<think>\n`, so the model begins its
  reasoning immediately and emits `</think>` before its final answer
- request `{prompt, max_gen_len, temperature, top_p}`; response
  `{generation, prompt_token_count, generation_token_count, stop_reason}`
- `repetition_penalty` (1.1 in the model config) cannot be passed via Bedrock's
  Llama schema and stays a baked-in default.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from smartops.errors import NotConfigured

logger = logging.getLogger(__name__)

MODEL_ARN_ENV_VAR = "SMARTOPS_ANALYST_MODEL_ARN"
REGION_ENV_VAR = "AWS_REGION"
# Optional dedicated credential for the imported Cisco model. Two accepted forms,
# matching the SAMA chat_bedrock.py probe: an `ABSK...` Bedrock API key (a bearer
# token), or `ACCESS_KEY:SECRET_KEY[:SESSION_TOKEN]`. If unset, boto3's normal
# credential chain (env, profile, role) is used.
API_KEY_ENV_VAR = "SMARTOPS_ANALYST_API_KEY"

# Confirmed defaults from the model's generation_config.json. Temperature is
# configurable; drop toward 0.3 for steadier verdicts, keep 0.6 for the reasoning
# diversity the model was tuned for.
DEFAULT_TEMPERATURE = 0.6
DEFAULT_TOP_P = 0.95
# In tokens. Reasoning needs room; kept well under the 32,768 window so the prompt
# has space. The caller is responsible for prompt size (see `packing`).
DEFAULT_MAX_GEN_LEN = 3072

# A Bedrock CUSTOM-IMPORTED model is evicted when idle and must be loaded on the
# next call, which surfaces as `ModelNotReadyException` for the first minute or two
# of a cold run. That is expected, not an error, so `invoke` waits and retries
# rather than failing the whole analysis. Defaults cover a ~4 minute warm-up
# (8 * 30s); override via env in `analyst_model_from_env`.
DEFAULT_READY_RETRIES = 8
DEFAULT_READY_WAIT_SECONDS = 30.0
_MODEL_NOT_READY_CODE = "ModelNotReadyException"

# Single source of truth for the template. The seeded `<think>` is the one change
# from the SAMA chat_bedrock.py probe, and is what the model's own chat_template
# appends as its generation prompt.
_PROMPT_TEMPLATE = (
    "<|begin_of_text|><|system|>\n{system}\n"
    "<|user|>\n{user}\n"
    "<|assistant|>\n<think>\n"
)


@dataclass(frozen=True)
class AnalystResponse:
    generation: str
    prompt_tokens: int
    generation_tokens: int
    stop_reason: str


class AnalystModel:
    """Invokes the imported reasoning model with one system+user turn.

    Stateless: each `invoke` is an independent completion (no conversation
    history), which is all the analysts need. `client` is injectable so the
    invoke/parse path is testable without boto3 or AWS.
    """

    def __init__(
        self,
        *,
        model_arn: str | None = None,
        region: str | None = None,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
        max_gen_len: int = DEFAULT_MAX_GEN_LEN,
        api_key: str | None = None,
        ready_retries: int = DEFAULT_READY_RETRIES,
        ready_wait_seconds: float = DEFAULT_READY_WAIT_SECONDS,
        client: Any | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        self.model_arn = model_arn or os.environ.get(MODEL_ARN_ENV_VAR, "").strip()
        self.region = region or os.environ.get(REGION_ENV_VAR, "us-east-1")
        self.temperature = temperature
        self.top_p = top_p
        self.max_gen_len = max_gen_len
        self.ready_retries = ready_retries
        self.ready_wait_seconds = ready_wait_seconds
        self._api_key = (api_key or os.environ.get(API_KEY_ENV_VAR, "")).strip()
        self._client = client
        self._sleep = sleep  # injectable so tests do not actually wait

    @staticmethod
    def format_prompt(system: str, user: str) -> str:
        """Build the raw prompt string, with the seeded `<think>` generation cue."""
        return _PROMPT_TEMPLATE.format(system=system, user=user)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self.model_arn:
            raise NotConfigured(
                f"{MODEL_ARN_ENV_VAR} is not set; cannot invoke the analyst model"
            )
        # Local import keeps boto3 off the import path for code that only needs the
        # template/parse helpers.
        import boto3

        kwargs: dict[str, Any] = {"region_name": self.region}
        if self._api_key:
            if self._api_key.startswith("ABSK"):
                # A Bedrock API key (bearer token): boto3's bedrock-runtime picks
                # this up from the environment.
                os.environ["AWS_BEARER_TOKEN_BEDROCK"] = self._api_key
            else:
                parts = self._api_key.split(":")
                if len(parts) >= 2:
                    kwargs["aws_access_key_id"] = parts[0].strip()
                    kwargs["aws_secret_access_key"] = parts[1].strip()
                    if len(parts) >= 3:
                        kwargs["aws_session_token"] = parts[2].strip()
                else:
                    logger.warning(
                        "%s is set but is neither an ABSK key nor ACCESS:SECRET; "
                        "ignoring it and falling back to the default credential chain",
                        API_KEY_ENV_VAR,
                    )
        self._client = boto3.client("bedrock-runtime", **kwargs)
        return self._client

    def invoke(self, system: str, user: str) -> AnalystResponse:
        client = self._get_client()
        body = json.dumps(
            {
                "prompt": self.format_prompt(system, user),
                "max_gen_len": self.max_gen_len,
                "temperature": self.temperature,
                "top_p": self.top_p,
            }
        )
        response = self._invoke_with_warmup(client, body)
        result = json.loads(response["body"].read())
        return AnalystResponse(
            generation=result.get("generation", ""),
            prompt_tokens=result.get("prompt_token_count", 0),
            generation_tokens=result.get("generation_token_count", 0),
            stop_reason=result.get("stop_reason", "unknown"),
        )

    def _invoke_with_warmup(self, client: Any, body: str) -> Any:
        """Call invoke_model, waiting out `ModelNotReadyException` cold starts.

        An imported model that has been idle is evicted and loads on the next
        call, raising `ModelNotReadyException` until it is ready. That is an
        expected cold-start state, not a failure, so we wait and retry up to
        `ready_retries` times rather than sinking the analysis. Any other error
        propagates immediately.
        """
        from botocore.exceptions import ClientError

        for attempt in range(self.ready_retries + 1):
            try:
                return client.invoke_model(
                    modelId=self.model_arn,
                    body=body,
                    contentType="application/json",
                    accept="application/json",
                )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == _MODEL_NOT_READY_CODE and attempt < self.ready_retries:
                    logger.warning(
                        "analyst model warming up (ModelNotReady), attempt %d/%d; "
                        "waiting %.0fs",
                        attempt + 1,
                        self.ready_retries,
                        self.ready_wait_seconds,
                    )
                    self._sleep(self.ready_wait_seconds)
                    continue
                raise


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        logger.warning("%s=%r is not a number; using %s", name, raw, default)
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        logger.warning("%s=%r is not an integer; using %s", name, raw, default)
        return default


def analyst_model_from_env() -> AnalystModel | None:
    """Build the analyst model from the environment, or `None` if unconfigured.

    `None` means `SMARTOPS_ANALYST_MODEL_ARN` is unset: the analysis step is then
    skipped and the run still ends cleanly at the broker report -- the same
    "absence is a supported state" discipline the rest of the CLI follows.
    """
    if not os.environ.get(MODEL_ARN_ENV_VAR, "").strip():
        return None
    return AnalystModel(
        temperature=_env_float("SMARTOPS_ANALYST_TEMPERATURE", DEFAULT_TEMPERATURE),
        top_p=_env_float("SMARTOPS_ANALYST_TOP_P", DEFAULT_TOP_P),
        max_gen_len=_env_int("SMARTOPS_ANALYST_MAX_GEN_LEN", DEFAULT_MAX_GEN_LEN),
        ready_retries=_env_int("SMARTOPS_ANALYST_READY_RETRIES", DEFAULT_READY_RETRIES),
        ready_wait_seconds=_env_float(
            "SMARTOPS_ANALYST_READY_WAIT_SECONDS", DEFAULT_READY_WAIT_SECONDS
        ),
    )
