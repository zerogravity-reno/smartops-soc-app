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
import threading
import time
from dataclasses import dataclass
from typing import Any

from smartops.analyst_cost import AnalystSpend
from smartops.errors import NotConfigured

logger = logging.getLogger(__name__)

MODEL_ARN_ENV_VAR = "SMARTOPS_ANALYST_MODEL_ARN"
REGION_ENV_VAR = "AWS_REGION"
# Optional dedicated credential for the imported Cisco model. Two accepted forms,
# matching the SAMA chat_bedrock.py probe: an `ABSK...` Bedrock API key (a bearer
# token), or `ACCESS_KEY:SECRET_KEY[:SESSION_TOKEN]`. If unset, boto3's normal
# credential chain (env, profile, role) is used.
API_KEY_ENV_VAR = "SMARTOPS_ANALYST_API_KEY"

_BEARER_ENV_VAR = "AWS_BEARER_TOKEN_BEDROCK"
"""The variable name botocore derives for bedrock's bearer token.

`utils._get_bearer_env_var_name` builds it from the service's signing name
(`bedrock`), so this must stay in step with that derivation -- it is the key of the
private mapping handed to `ScopedEnvTokenProvider`, never written to `os.environ`.
"""

# GREEDY, deliberately, and NOT the model's shipped `generation_config.json` value.
#
# That file carries `temperature=0.6, top_p=0.95` and this tracked it verbatim until it
# was measured. Those are the model's *conversational* defaults, and a SOC verdict is not
# a conversation: at 0.6 one evidence slice produced three of the four possible
# dispositions across five draws, confidence spreading 0.60, citation Jaccard 0.27
# (docs/sessions/handover_2026-08-27_analyst-verdict-variance.md).
#
# 0 rather than the model card's 0.1-0.3, on measurement rather than preference. The
# reason to avoid greedy was that it answered THINLY -- one observation citing one
# block, on a slice holding 15 tagged sets -- and on the network domain it read
# `suspicious` where sampling twice read `malicious`, which was the better call. Both
# were artefacts of a prompt with no reporting floor. With the floor in `prompts.py`,
# greedy returns four observations on identity AND network, and reads network
# `malicious` 0.95 citing the VirusTotal row paired with a matching connection -- the
# accurate answer, three draws running. Measured 2026-08-29, three arms, two domains.
#
# So the floor and this value are ONE change with two halves. Raising the temperature
# without removing the floor is safe; removing the floor while leaving this at 0 brings
# the thin answers straight back. Change them together or not at all.
#
# What greedy buys beyond stability: a verdict replays exactly from its `evidence_id`.
# The draws are byte-identical -- same disposition, same citations, same generation
# token count -- so an audit can reproduce a stored verdict rather than approximate it.
#
# `top_p` stays at the shipped 0.95. It only truncates the distribution's tail and is
# inert under greedy decoding; left at the model's own value so that raising the
# temperature is a one-line change with no second surprise.
DEFAULT_TEMPERATURE = 0.0
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

_RETRY_CONFIG = {"max_attempts": 3, "mode": "adaptive"}
"""Botocore-level retries, which this client had none of.

A different failure from the cold start `_invoke_with_warmup` handles, and it needs a
different remedy. The three analysts run CONCURRENTLY against one imported model
(`gather()` fans out via `asyncio.to_thread`), so they arrive at the endpoint together
and a `ThrottlingException` on one is the expected shape of contention rather than a
surprise. With no retry config, botocore's default of 5 legacy attempts applies to the
standard set but `adaptive` is what actually paces a burst: it maintains a client-side
rate limiter across the shared client, which is the thing three simultaneous callers
need.

Why it matters more here than it looks: a throttled analyst raises out of
`AnalystModel.invoke`, `_invoke_with_one_reask` catches it and returns an unparsed
`_Attempt`, and the domain lands on the wire with an EMPTY NARRATIVE and no
observations. Before 2026-08-31 that surfaced as `inconclusive` with confidence 0.0,
and the hazard was that a capacity blip read as a legitimate verdict. Removing the
verdict did not remove the hazard, it moved it: an empty narrative is now what a
genuinely empty slice also produces, so a transient failure is indistinguishable from
"we looked and there was nothing" by the narrative alone.

`RetrievalSummary` is the only thing that separates them, which is precisely why it
is load-bearing rather than supplementary -- see `contracts.reasoning`. A reader who
judges emptiness from the findings alone will get this wrong; the step's `completed`
flag is the field that answers it.

`mode` is deliberately not `standard`: standard retries the same call on a fixed
backoff, adaptive additionally slows the *next* caller, which is what stops three
threads from re-colliding on each retry.
"""


_TIMEOUTS = {"connect_timeout": 15, "read_timeout": 600}
"""Seconds. botocore's default read is 60, and a full 8,192-token Analyst synthesis
took ~72 s on ea38cb13: it would time out and be retried, and billed, up to 3 times.
600 is what the webapp's own client allowed."""


def _botocore_config() -> Any:
    """`Config(retries=_RETRY_CONFIG)`, imported lazily.

    Local import for the same reason `_get_client` imports boto3 locally: code that
    only wants the template or parse helpers should not pay for botocore.
    """
    from botocore.config import Config

    return Config(retries=_RETRY_CONFIG, **_TIMEOUTS)


# Single source of truth for the template, and it must match the model's own
# `chat_template` byte for byte -- `<|system|>`, `<|user|>`, `<|assistant|>` and
# `<think>` are real special tokens for THIS model (ids 128264-128268 in its
# `tokenizer_config.json`), not the Llama-3.1 base's `<|start_header_id|>` scheme, so
# a near-miss here is silently off-template rather than an error.
#
# Derived by walking the published Jinja with its whitespace control applied
# (`{%-` strips preceding whitespace, so most of the apparent blank lines collapse):
#
#     {{ bos_token }} -> <|begin_of_text|>
#     \n<|system|>\n{system}      (trailing blank line eaten by the next `{%- elif`)
#     \n<|user|>\n{user}          (same)
#     \n<|assistant|>\n<think>    (trailing newline eaten by `{%- endif %}`)
#
# So there IS a newline after the BOS token and there is NO trailing newline after the
# seeded `<think>`. Both were wrong here before; `test_analyst_model.py` pins the exact
# string now. The seeded `<think>` is not our invention -- it is what the template
# appends for `add_generation_prompt=True`.
_PROMPT_TEMPLATE = (
    "<|begin_of_text|>\n<|system|>\n{system}\n"
    "<|user|>\n{user}\n"
    "<|assistant|>\n<think>"
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
        spend: AnalystSpend | None = None,
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
        self.spend = spend if spend is not None else AnalystSpend()
        """Billed-window record for this model's calls. Shared across the three
        analysts because they share the `AnalystModel`, which is what makes their
        concurrent calls collapse into one billing window rather than three."""
        # `analyze()` runs identity/network/endpoint concurrently via
        # `asyncio.gather(*(asyncio.to_thread(run_one, model, ...)))`, all
        # sharing this one `AnalystModel`. `threading.Lock`, not an
        # `asyncio.Lock`: `_get_client()` runs inside those worker threads, not
        # on the event loop.
        self._client_lock = threading.Lock()

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

        # Double-checked locking so two concurrent worker threads sharing one
        # `AnalystModel` -- which is what `analyze()`'s
        # `asyncio.gather(*(asyncio.to_thread(run_one, model, ...)))` produces --
        # cannot each build a client. The outer check above already short-circuits
        # every call after the first; this one covers the callers that arrived
        # while the lock was held building it.
        with self._client_lock:
            if self._client is not None:
                return self._client

            kwargs: dict[str, Any] = {"region_name": self.region}
            if self._api_key:
                if self._api_key.startswith("ABSK"):
                    self._client = self._bearer_client(boto3, self._api_key)
                    return self._client
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
            self._client = boto3.client(
                "bedrock-runtime", config=_botocore_config(), **kwargs
            )
        return self._client

    def _bearer_client(self, boto3: Any, api_key: str) -> Any:
        """A bedrock-runtime client authenticated by an `ABSK...` Bedrock API key.

        Built WITHOUT touching `os.environ`, which took three attempts to get
        right and is worth recording, because both obvious approaches are wrong:

        1. Setting `AWS_BEARER_TOKEN_BEDROCK` and leaving it set leaks a
           credential into the process. A second `AnalystModel` built later with
           no key of its own silently inherits this one's token instead of
           falling through to the default AWS credential chain.
        2. Setting it only around `boto3.client(...)` and restoring it after --
           which is what this did until now -- does not work at all. The claim it
           rested on (that botocore reads the variable once, at client
           construction) is false: `handlers._should_prefer_bearer_auth` calls
           `get_token_from_environment(signing_name)` on EVERY request
           (botocore/handlers.py:1462, botocore 1.43.65) and that helper reads
           the real `os.environ`, ignoring any injected mapping. With the
           variable restored away, bearer was never chosen, every call fell back
           to sigv4 on the default chain, and a cross-account ARN answered
           `AccessDeniedException: The provided resource ARN is from a different
           account.` -- surfacing as "analyst could not run", i.e. as a model
           failure rather than a credential one.

        So the token is supplied through botocore's own injection point instead:
        `ScopedEnvTokenProvider` accepts the mapping it reads (botocore/tokens.py:
        `__init__(self, session, environ=None)`), so a private mapping holding
        just this key reaches the signer with no global state involved.

        `auth_scheme_preference` is the other half and is NOT optional.
        `InvokeModel` carries no auth trait of its own (`operation_model.auth` is
        `None`), so botocore falls back to the service default -- sigv4 -- unless
        either the env probe above fires or the preference names bearer
        explicitly. Naming it here is what makes the injected token actually get
        used, and it is set on this client only.
        """
        import botocore.session
        from botocore.config import Config
        from botocore.tokens import ScopedEnvTokenProvider

        session = botocore.session.get_session()
        session.register_component(
            "token_provider",
            ScopedEnvTokenProvider(session, environ={_BEARER_ENV_VAR: api_key}),
        )
        return boto3.Session(botocore_session=session).client(
            "bedrock-runtime",
            region_name=self.region,
            config=Config(
                auth_scheme_preference="httpBearerAuth",
                retries=_RETRY_CONFIG,
                **_TIMEOUTS,
            ),
        )

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
        # AFTER the call returned, not before: Bedrock starts the billing window
        # at the first *successful* invocation, so a cold-start retry that never
        # answered is not a billable minute. See `smartops.analyst_cost`.
        self.spend.record()
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


MAX_GEN_LEN_ENV_VAR = "SMARTOPS_ANALYST_MAX_GEN_LEN"


def _clamped_max_gen_len() -> int:
    """`MAX_GEN_LEN_ENV_VAR`, refused above `DEFAULT_MAX_GEN_LEN`.

    `packing._GENERATION_RESERVE` is set to `DEFAULT_MAX_GEN_LEN` and reserved
    out of the 32,768-token window once, at import. This env var is read at
    RUNTIME and can name a larger value -- `SMARTOPS_ANALYST_MAX_GEN_LEN=8192`
    overflows the window by ~4,600 tokens against that frozen reserve, silently,
    since nothing at import time can see a value only set later. Clamping here
    is the cheapest place to close that gap: refusing (or silently honouring) a
    too-large value would either break every run using this env var today or
    let the overflow back in, so this warns and falls back to the reserved
    default instead. Raise `DEFAULT_MAX_GEN_LEN` itself (which re-derives
    `_PACK_TOKEN_BUDGET`) if more generation room is genuinely needed.
    """
    requested = _env_int(MAX_GEN_LEN_ENV_VAR, DEFAULT_MAX_GEN_LEN)
    if requested > DEFAULT_MAX_GEN_LEN:
        logger.warning(
            "%s=%d exceeds DEFAULT_MAX_GEN_LEN=%d, which is what "
            "packing._GENERATION_RESERVE reserved out of the context window at "
            "import time; using %d instead so the reserved prompt budget stays "
            "honest. Raise DEFAULT_MAX_GEN_LEN (and re-derive the packing "
            "budget) if more generation room is genuinely needed.",
            MAX_GEN_LEN_ENV_VAR,
            requested,
            DEFAULT_MAX_GEN_LEN,
            DEFAULT_MAX_GEN_LEN,
        )
        return DEFAULT_MAX_GEN_LEN
    return requested


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
        max_gen_len=_clamped_max_gen_len(),
        ready_retries=_env_int("SMARTOPS_ANALYST_READY_RETRIES", DEFAULT_READY_RETRIES),
        ready_wait_seconds=_env_float(
            "SMARTOPS_ANALYST_READY_WAIT_SECONDS", DEFAULT_READY_WAIT_SECONDS
        ),
    )
