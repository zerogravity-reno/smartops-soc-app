"""Tests for the analyst model client (template + invoke parsing), no AWS."""

from __future__ import annotations

import json
import os
import threading
import time

import logging

import pytest
from smartops.errors import NotConfigured
from smartops.subagent_analysts.model import (
    DEFAULT_MAX_GEN_LEN,
    DEFAULT_TEMPERATURE,
    AnalystModel,
    _botocore_config,
    analyst_model_from_env,
)


class _FakeBody:
    def __init__(self, payload: dict):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._data


class _FakeClient:
    def __init__(self, payload: dict):
        self._payload = payload
        self.last_call: dict | None = None

    def invoke_model(self, **kwargs):
        self.last_call = kwargs
        return {"body": _FakeBody(self._payload)}


class TestTemplate:
    """The template must match the model's published `chat_template` exactly.

    Pinned as one byte-for-byte equality rather than a handful of `startswith` /
    `in` / `rstrip().endswith()` probes, which is what this was. Those passed both
    before and after a real off-template defect: the prompt was missing the newline
    after `<|begin_of_text|>` and carried an extra one after the seeded `<think>`,
    and every loose assertion still held. Off-template prompting does not raise --
    it just degrades instruction-following silently, which is the failure this file
    is the only place to catch.

    EXPECTED below is derived from the published Jinja with its whitespace control
    applied; the derivation is recorded at `_PROMPT_TEMPLATE` in
    `subagent_analysts/model.py`. If Cisco republishes the template, re-derive it
    there and update this constant -- do not relax the comparison.
    """

    EXPECTED = (
        "<|begin_of_text|>\n"
        "<|system|>\n"
        "SYS\n"
        "<|user|>\n"
        "USR\n"
        "<|assistant|>\n"
        "<think>"
    )

    def test_prompt_matches_the_published_chat_template_byte_for_byte(self):
        assert AnalystModel.format_prompt("SYS", "USR") == self.EXPECTED

    def test_the_special_tokens_are_this_models_own_not_llama_31_headers(self):
        """`<|system|>` etc. are real special tokens for THIS model (ids 128264-128268).

        The base Llama-3.1 `<|start_header_id|>system<|end_header_id|>` scheme would
        tokenize here as literal text, so a well-meant "correction" toward it is a
        regression. Asserted so that reasoning has to be re-done deliberately.
        """
        prompt = AnalystModel.format_prompt("SYS", "USR")

        assert "<|start_header_id|>" not in prompt
        assert "<|eot_id|>" not in prompt

    def test_the_generation_prompt_seeds_the_reasoning_tag(self):
        """`add_generation_prompt=True` ends the template at `<think>`, so the model
        opens its reasoning immediately and emits `</think>` before the answer block
        that `parse.split_reasoning` splits on."""
        assert AnalystModel.format_prompt("SYS", "USR").endswith("<|assistant|>\n<think>")


class TestSamplingDefaults:
    def test_temperature_does_not_track_the_models_chat_default(self):
        """0.6 is what `generation_config.json` ships, and it is deliberately NOT
        used: it is the model's conversational setting, and at 0.6 one evidence
        slice produced three of the four dispositions across five draws. See
        docs/sessions/handover_2026-08-27_analyst-verdict-variance.md.

        Asserted as an inequality against 0.6 as well as an equality, so that
        "restore the documented default" reads as the regression it would be.
        """
        assert DEFAULT_TEMPERATURE == 0.0
        assert DEFAULT_TEMPERATURE != 0.6


class TestThrottleRetries:
    """A throttled analyst is invisible without this: the exception is caught by
    `_invoke_with_one_reask` and the domain lands on the wire as `inconclusive`
    with confidence 0.0 -- indistinguishable from an honest "cannot judge".

    Distinct from the `ModelNotReadyException` warm-up loop below, which handles
    cold-start eviction. Three analysts run concurrently against one imported
    model, so contention is the expected case, not a surprise.
    """

    def test_the_client_config_retries_adaptively(self):
        config = _botocore_config()

        assert config.retries["max_attempts"] == 3
        # `adaptive`, not `standard`: standard retries the same call on a backoff,
        # adaptive also rate-limits the NEXT caller, which is what stops three
        # threads re-colliding on every retry.
        assert config.retries["mode"] == "adaptive"


class TestInvoke:
    def test_parses_generation_and_token_counts(self):
        client = _FakeClient(
            {
                "generation": "reasoning </think> VERDICT: supports",
                "prompt_token_count": 1200,
                "generation_token_count": 88,
                "stop_reason": "stop",
            }
        )
        model = AnalystModel(model_arn="arn:fake", client=client)
        resp = model.invoke("sys", "usr")
        assert resp.generation.endswith("VERDICT: supports")
        assert resp.prompt_tokens == 1200
        assert resp.generation_tokens == 88
        assert resp.stop_reason == "stop"
        # payload shape sent to Bedrock
        body = json.loads(client.last_call["body"])
        assert set(body) == {"prompt", "max_gen_len", "temperature", "top_p"}
        assert client.last_call["modelId"] == "arn:fake"

    def test_unconfigured_without_arn_or_client_raises(self, monkeypatch):
        monkeypatch.delenv("SMARTOPS_ANALYST_MODEL_ARN", raising=False)
        with pytest.raises(NotConfigured):
            AnalystModel().invoke("s", "u")


class _NotReadyThenReadyClient:
    """Raises ModelNotReadyException `fail_times`, then returns a real payload."""

    def __init__(self, fail_times: int, payload: dict):
        self._remaining = fail_times
        self._payload = payload
        self.calls = 0

    def invoke_model(self, **kwargs):
        from botocore.exceptions import ClientError

        self.calls += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise ClientError(
                {"Error": {"Code": "ModelNotReadyException", "Message": "warming up"}},
                "InvokeModel",
            )
        return {"body": _FakeBody(self._payload)}


class TestColdStartWarmup:
    def test_retries_until_model_is_ready(self):
        client = _NotReadyThenReadyClient(
            fail_times=2,
            payload={"generation": "</think> VERDICT: refutes", "prompt_token_count": 5,
                     "generation_token_count": 3, "stop_reason": "stop"},
        )
        waited: list[float] = []
        model = AnalystModel(
            model_arn="arn:fake", client=client, ready_wait_seconds=0.0,
            sleep=waited.append,
        )
        resp = model.invoke("s", "u")
        assert resp.generation.endswith("VERDICT: refutes")
        assert client.calls == 3  # 2 not-ready + 1 success
        assert len(waited) == 2  # slept once per not-ready

    def test_gives_up_after_ready_retries(self):
        from botocore.exceptions import ClientError

        client = _NotReadyThenReadyClient(fail_times=99, payload={})
        model = AnalystModel(
            model_arn="arn:fake", client=client, ready_retries=2, ready_wait_seconds=0.0,
            sleep=lambda _s: None,
        )
        with pytest.raises(ClientError):
            model.invoke("s", "u")
        assert client.calls == 3  # initial + 2 retries


class TestBearerTokenNeverTouchesTheEnvironment:
    """An `ABSK` key must reach the signer without any process-global mutation.

    Both of the obvious implementations are wrong, and this class pins the way
    out of both. Setting `AWS_BEARER_TOKEN_BEDROCK` and leaving it set leaks a
    credential to every later client in the process. Setting it only around
    `boto3.client(...)` and restoring it -- which is what this did until
    2026-08-25 -- does not authenticate at all: botocore's
    `_should_prefer_bearer_auth` re-reads the real `os.environ` on EVERY request
    (botocore/handlers.py:1462), so with the variable restored away every call
    silently fell back to sigv4 on the default credential chain. Against a
    cross-account model ARN that answered `AccessDeniedException`, which
    `run_one`/`gather_finding` contain as "analyst could not run" -- a credential
    fault wearing a model fault's clothes.
    """

    def test_the_variable_is_never_set_at_any_point(self, monkeypatch):
        monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
        seen: list[bool] = []

        class _Session:
            def __init__(self, *_a, **_k):
                pass

            def client(self, *_a, **_k):
                seen.append("AWS_BEARER_TOKEN_BEDROCK" in os.environ)
                return object()

        monkeypatch.setattr("boto3.Session", _Session)

        AnalystModel(model_arn="arn:fake", api_key="ABSK-secret")._get_client()

        assert seen == [False], "the token must not be in os.environ during construction"
        assert "AWS_BEARER_TOKEN_BEDROCK" not in os.environ

    def test_a_pre_existing_bearer_token_is_left_exactly_as_it_was(self, monkeypatch):
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "pre-existing-token")
        monkeypatch.setattr(
            "boto3.Session", lambda *a, **k: type("S", (), {"client": lambda *a, **k: object()})()
        )

        AnalystModel(model_arn="arn:fake", api_key="ABSK-secret")._get_client()

        assert os.environ["AWS_BEARER_TOKEN_BEDROCK"] == "pre-existing-token"

    def test_the_token_and_the_scheme_preference_both_reach_the_real_client(
        self, monkeypatch
    ):
        """The two halves of the fix, checked against real botocore, no network.

        The token alone is not enough: `InvokeModel` carries no auth trait
        (`operation_model.auth is None`), so botocore resolves the service default
        -- sigv4 -- unless the preference names bearer. Asserting only that the
        token is attached would pass while every request still signed sigv4.
        """
        monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
        # A region and dummy sigv4 creds so client construction never consults an
        # ambient profile or instance metadata; the bearer path ignores them.
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret")

        client = AnalystModel(
            model_arn="arn:aws:bedrock:us-east-1:111122223333:imported-model/abc",
            region="us-east-1",
            api_key="ABSK-secret",
        )._get_client()

        assert client._request_signer._auth_token.token == "ABSK-secret"
        assert client.meta.config.auth_scheme_preference == "httpBearerAuth"
        assert "AWS_BEARER_TOKEN_BEDROCK" not in os.environ


class TestConcurrentClientConstructionIsSerialized:
    """`analyze()` fans identity/network/endpoint out via
    `asyncio.gather(*(asyncio.to_thread(run_one, model, ...)))`, all three
    sharing one `AnalystModel`. Without a lock, several worker threads can pass
    `self._client is None` at once and each build their own client -- so the
    model would hold a different client than the one some callers were handed."""

    def test_only_one_client_is_built(self, monkeypatch):
        build_count = 0
        count_lock = threading.Lock()

        def fake_bearer_client(self, _boto3, api_key):
            nonlocal build_count
            with count_lock:
                build_count += 1
            # Widens the race window so an unsynchronized implementation is
            # overwhelmingly likely to interleave within it.
            time.sleep(0.05)
            return object()

        monkeypatch.setattr(AnalystModel, "_bearer_client", fake_bearer_client)
        model = AnalystModel(model_arn="arn:fake", api_key="ABSK-shared-secret")

        threads = [threading.Thread(target=model._get_client) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert build_count == 1, "the client must be built once, not once per racing thread"


class TestFromEnv:
    def test_none_when_arn_absent(self, monkeypatch):
        monkeypatch.delenv("SMARTOPS_ANALYST_MODEL_ARN", raising=False)
        assert analyst_model_from_env() is None

    def test_reads_optional_generation_controls(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_ANALYST_MODEL_ARN", "arn:fake")
        monkeypatch.setenv("SMARTOPS_ANALYST_TEMPERATURE", "0.3")
        # At or below DEFAULT_MAX_GEN_LEN, so this exercises the pass-through
        # half of `_clamped_max_gen_len` rather than its clamp.
        monkeypatch.setenv("SMARTOPS_ANALYST_MAX_GEN_LEN", "2048")
        model = analyst_model_from_env()
        assert model is not None
        assert model.temperature == 0.3
        assert model.max_gen_len == 2048


class TestMaxGenLenIsClampedToTheReservedBudget:
    """Finding 3 (2026-08-30 whole-branch review).

    `packing._GENERATION_RESERVE` is set to `DEFAULT_MAX_GEN_LEN` and reserved
    out of the 32,768-token window once, at import -- but this env var is read
    at RUNTIME, and used to be handed straight to `AnalystModel` with nothing
    checking it against that frozen reserve.
    `SMARTOPS_ANALYST_MAX_GEN_LEN=8192` overflowed the window by ~4,600 tokens,
    silently, while `_GENERATION_RESERVE`'s docstring claimed the two could not
    diverge.
    """

    def test_a_value_above_the_default_is_clamped_and_warns(self, monkeypatch, caplog):
        monkeypatch.setenv("SMARTOPS_ANALYST_MODEL_ARN", "arn:fake")
        monkeypatch.setenv("SMARTOPS_ANALYST_MAX_GEN_LEN", "8192")

        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.model"):
            model = analyst_model_from_env()

        assert model is not None
        assert model.max_gen_len == DEFAULT_MAX_GEN_LEN
        assert "SMARTOPS_ANALYST_MAX_GEN_LEN=8192" in caplog.text
        assert str(DEFAULT_MAX_GEN_LEN) in caplog.text

    def test_a_value_at_the_default_is_not_clamped_and_does_not_warn(self, monkeypatch, caplog):
        monkeypatch.setenv("SMARTOPS_ANALYST_MODEL_ARN", "arn:fake")
        monkeypatch.setenv("SMARTOPS_ANALYST_MAX_GEN_LEN", str(DEFAULT_MAX_GEN_LEN))

        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.model"):
            model = analyst_model_from_env()

        assert model is not None
        assert model.max_gen_len == DEFAULT_MAX_GEN_LEN
        assert caplog.text == ""

    def test_unset_falls_back_to_the_default_unclamped(self, monkeypatch, caplog):
        monkeypatch.setenv("SMARTOPS_ANALYST_MODEL_ARN", "arn:fake")
        monkeypatch.delenv("SMARTOPS_ANALYST_MAX_GEN_LEN", raising=False)

        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.model"):
            model = analyst_model_from_env()

        assert model is not None
        assert model.max_gen_len == DEFAULT_MAX_GEN_LEN
        assert caplog.text == ""


class TestReadTimeout:
    def test_both_clients_wait_out_a_long_generation(self, monkeypatch):
        # botocore's default read is 60 s; a full 8,192-token synthesis took ~72 s (ea38cb13).
        import boto3

        from smartops.subagent_analysts.model import _botocore_config

        seen = {}

        class Session:
            def __init__(self, **_):
                pass

            def client(self, *_, config, **__):
                seen["bearer"] = config

        monkeypatch.setattr(boto3, "Session", Session)
        AnalystModel(model_arn="arn:x", region="us-east-1", api_key="ABSK" + "x" * 20)._get_client()
        for config in (seen["bearer"], _botocore_config()):
            assert config.read_timeout >= 600 and config.connect_timeout <= 30
