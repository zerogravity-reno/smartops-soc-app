"""Tests for the analyst model client (template + invoke parsing), no AWS."""

from __future__ import annotations

import json

import pytest
from smartops.errors import NotConfigured
from smartops.subagent_analysts.model import AnalystModel, analyst_model_from_env


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
    def test_prompt_seeds_think_and_places_turns(self):
        prompt = AnalystModel.format_prompt("SYS", "USR")
        assert prompt.startswith("<|begin_of_text|><|system|>")
        assert "SYS" in prompt and "USR" in prompt
        assert "<|user|>" in prompt and "<|assistant|>" in prompt
        # the generation prompt seeds the reasoning tag
        assert prompt.rstrip().endswith("<think>")


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


class TestFromEnv:
    def test_none_when_arn_absent(self, monkeypatch):
        monkeypatch.delenv("SMARTOPS_ANALYST_MODEL_ARN", raising=False)
        assert analyst_model_from_env() is None

    def test_reads_optional_generation_controls(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_ANALYST_MODEL_ARN", "arn:fake")
        monkeypatch.setenv("SMARTOPS_ANALYST_TEMPERATURE", "0.3")
        monkeypatch.setenv("SMARTOPS_ANALYST_MAX_GEN_LEN", "4096")
        model = analyst_model_from_env()
        assert model is not None
        assert model.temperature == 0.3
        assert model.max_gen_len == 4096
