"""K4: per-role Broker models on the Anthropic API, and per-request pricing.

Tier presets A/B (`SMARTOPS_BROKER_TIERS`), what the Anthropic request carries
(no sampling params, effort, auto-caching), forced tool choice relaxed where
Opus 5.5 / Sonnet 5.5 reject it, and Haiku 5.5's long-context price judged per
request rather than over a whole loop.
"""

import asyncio

import pytest
from smartops.budget import (
    BEDROCK_MODEL_ID_ENV_VAR,
    PROVIDER_ENV_VAR,
    Budget,
    Usage,
    cost_of,
    loop_output_tokens,
    model_choices_from_env,
)

ENV = (
    PROVIDER_ENV_VAR, BEDROCK_MODEL_ID_ENV_VAR, "AWS_REGION", "AWS_DEFAULT_REGION", "DEEPSEEK_API_KEY",
    "SMARTOPS_MODEL_ID", "SMARTOPS_PRICING_KEY", "SMARTOPS_BROKER_TIERS", "ANTHROPIC_API_KEY",
    *(f"SMARTOPS_{k}_{r}" for k in ("MODEL_ID", "EFFORT") for r in ("BROKER", "SIEM", "VT")),
)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(PROVIDER_ENV_VAR, "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")


def ids(choices):
    return {role: (c.model_id, c.effort, c.pricing_key) for role, c in choices.items()}


class TestTierPresets:
    def test_a(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "a")
        assert ids(model_choices_from_env()) == {
            "broker": ("claude-opus-5-5", "high", "claude-opus-5-5"),
            "siem": ("claude-sonnet-5-5", "medium", "claude-sonnet-5-5"),
            "vt": ("claude-haiku-5-5", "low", "claude-haiku-5-5"),
        }

    def test_b(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "B")
        assert ids(model_choices_from_env())["siem"] == ("claude-haiku-5-5", "medium", "claude-haiku-5-5")
        assert ids(model_choices_from_env())["broker"][0] == "claude-sonnet-5-5"

    def test_a_role_override_wins_and_is_priced_from_its_own_id(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "A")
        monkeypatch.setenv("SMARTOPS_PRICING_KEY", "claude-opus-5")  # must not bill every role
        monkeypatch.setenv("SMARTOPS_MODEL_ID_SIEM", "claude-haiku-5-5")
        monkeypatch.setenv("SMARTOPS_EFFORT_SIEM", "high")
        assert ids(model_choices_from_env())["siem"] == ("claude-haiku-5-5", "high", "claude-haiku-5-5")

    def test_an_unknown_tier_is_an_error(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "C")
        with pytest.raises(ValueError, match="SMARTOPS_BROKER_TIERS"):
            model_choices_from_env()

    def test_bedrock_ignores_presets_and_keeps_one_id(self, monkeypatch):
        monkeypatch.setenv(PROVIDER_ENV_VAR, "bedrock")
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, "us.anthropic.claude-sonnet-4-6")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "A")
        assert {c.model_id for c in model_choices_from_env().values()} == {"us.anthropic.claude-sonnet-4-6"}


    def test_loop_output_caps_follow_effort(self, monkeypatch):
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "A")
        c = model_choices_from_env()
        assert loop_output_tokens(c["broker"], 11, 16_000) == 44_000
        assert loop_output_tokens(c["siem"], 25, 12_000) == 50_000
        assert loop_output_tokens(c["vt"], 25, 12_000) == 25_000
        monkeypatch.setenv(PROVIDER_ENV_VAR, "bedrock")
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, "us.anthropic.claude-sonnet-4-6")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        assert loop_output_tokens(model_choices_from_env()["siem"], 25, 12_000) == 12_000

class TestAnthropicRequest:
    def build(self, monkeypatch, role):
        monkeypatch.setenv("SMARTOPS_BROKER_TIERS", "A")
        return model_choices_from_env()[role].build()

    def test_no_sampling_params_effort_and_auto_cache(self, monkeypatch):
        model = self.build(monkeypatch, "broker")
        request = model.format_request([{"role": "user", "content": [{"text": "hi"}]}], [], "sys")
        assert "temperature" not in request and "top_p" not in request
        assert request["output_config"] == {"effort": "high"}
        assert request["cache_control"] == {"type": "ephemeral"}
        assert request["model"] == "claude-opus-5-5"

    def test_forced_tool_choice_becomes_auto_on_opus_and_sonnet_5_5(self, monkeypatch):
        model = self.build(monkeypatch, "broker")
        assert model._format_tool_choice({"any": {}}) == {"tool_choice": {"type": "auto"}}

    def test_haiku_5_5_keeps_forced_tool_choice(self, monkeypatch):
        model = self.build(monkeypatch, "vt")
        assert model._format_tool_choice({"any": {}}) == {"tool_choice": {"type": "any"}}

    def test_a_missing_key_fails_at_build(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY")
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            self.build(monkeypatch, "siem")


class TestPerRequestPricing:
    """Haiku 5.5: $0.10/$0.50 per MTok up to a 100k-token prompt, $0.50/$2.50 above."""

    def test_rates(self):
        assert cost_of("claude-haiku-5-5", Usage(input_tokens=100_000)) == 10_000  # at the threshold: $0.10/MTok
        assert cost_of("claude-haiku-5-5", Usage(input_tokens=100_001)) == 50_001  # over it: $0.50/MTok
        assert cost_of("claude-opus-5-5", Usage(input_tokens=1_000_000, output_tokens=1_000_000)) == 24_000_000
        assert cost_of("claude-sonnet-5-5", Usage(cache_read_input_tokens=1_000_000)) == 100_000  # 0.05x of $2

    def test_cache_reads_count_toward_the_threshold(self):
        small = cost_of("claude-haiku-5-5", Usage(input_tokens=60_000))
        crossed = cost_of("claude-haiku-5-5", Usage(input_tokens=60_000, cache_read_input_tokens=50_000))
        assert small == 6_000 and crossed == 30_000 + 2_500  # 60k at $0.50 + 50k reads at $0.05

    def test_settle_prices_each_call_not_the_loop_total(self):
        budget = Budget.from_usd(10.0)

        async def run(calls):
            reservation = await budget.reserve(role="siem", model="claude-haiku-5-5", max_output_tokens=10)
            total = Usage(input_tokens=sum(c.input_tokens for c in calls))
            return await budget.settle(reservation, total, calls=calls)

        two_small = asyncio.run(run([Usage(input_tokens=60_000)] * 2))
        one_large = asyncio.run(run([Usage(input_tokens=120_000)]))
        assert (two_small, one_large) == (12_000, 60_000)


def test_usage_by_role_counts_tokens_and_requests():
    """B30: cache reads and output per request were not visible after a run."""
    async def go():
        b = Budget.from_usd(10)
        r = await b.reserve(role="siem", model="claude-sonnet-5-5", task_id="t", max_output_tokens=100)
        calls = [Usage(input_tokens=10, output_tokens=5, cache_read_input_tokens=90),
                 Usage(input_tokens=20, output_tokens=7)]
        await b.settle(r, Usage(input_tokens=30, output_tokens=12, cache_read_input_tokens=90), calls)
        return b.usage_by_role()

    assert asyncio.run(go()) == {"siem": {"calls": 2, "input": 30, "output": 12, "cache_read": 90, "cache_write": 0}}
