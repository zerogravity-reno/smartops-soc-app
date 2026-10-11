import asyncio

import pytest
from smartops.budget import (
    BEDROCK_MODEL_ID_ENV_VAR,
    PRICING,
    PROVIDER_ENV_VAR,
    Budget,
    ModelChoice,
    ModelPrice,
    Provider,
    Usage,
    available_provider,
    cost_of,
    estimate_cost,
    model_choice_from_env,
)


def test_cost_of_known_model():
    usage = Usage(input_tokens=1000, output_tokens=500)
    # opus: 5 micro-usd/input-token, 25 micro-usd/output-token
    assert cost_of("claude-opus-5", usage) == 1000 * 5 + 500 * 25


def test_cost_of_includes_cache_tokens():
    usage = Usage(cache_creation_input_tokens=1000, cache_read_input_tokens=1000)
    # opus input price 5: write = 5 * 1.25 = 6.25/token, read = 5 * 0.1 = 0.5/token
    assert cost_of("claude-opus-5", usage) == 6250 + 500


def test_cost_of_unknown_model_raises():
    with pytest.raises(ValueError):
        cost_of("not-a-real-model", Usage())


def test_estimate_cost_is_output_worst_case():
    assert estimate_cost("claude-opus-5", max_output_tokens=1000) == 1000 * 25
    assert estimate_cost("claude-opus-5", max_output_tokens=1000, estimated_input_tokens=100) == 100 * 5 + 1000 * 25


def test_estimate_cost_rejects_negative_max_output_tokens():
    with pytest.raises(ValueError):
        estimate_cost("claude-opus-5", max_output_tokens=-1)


def test_estimate_cost_rejects_negative_estimated_input_tokens():
    with pytest.raises(ValueError):
        estimate_cost("claude-opus-5", max_output_tokens=100, estimated_input_tokens=-1)


def test_from_usd_converts_to_micro_usd():
    budget = Budget.from_usd(2.5)
    assert budget.remaining == 2_500_000


def test_model_choice_temperature_default():
    choice = ModelChoice(model_id="us.anthropic.claude-sonnet-4-6-v1:0", pricing_key="claude-sonnet-4-6")
    assert choice.temperature == 0.3
    assert choice.top_p is None


class TestReserveAndSettle:
    async def test_reserve_deducts_worst_case_estimate(self):
        budget = Budget(total_micro_usd=100_000)
        reservation = await budget.reserve(role="subagent:edr", model="claude-haiku-4-5", max_output_tokens=1000, task_id="t1")

        assert reservation is not None
        assert budget.remaining == 100_000 - 1000 * 5  # haiku output price = 5

    async def test_settle_credits_back_the_unused_portion(self):
        budget = Budget(total_micro_usd=100_000)
        reservation = await budget.reserve(role="subagent:edr", model="claude-haiku-4-5", max_output_tokens=1000, task_id="t1")

        actual = await budget.settle(reservation, Usage(input_tokens=200, output_tokens=100))

        assert actual == 200 * 1 + 100 * 5  # 700
        assert budget.remaining == 100_000 - actual

    async def test_reserve_returns_none_and_leaves_remaining_untouched_when_insufficient(self):
        budget = Budget(total_micro_usd=1000)

        reservation = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=1000)

        assert reservation is None
        assert budget.remaining == 1000

    async def test_subagent_stops_immediately_without_attempting_a_call(self):
        budget = Budget(total_micro_usd=0)
        called_model = False

        async def fake_subagent() -> dict:
            nonlocal called_model
            reservation = await budget.reserve(role="subagent:edr", model="claude-opus-5", max_output_tokens=100)
            if reservation is None:
                return {"status": "error", "error": "budget exhausted"}
            called_model = True  # would be the real tool/LLM call
            return {"status": "ok"}

        result = await fake_subagent()

        assert result == {"status": "error", "error": "budget exhausted"}
        assert called_model is False

    async def test_release_credits_back_the_full_reservation(self):
        budget = Budget(total_micro_usd=100_000)
        reservation = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=1000)

        await budget.release(reservation)

        assert budget.remaining == 100_000

    async def test_release_records_no_ledger_entry(self):
        budget = Budget(total_micro_usd=100_000)
        reservation = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=1000)

        await budget.release(reservation)

        assert budget.ledger == []
        assert budget.spend_by_role() == {}

    async def test_many_concurrent_reservations_never_drive_remaining_negative(self):
        budget = Budget(total_micro_usd=10_000)
        per_call_cost = 600 * 5  # haiku output price = 5 -> 3000 micro-usd each

        results = await asyncio.gather(
            *[
                budget.reserve(role="subagent:edr", model="claude-haiku-4-5", max_output_tokens=600)
                for _ in range(10)
            ]
        )

        successes = [r for r in results if r is not None]
        assert len(successes) == 10_000 // per_call_cost  # exactly 3 fit
        assert budget.remaining == 10_000 - len(successes) * per_call_cost
        assert budget.remaining >= 0


class TestOutputTokenCeiling:
    """The investigation-level output-token ceiling -- the second reservation
    dimension that makes total output a HARD cap.

    The USD hold is sized from an optimistic input estimate (~8 expected turns,
    not the 25-turn worst case), so `settle()` debiting real cost can carry total
    spend past the USD ceiling when several long subagents overlap. Output tokens
    are the dominant cost and already per-call capped, so a single ceiling over
    them restores a genuine upper bound. These pin that it bites, that it credits
    back correctly, and that it stays entirely dormant when unconfigured.
    """

    async def test_no_ceiling_by_default_leaves_output_unbounded(self):
        budget = Budget(total_micro_usd=1_000_000)
        assert budget.output_tokens_remaining is None

        r = await budget.reserve(role="planner", model="claude-haiku-4-5", max_output_tokens=10_000)

        assert r is not None
        assert r.reserved_output_tokens == 10_000  # recorded, but not tracked
        assert budget.output_tokens_remaining is None

    async def test_reserve_deducts_the_output_hold(self):
        budget = Budget(total_micro_usd=1_000_000, max_output_tokens_total=5_000)

        await budget.reserve(role="subagent:siem", model="claude-haiku-4-5", max_output_tokens=1_000)

        assert budget.output_tokens_remaining == 4_000

    async def test_reserve_refuses_when_the_output_ceiling_is_hit_though_usd_is_ample(self):
        # USD is effectively unlimited; only the output ceiling should bind.
        budget = Budget(total_micro_usd=1_000_000_000, max_output_tokens_total=1_500)

        first = await budget.reserve(role="subagent:siem", model="claude-haiku-4-5", max_output_tokens=1_000)
        second = await budget.reserve(role="subagent:vt", model="claude-haiku-4-5", max_output_tokens=1_000)

        assert first is not None
        assert second is None  # 1_000 + 1_000 > 1_500

    async def test_a_refused_reservation_leaves_both_ceilings_untouched(self):
        # The atomicity guarantee: a call blocked by the output ceiling must not
        # have quietly spent USD on the way to being refused.
        budget = Budget(total_micro_usd=1_000_000, max_output_tokens_total=500)

        r = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=1_000)

        assert r is None
        assert budget.remaining == 1_000_000
        assert budget.output_tokens_remaining == 500

    async def test_a_refusal_on_usd_leaves_the_output_ceiling_untouched(self):
        # The mirror case: USD binds first, output ceiling must not be debited.
        budget = Budget(total_micro_usd=1, max_output_tokens_total=10_000)

        r = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=1_000)

        assert r is None
        assert budget.output_tokens_remaining == 10_000

    async def test_settle_credits_back_the_unused_output_hold(self):
        budget = Budget(total_micro_usd=1_000_000, max_output_tokens_total=5_000)
        r = await budget.reserve(role="subagent:siem", model="claude-haiku-4-5", max_output_tokens=1_000)

        await budget.settle(r, Usage(input_tokens=200, output_tokens=300))

        # Held 1_000, produced 300 -> 700 credited back: 4_000 + 700.
        assert budget.output_tokens_remaining == 4_700

    async def test_release_credits_back_the_full_output_hold(self):
        budget = Budget(total_micro_usd=1_000_000, max_output_tokens_total=5_000)
        r = await budget.reserve(role="subagent:siem", model="claude-haiku-4-5", max_output_tokens=1_000)

        await budget.release(r)

        assert budget.output_tokens_remaining == 5_000

    async def test_committed_output_can_never_exceed_the_ceiling(self):
        # The invariant the whole dimension exists for: even when every call
        # overshoots its USD estimate, settled output tokens plus outstanding
        # holds stay under the ceiling. Ten calls of 600 against a 2_000 ceiling.
        budget = Budget(total_micro_usd=1_000_000_000, max_output_tokens_total=2_000)

        reservations = await asyncio.gather(
            *[
                budget.reserve(role="subagent:siem", model="claude-haiku-4-5", max_output_tokens=600)
                for _ in range(10)
            ]
        )

        granted = [r for r in reservations if r is not None]
        assert len(granted) == 3  # 3 * 600 = 1_800 fits, a 4th would exceed 2_000
        assert budget.output_tokens_remaining == 2_000 - 3 * 600
        assert budget.output_tokens_remaining >= 0

    async def test_the_usd_ledger_is_unaffected_by_the_output_dimension(self):
        # The two ceilings are orthogonal: adding the output dimension must not
        # change what the USD path records.
        budget = Budget.from_usd(1.0, max_output_tokens_total=100_000)
        r = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=10, task_id="t1")

        actual = await budget.settle(r, Usage(output_tokens=10))

        assert actual == 10 * 25
        assert budget.spend_by_role() == {"planner": 10 * 25}

    def test_from_usd_carries_the_ceiling(self):
        budget = Budget.from_usd(2.5, max_output_tokens_total=42_000)

        assert budget.remaining == 2_500_000
        assert budget.output_tokens_remaining == 42_000


class TestPerTaskOutputAllowance:
    def test_one_tasks_default_allowance_covers_a_broker_and_three_siem_steps(self):
        # a818a3fd G1 (B-2): the third siem step was refused with $9.96 left.
        from smartops.broker import DEFAULT_BROKER_TURNS
        from smartops.budget import loop_output_tokens
        from smartops.main import DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK
        from smartops.subagents import _recovery_output_tokens

        broker = ModelChoice(model_id="m", pricing_key="claude-haiku-4-5", effort="high")
        siem = ModelChoice(model_id="m", pricing_key="claude-haiku-4-5", effort="medium")
        hold = (
            loop_output_tokens(broker, DEFAULT_BROKER_TURNS, 0)
            + 3 * (loop_output_tokens(siem, 25, 0) + _recovery_output_tokens(siem))
        )
        assert hold <= DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK


class TestLedger:
    async def test_spend_by_role_and_by_task(self):
        budget = Budget.from_usd(1.0)

        planner = await budget.reserve(role="planner", model="claude-opus-5", max_output_tokens=10)
        await budget.settle(planner, Usage(output_tokens=10))

        edr_a = await budget.reserve(role="subagent:edr", model="claude-haiku-4-5", max_output_tokens=10, task_id="t1")
        await budget.settle(edr_a, Usage(output_tokens=10))

        edr_b = await budget.reserve(role="subagent:edr", model="claude-haiku-4-5", max_output_tokens=10, task_id="t2")
        await budget.settle(edr_b, Usage(output_tokens=10))

        assert budget.spend_by_role() == {"planner": 10 * 25, "subagent:edr": 10 * 5 * 2}
        assert budget.spend_by_task() == {"t1": 10 * 5, "t2": 10 * 5}

    async def test_task_id_omitted_for_non_mission_roles_and_excluded_from_by_task(self):
        budget = Budget.from_usd(1.0)
        critic = await budget.reserve(role="critic", model="claude-opus-5", max_output_tokens=10)
        await budget.settle(critic, Usage(output_tokens=10))

        assert budget.spend_by_task() == {}
        assert budget.spend_by_role() == {"critic": 10 * 25}


class TestProviderLadder:
    """Startup resolution from env: Bedrock -> DeepSeek -> nothing.

    No live calls anywhere -- these assert which provider is *selected*, which
    is a pure function of the environment.
    """

    PROVIDER_VARS = (
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "DEEPSEEK_API_KEY",
        BEDROCK_MODEL_ID_ENV_VAR,
        "SMARTOPS_MODEL_ID",
        "SMARTOPS_PRICING_KEY",
        PROVIDER_ENV_VAR,
    )
    BEDROCK_ID = "us.anthropic.claude-sonnet-4-6-20260115-v1:0"

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        for var in self.PROVIDER_VARS:
            monkeypatch.delenv(var, raising=False)

    def test_no_credentials_selects_no_provider(self):
        # A supported state, not an error: the caller falls back to a scripted
        # invoker and the run still completes.
        assert available_provider() is None
        assert model_choice_from_env() is None

    def test_deepseek_is_selected_when_only_it_is_configured(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-fake")

        assert available_provider() is Provider.DEEPSEEK

    def test_bedrock_wins_when_both_are_configured(self, monkeypatch):
        # Bedrock is the primary; DeepSeek is the cheaper alternative, not the
        # preference.
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-fake")
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, self.BEDROCK_ID)
        monkeypatch.setenv("AWS_REGION", "us-east-1")

        assert available_provider() is Provider.BEDROCK

    def test_explicit_override_beats_detection(self, monkeypatch):
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, self.BEDROCK_ID)
        monkeypatch.setenv(PROVIDER_ENV_VAR, "deepseek")

        assert available_provider() is Provider.DEEPSEEK

    def test_none_turns_the_model_off_despite_credentials(self, monkeypatch):
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, self.BEDROCK_ID)
        monkeypatch.setenv(PROVIDER_ENV_VAR, "none")

        assert available_provider() is None

    def test_an_unknown_provider_name_names_the_valid_ones(self, monkeypatch):
        monkeypatch.setenv(PROVIDER_ENV_VAR, "gpt-9")

        with pytest.raises(ValueError, match="bedrock"):
            available_provider()

    def test_aws_region_alone_does_not_select_bedrock(self, monkeypatch):
        # AWS_REGION is set in almost any AWS environment -- for S3, CloudWatch,
        # anything. Activating on it would select Bedrock for deployments that
        # never intended to use a model at all.
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        assert available_provider() is None

    def test_bedrock_choice_carries_the_region_explicitly(self, monkeypatch):
        # Passing region_name explicitly matters: AWS_REGION loses to a
        # configured profile, and Strands then falls back to us-west-2 silently.
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, self.BEDROCK_ID)
        monkeypatch.setenv("AWS_REGION", "eu-central-1")

        choice = model_choice_from_env()

        assert choice.provider is Provider.BEDROCK
        assert choice.region == "eu-central-1"

    def test_the_pricing_key_is_inferred_from_the_model_id(self, monkeypatch):
        # So only one variable has to be configured in the common case. The two
        # namespaces stay distinct; the second is just derived rather than typed.
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, self.BEDROCK_ID)
        monkeypatch.setenv("AWS_REGION", "us-east-1")

        choice = model_choice_from_env()

        assert choice.model_id == self.BEDROCK_ID
        assert choice.pricing_key == "claude-sonnet-4-6"

    def test_an_explicit_pricing_key_overrides_inference(self, monkeypatch):
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, self.BEDROCK_ID)
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("SMARTOPS_PRICING_KEY", "claude-opus-5")

        assert model_choice_from_env().pricing_key == "claude-opus-5"

    def test_an_unbillable_model_id_raises_rather_than_guessing(self, monkeypatch):
        # Billing a non-Claude model against a Claude tier silently would be
        # worse than refusing to start.
        monkeypatch.setenv(BEDROCK_MODEL_ID_ENV_VAR, "meta.llama3-70b-instruct-v1:0")
        monkeypatch.setenv("AWS_REGION", "us-east-1")

        with pytest.raises(ValueError, match="SMARTOPS_PRICING_KEY"):
            model_choice_from_env()

    def test_bedrock_without_a_model_id_names_the_variable_to_set(self, monkeypatch):
        # No placeholder default: one that looks configured and 404s on the
        # first call is worse than a startup error naming the fix.
        monkeypatch.setenv(PROVIDER_ENV_VAR, "bedrock")

        with pytest.raises(ValueError, match=BEDROCK_MODEL_ID_ENV_VAR):
            model_choice_from_env()

    def test_deepseek_fails_loudly_until_its_rates_are_known(self, monkeypatch):
        # Deliberate: DeepSeek has no PRICING entry yet, so selecting it raises
        # naming the gap. Better a startup error than a ledger reporting the
        # cheap provider as free -- the exact bug the nano-USD change fixed, and
        # this keeps it from returning by the back door.
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-fake")

        with pytest.raises(ValueError, match="PRICING"):
            model_choice_from_env()

    def test_an_openai_compatible_provider_needs_a_key_env_var(self):
        choice = ModelChoice(
            model_id="deepseek-chat",
            pricing_key="claude-sonnet-4-6",  # stand-in; rates aren't the point here
            provider=Provider.DEEPSEEK,
            base_url="https://api.deepseek.com",
            api_key_env_var=None,
        )

        with pytest.raises(ValueError, match="api_key_env_var"):
            choice.build()

    def test_an_openai_compatible_provider_reports_a_missing_key(self, monkeypatch):
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        choice = ModelChoice(
            model_id="deepseek-chat",
            pricing_key="claude-sonnet-4-6",
            provider=Provider.DEEPSEEK,
            base_url="https://api.deepseek.com",
            api_key_env_var="DEEPSEEK_API_KEY",
        )

        with pytest.raises(ValueError, match="DEEPSEEK_API_KEY is not set"):
            choice.build()

    def test_the_api_key_is_not_stored_on_the_choice(self, monkeypatch):
        # It is read from the environment at build() time, so a repr of the
        # choice -- in a log line, a traceback, a span -- cannot leak it.
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-super-secret")
        choice = ModelChoice(
            model_id="deepseek-chat",
            pricing_key="claude-sonnet-4-6",
            provider=Provider.DEEPSEEK,
            base_url="https://api.deepseek.com",
            api_key_env_var="DEEPSEEK_API_KEY",
        )

        assert "sk-super-secret" not in repr(choice)

    def test_bedrock_build_returns_a_model_not_a_bare_string(self, monkeypatch):
        # The reason build() exists: Bedrock accepts a bare id, but returning a
        # string for an OpenAI-compatible provider would be misread as a Bedrock
        # id. Both paths must return something Agent(model=...) can take.
        built = {}

        class FakeBedrockModel:
            def __init__(self, **kwargs):
                built.update(kwargs)

        import strands.models.bedrock as bedrock_module

        monkeypatch.setattr(bedrock_module, "BedrockModel", FakeBedrockModel)

        choice = ModelChoice(
            model_id="us.anthropic.x-v1:0",
            pricing_key="claude-sonnet-4-6",
            provider=Provider.BEDROCK,
            region="eu-west-2",
        )
        result = choice.build()

        assert isinstance(result, FakeBedrockModel)
        assert built["model_id"] == "us.anthropic.x-v1:0"
        assert built["region_name"] == "eu-west-2"
        # Python Bedrock has no default request timeout -- an unset one would
        # hang a stuck connection forever, and Limits bounds tokens, not clock.
        assert built["boto_client_config"].connect_timeout == choice.connect_timeout
        assert built["boto_client_config"].read_timeout == choice.read_timeout


class TestCacheablePrefix:
    """Both halves of the cached prefix, and the provider boundary around them.

    Bedrock has no automatic caching, so a cache point is the only way to get
    one -- meaning the difference between "caching is on" and "caching silently
    never happened" is entirely these two call shapes. That is worth pinning:
    the failure mode is not an error, it is a full-price bill that looks normal.
    """

    def _bedrock(self, **overrides):
        return ModelChoice(
            model_id="us.anthropic.x-v1:0",
            pricing_key="claude-sonnet-4-6",
            provider=Provider.BEDROCK,
            **overrides,
        )

    def test_tool_schemas_are_marked_cacheable(self, monkeypatch):
        built = {}

        class FakeBedrockModel:
            def __init__(self, **kwargs):
                built.update(kwargs)

        import strands.models.bedrock as bedrock_module

        monkeypatch.setattr(bedrock_module, "BedrockModel", FakeBedrockModel)
        self._bedrock().build()

        # `cache_tools`, not the deprecated `cache_prompt` -- the latter warns
        # and this suite turns SDK deprecation warnings into errors.
        assert built["cache_tools"] == "default"
        assert "cache_prompt" not in built

    def test_the_system_prompt_carries_a_cache_point_after_its_text(self):
        blocks = self._bedrock().system_prompt_blocks("SYSTEM TEXT")

        # Order is load-bearing: everything BEFORE the cache point is what gets
        # cached, so a cache point placed first would cache nothing at all.
        assert blocks == [{"text": "SYSTEM TEXT"}, {"cachePoint": {"type": "default"}}]

    def test_a_non_bedrock_provider_gets_a_plain_string(self):
        # `cachePoint` is Bedrock's wire format. Handing it to an
        # OpenAI-compatible provider sends a content block it cannot parse.
        choice = ModelChoice(
            model_id="deepseek-chat",
            pricing_key="claude-haiku-4-5",
            provider=Provider.DEEPSEEK,
            base_url="https://api.deepseek.com",
            api_key_env_var="DEEPSEEK_API_KEY",
        )

        assert choice.system_prompt_blocks("SYSTEM TEXT") == "SYSTEM TEXT"

    def test_caching_can_be_turned_off_on_both_halves_together(self, monkeypatch):
        # One switch governs tools and system prompt, because a run with one
        # cached and the other not is a configuration nobody can name afterwards
        # when reading the cost ledger.
        built = {}

        class FakeBedrockModel:
            def __init__(self, **kwargs):
                built.update(kwargs)

        import strands.models.bedrock as bedrock_module

        monkeypatch.setattr(bedrock_module, "BedrockModel", FakeBedrockModel)
        choice = self._bedrock(cache_prefix=False)
        choice.build()

        assert "cache_tools" not in built
        assert choice.system_prompt_blocks("SYSTEM TEXT") == "SYSTEM TEXT"


class TestSubDollarRates:
    """Regression guard for the bug that made cheap providers unbillable.

    Rates used to be stored as integer USD-per-million-tokens, which equals
    micro-USD-per-token only for whole-dollar prices. Every Claude tier is
    $1-$25/Mtok so it never showed; a sub-dollar provider truncated to zero.
    These tests pin both halves of the damage.
    """

    # ~$0.27 in / ~$1.10 out per Mtok -- illustrative sub-dollar rates, in the
    # range a cheap provider actually charges. Not a claim about any vendor's
    # published prices.
    CHEAP = ModelPrice(input_per_token_nano=270, output_per_token_nano=1_100)

    @pytest.fixture(autouse=True)
    def _register_cheap_model(self):
        PRICING["test-cheap-model"] = self.CHEAP
        yield
        del PRICING["test-cheap-model"]

    def test_sub_dollar_input_rate_is_not_priced_as_free(self):
        # The core bug: input_per_mtok=int(0.27) was 0, so input tokens cost
        # nothing no matter how many there were.
        usage = Usage(input_tokens=1_000_000)

        assert cost_of("test-cheap-model", usage) == 270_000  # $0.27, not $0

    def test_sub_dollar_rates_price_a_realistic_call_exactly(self):
        usage = Usage(input_tokens=100_000, output_tokens=20_000)

        # (100_000*270 + 20_000*1_100) nano = 49_000_000 nano = 49_000 micro
        assert cost_of("test-cheap-model", usage) == 49_000

    def test_cheap_model_is_priced_below_an_expensive_one_not_equal_to_zero(self):
        usage = Usage(input_tokens=100_000, output_tokens=20_000)

        cheap = cost_of("test-cheap-model", usage)
        pricey = cost_of("claude-sonnet-4-6", usage)

        # The comparison the provider decision rests on: strictly cheaper, and
        # strictly positive. Truncation used to make this 0 vs 600_000.
        assert 0 < cheap < pricey

    async def test_budget_gating_still_bites_on_a_sub_dollar_model(self):
        # The consequential half: estimate_cost() feeds reserve(), so a zero
        # input rate made the admission check admit everything.
        estimate = estimate_cost(
            "test-cheap-model", max_output_tokens=10_000, estimated_input_tokens=100_000
        )
        assert estimate > 0

        budget = Budget(total_micro_usd=estimate - 1)
        assert await budget.reserve(
            role="broker",
            model="test-cheap-model",
            max_output_tokens=10_000,
            estimated_input_tokens=100_000,
        ) is None
        assert budget.remaining == estimate - 1

    async def test_input_tokens_count_toward_the_reservation_ceiling(self):
        # Guards the specific failure mode: with input priced at 0, these two
        # estimates were identical and an input-heavy call reserved nothing for
        # its input.
        without_input = estimate_cost("test-cheap-model", max_output_tokens=1_000)
        with_input = estimate_cost(
            "test-cheap-model", max_output_tokens=1_000, estimated_input_tokens=500_000
        )

        assert with_input > without_input

    def test_rounding_to_the_ledger_unit_is_half_up_on_the_total(self):
        # One rounding, on the whole call -- not per token, which would compound.
        # 5 tokens * 270 nano = 1350 nano = 1.35 micro -> 1
        assert cost_of("test-cheap-model", Usage(input_tokens=5)) == 1
        # 6 tokens * 270 nano = 1620 nano = 1.62 micro -> 2
        assert cost_of("test-cheap-model", Usage(input_tokens=6)) == 2
