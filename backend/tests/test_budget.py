import asyncio

import pytest

from smartops.budget import PRICING, Budget, ModelPrice, Usage, cost_of, estimate_cost


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
