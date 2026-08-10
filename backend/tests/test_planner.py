from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from contracts import AnalystTask, Scope, TaskClassification

from smartops.budget import Budget
from smartops.planner import default_classifier, plan_missions


def make_scope(**overrides):
    now = datetime(2026, 8, 9, tzinfo=timezone.utc)
    defaults = dict(entities=["host-1"], time_window=(now - timedelta(hours=1), now))
    return Scope(**{**defaults, **overrides})


def make_task(**overrides):
    defaults = dict(
        task_id="t1",
        hypothesis_id="h1",
        goal="did host-1 execute a malicious binary",
        scope=make_scope(),
    )
    return AnalystTask(**{**defaults, **overrides})


@dataclass
class _FakeMetrics:
    accumulated_usage: dict


@dataclass
class _FakeResult:
    structured_output: TaskClassification | None
    metrics: _FakeMetrics = None

    def __post_init__(self):
        if self.metrics is None:
            self.metrics = _FakeMetrics(accumulated_usage={"inputTokens": 0, "outputTokens": 0})


def fake_classifier(classification: TaskClassification | None, usage: dict | None = None):
    """A `Classifier` stub that records the goal it was called with and
    returns a canned result, so tests never touch the real Strands SDK."""
    calls: list[str] = []

    def classify(goal: str) -> _FakeResult:
        calls.append(goal)
        return _FakeResult(
            structured_output=classification,
            metrics=_FakeMetrics(accumulated_usage=usage or {"inputTokens": 100, "outputTokens": 50}),
        )

    classify.calls = calls
    return classify


class TestPlanMissions:
    async def test_classifies_into_one_mission_per_family(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(TaskClassification(tool_families=["edr", "vt"], rationale="host + hash"))

        missions = await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        assert [m.tool_family for m in missions] == ["edr", "vt"]
        assert all(m.goal == task.goal for m in missions)
        assert all(m.scope == task.scope for m in missions)
        assert all(m.hypothesis_id == task.hypothesis_id for m in missions)

    async def test_mission_task_ids_are_derived_and_unique_per_family(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(TaskClassification(tool_families=["edr", "vt"], rationale="host + hash"))

        missions = await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        assert [m.task_id for m in missions] == ["t1:edr", "t1:vt"]

    async def test_empty_tool_families_produces_no_missions(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(TaskClassification(tool_families=[], rationale="nothing domain-relevant"))

        missions = await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        assert missions == []

    async def test_exhausted_budget_returns_no_missions_without_calling_classifier(self):
        task = make_task()
        budget = Budget(total_micro_usd=0)
        classify = fake_classifier(TaskClassification(tool_families=["edr"], rationale="irrelevant"))

        missions = await plan_missions(task, budget, model="claude-opus-5", classify=classify)

        assert missions == []
        assert classify.calls == []

    async def test_classifier_called_with_the_task_goal(self):
        task = make_task(goal="is 1.2.3.4 beaconing to a known C2 domain")
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(TaskClassification(tool_families=["ndr"], rationale="ip + beaconing"))

        await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        assert classify.calls == ["is 1.2.3.4 beaconing to a known C2 domain"]

    async def test_usage_is_translated_from_strands_camel_case_and_settled(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(
            TaskClassification(tool_families=["edr"], rationale="host"),
            usage={
                "inputTokens": 200,
                "outputTokens": 100,
                "cacheReadInputTokens": 50,
                "cacheWriteInputTokens": 10,
            },
        )

        await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        # haiku: input=1, output=5, cache_write=1*1.25, cache_read=1*0.1 micro-usd/token
        expected_cost = 200 * 1 + 100 * 5 + round(10 * 1 * 1.25) + round(50 * 1 * 0.1)
        assert budget.spend_by_role() == {"planner": expected_cost}
        assert budget.spend_by_task() == {"t1": expected_cost}

    async def test_missing_structured_output_raises(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(None)

        with pytest.raises(Exception):
            await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

    async def test_default_classifier_is_not_constructed_when_one_is_injected(self):
        # regression guard: passing `classify` must short-circuit before any
        # attempt to import/construct a real strands.Agent.
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(TaskClassification(tool_families=[], rationale="n/a"))

        await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)  # must not raise/import strands

    async def test_duplicate_families_from_the_classifier_are_deduplicated(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        classify = fake_classifier(TaskClassification(tool_families=["edr", "edr", "vt"], rationale="dup"))

        missions = await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        assert [m.task_id for m in missions] == ["t1:edr", "t1:vt"]

    async def test_exception_during_classification_releases_the_reservation(self):
        task = make_task()
        budget = Budget.from_usd(1.0)
        remaining_before = budget.remaining

        def classify(goal):
            raise RuntimeError("provider timeout")

        with pytest.raises(RuntimeError):
            await plan_missions(task, budget, model="claude-haiku-4-5", classify=classify)

        # released, not settled: full credit back, no ledger entry recorded
        # for a call that never actually happened.
        assert budget.remaining == remaining_before
        assert budget.ledger == []


class TestDefaultClassifier:
    def test_applies_a_soft_output_token_cap_and_the_structured_output_model(self):
        with patch("strands.Agent") as MockAgent:
            mock_agent_instance = MagicMock()
            MockAgent.return_value = mock_agent_instance

            classify = default_classifier("claude-haiku-4-5", max_output_tokens=321)
            classify("some goal")

            _, construct_kwargs = MockAgent.call_args
            assert construct_kwargs["model"] == "claude-haiku-4-5"
            assert construct_kwargs["structured_output_model"] is TaskClassification

            call_args, call_kwargs = mock_agent_instance.call_args
            assert call_args == ("some goal",)
            assert call_kwargs["limits"]["output_tokens"] == 321
