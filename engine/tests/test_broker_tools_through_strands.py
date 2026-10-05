"""The Broker's tools, invoked the way Strands actually invokes them.

Every other test calls these functions directly, with arguments already built into
`FetchStep` / `Scope` objects. Strands does not: it validates the model's raw JSON
against the generated schema and passes whatever that produces. For a
`list[FetchStep]` parameter, what arrives is a list of plain **dicts**.

That difference hid a total failure of `plan_fetch`. Iterating the raw `steps`
argument and reading `step.step_id` raised `AttributeError: 'dict' object has no
attribute 'step_id'` on every live call. Strands turned it into an error tool
result, the model re-planned, failed identically, and six of eleven turns were
gone before `broker_task` fell back to a synthesized plan -- so a run still
produced a report and nothing looked broken. Meanwhile 800-odd tests passed,
because they all handed the function objects it could not have received.

These tests go through `DecoratedFunctionTool.stream()` for that reason. Direct
calls are still worth having -- they are how the branch logic is exercised -- but
at least one path per tool has to cross the boundary the model's input crosses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from smartops.broker import BrokerRequest, plan_fetch

from contracts import AnalystTask, Entity, Scope


class _StubAgent:
    """`ToolContext` requires `invocation_state["agent"]`; nothing here reads it."""


def _task() -> AnalystTask:
    return AnalystTask(
        task_id="t-1",
        hypothesis_id="h-1",
        goal="check the reputation of coinhive.com",
        scope=Scope(
            entities=[Entity(kind="domain", value="coinhive.com")],
            time_window=(
                datetime(2018, 8, 20, tzinfo=UTC),
                datetime(2018, 8, 21, tzinfo=UTC),
            ),
        ),
    )


async def _call(tool: Any, tool_input: dict, req: BrokerRequest) -> dict:
    """Invoke a decorated tool the way the framework does, and return its result."""
    tool_use = {"toolUseId": "tooluse_1", "name": tool.tool_spec["name"], "input": tool_input}
    invocation_state = {"agent": _StubAgent(), "smartops": req}
    last = None
    async for event in tool.stream(tool_use, invocation_state):
        last = event
    return last["tool_result"]


# The shape a real model emitted on the run that exposed this: plain dicts, all
# required fields present, `completion` nested as its own dict.
_MODEL_PLAN = {
    "rationale": "reputation first, then look for the indicator in our own logs",
    "steps": [
        {
            "step_id": "vt_domain_rep",
            "family": "vt",
            "objective": "external reputation for coinhive.com",
            "completion": {"requires": "rows_or_confirmed_empty", "categories": []},
        },
        {
            "step_id": "vt_ip_rep",
            "family": "vt",
            "objective": "external reputation for 217.182.164.14",
            "completion": {"requires": "rows_or_confirmed_empty", "categories": []},
        },
    ],
}


class TestPlanFetchAcceptsWhatAModelActuallySends:
    @pytest.fixture
    def req(self) -> BrokerRequest:
        return BrokerRequest(task=_task())

    async def test_a_well_formed_plan_of_dicts_succeeds(self, req):
        """The regression. This exact input shape failed six times in a row live
        while every direct-call test passed."""
        result = await _call(plan_fetch, _MODEL_PLAN, req)

        assert result["status"] == "success", result["content"]

    async def test_the_plan_is_actually_recorded(self, req):
        """`status=success` alone would not catch a tool that swallowed the plan.
        The point of planning is that the step ids exist afterwards, because
        `_dispatch()` refuses any dispatch that cannot cite one."""
        await _call(plan_fetch, _MODEL_PLAN, req)

        assert req.plan is not None
        assert [s.step_id for s in req.plan.steps] == ["vt_domain_rep", "vt_ip_rep"]
        assert set(req.step_outcomes) == {"vt_domain_rep", "vt_ip_rep"}

    async def test_the_steps_are_coerced_to_the_contract_type(self, req):
        """`FetchPlan(...)` is what turns the model's dicts into `FetchStep`s, and
        everything downstream -- `evaluate_step`, `StepOutcome.step` -- assumes the
        typed object. A dict reaching `step_outcomes` would fail later and further
        from the cause."""
        from contracts import FetchStep

        await _call(plan_fetch, _MODEL_PLAN, req)

        for outcome in req.step_outcomes.values():
            assert isinstance(outcome.step, FetchStep)

    async def test_a_planned_step_starts_unevaluated(self, req):
        """Planned is not judged. `evaluated=False` until a rule runs against a
        real result -- otherwise a step nobody dispatched reports
        `completed=False, evaluated=True`, which means "ran and fell short"."""
        await _call(plan_fetch, _MODEL_PLAN, req)

        for outcome in req.step_outcomes.values():
            assert outcome.evaluated is False
            assert outcome.completed is False

    async def test_only_the_required_fields_is_enough(self, req):
        """`completion` and `depends_on` are optional in the schema, so a model may
        omit them; the defaults have to survive the coercion."""
        result = await _call(
            plan_fetch,
            {
                "rationale": "r",
                "steps": [{"step_id": "vt-1", "family": "vt", "objective": "rep"}],
            },
            req,
        )

        assert result["status"] == "success", result["content"]
        assert req.plan is not None


class TestPlanFetchRefusesLegiblyThroughTheFramework:
    @pytest.fixture
    def req(self) -> BrokerRequest:
        return BrokerRequest(task=_task())

    async def test_a_duplicate_step_id_is_refused_as_a_readable_tool_result(self, req):
        """`plan_fetch` catches `ValidationError` and returns prose naming the
        problem, precisely so the model does not get the framework's generic
        error. That path only means anything if it is reachable from here -- and
        it must come back as `success` carrying a refusal, not as `error`, or the
        model sees a stack trace instead of an instruction."""
        result = await _call(
            plan_fetch,
            {
                "rationale": "r",
                "steps": [
                    {"step_id": "vt-1", "family": "vt", "objective": "a"},
                    {"step_id": "vt-1", "family": "vt", "objective": "b"},
                ],
            },
            req,
        )

        assert result["status"] == "success"
        text = result["content"][0]["text"]
        assert "refused" in text
        assert "vt-1" in text
        # Nothing recorded, so a plan already in place would survive.
        assert req.plan is None

    async def test_an_unknown_family_is_rejected_by_the_schema(self, req):
        """`family` is a `ToolFamily` Literal, so this never reaches the function.
        Asserted so the boundary is documented: schema-level refusals return
        `error` and carry no guidance, which is why the checks that DO want to
        guide the model live inside the function."""
        result = await _call(
            plan_fetch,
            {
                "rationale": "r",
                "steps": [{"step_id": "x-1", "family": "carrier_pigeon", "objective": "a"}],
            },
            req,
        )

        assert result["status"] == "error"
        assert req.plan is None
