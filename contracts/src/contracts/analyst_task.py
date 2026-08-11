"""AnalystTask: the Analyst's tool-agnostic output for one hypothesis, and the
input to the Subtasks Planner.

Deliberately carries only what the Analyst can specify without naming a
product, index, or field: a goal and a scope (see `Analyst Agent` Asana card).
The Planner classifies this into zero or more `SubagentMission`s -- one per
`ToolFamily` it decides is relevant -- via `smartops.planner.plan_missions()`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from contracts.subtask import Scope, ToolFamily


class AnalystTask(BaseModel):
    """One hypothesis's worth of investigative intent, before any domain
    classification has happened.

    This is the Analyst -> Broker interface. It is versioned because the Analyst
    that produces it does not exist yet: the Broker (its only consumer) defines
    the shape it needs, and extension by the producer should be a normal event
    rather than a break. Deliberately excludes hypothesis prose, prior findings,
    and round/priority -- each would be a guess about what an unbuilt Analyst
    wants, and the first two are further attacker-influenceable input to defend.
    """

    schema_version: int = 1
    task_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    goal: str = Field(min_length=1)
    scope: Scope


class TaskClassification(BaseModel):
    """Forced structured-output shape for the Planner's classification call.

    `tool_families` being empty is not a *validation* error -- Pydantic
    accepts it, `plan_missions()` won't raise. But don't read that as "safe to
    ignore": in practice an empty result almost always means the classifier
    failed to match a domain for a real investigative task, not that the task
    is genuinely irrelevant to every known specialist. Distinct from
    `SubtaskStatus.rejected`, which is a subagent's verdict on a mission it
    actually received -- the Planner never creates a mission for a family it
    didn't select here, so there's no equivalent verdict to inspect.

    Currently `plan_missions()` returns `[]` on this with no visibility --
    no log, no telemetry span, nothing distinguishing "correctly nothing to
    do" from "the classifier missed." That's a real gap, not a design
    decision -- revisit once tool execution is real (see the 2026-08-09
    session doc) and this can actually happen against production tasks
    instead of hand-written test cases.
    """

    tool_families: list[ToolFamily] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
