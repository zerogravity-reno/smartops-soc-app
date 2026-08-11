"""AnalystTask: the Analyst's tool-agnostic output for one hypothesis, and the
input to the Task Broker.

Deliberately carries only what the Analyst can specify without naming a
product, index, or field: a goal and a scope (see `Analyst Agent` Asana card).

The Broker turns this into zero or more `SubagentMission`s by *calling a domain
specialist's tool* -- that tool call IS the classification decision. There is no
separate classification step: an earlier design ran one LLM call to pick tool
families and then dispatched, which is two calls making the same decision, and
`smartops.planner.plan_missions()` was retired with it. See `smartops.broker`.

Until an Analyst agent exists, `smartops.main` mimics this handover, which is
what the `schema_version` below is for.
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
    """Forced structured-output shape for the Broker's own account of its run.

    This is the Broker's *self-report*, not the record of what happened.
    `BrokerOutcome.dispatched` is observed independently at the moment of each
    dispatch, and the two are compared precisely because a model's account of its
    reasoning can diverge from its behaviour -- `broker_task()` logs a warning
    when it does, and trusts the observed list.

    `tool_families` being empty is not a *validation* error -- Pydantic accepts
    it. But don't read that as "safe to ignore": for a real investigative task an
    empty result almost always means the Broker failed to match a domain, not
    that the task is genuinely irrelevant to every specialist. `broker_task()`
    warns on it for that reason.

    Distinct from `SubtaskStatus.rejected`, which is a subagent's verdict on a
    mission it actually received. A family absent from `tool_families` was never
    engaged at all, so there is no such verdict to inspect.

    The Broker may also produce *no* structured output -- Strands ends a
    turn-limited or token-limited run with a `stop_reason` and raises nothing. In
    that case `broker_task()` synthesizes this from what was observed rather than
    discarding evidence the dispatches already collected and paid for, and marks
    the rationale as unavailable.
    """

    tool_families: list[ToolFamily] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
