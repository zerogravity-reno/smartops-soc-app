"""Subtasks Planner: classifies an `AnalystTask` into per-domain `SubagentMission`s.

Owns exactly one decision -- which `ToolFamily`/families a task needs -- and
nothing else. Explicitly NOT this module's job (see docs/sessions for the
reasoning that drew these lines):

- Discovering which concrete tools exist for a family right now -- that's
  Task Broker Agent (Mariam's), which resolves "available tools to use" per
  family, dynamically, against the live MCP gateway.
- Actually calling a tool -- that's each subagent's own `Agent`, built with
  `tools/registry.tools_for(mission.tool_family)`, deriving and executing its
  own tool call(s) against `goal` + `scope`.

Classification is one LLM call per `AnalystTask`, forced into `TaskClassification`
via Strands' `structured_output_model` (the current, non-deprecated API --
`Agent.structured_output()` is deprecated as of strands-agents 1.50). An empty
`tool_families` result is a valid outcome: the task is unworkable for every
known domain, so zero missions are created, and that's not an error.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Protocol

from contracts import AnalystTask, SubagentMission, TaskClassification

from smartops.budget import Budget, Usage

PLANNER_ROLE = "planner"


class ClassifierResult(Protocol):
    """The minimal shape `plan_missions()` needs back from a classification
    call. Matches `strands.agent.AgentResult` structurally, without importing
    `strands` on the test import path -- fakes in tests just need to satisfy
    this shape.
    """

    structured_output: TaskClassification | None
    metrics: object  # duck-typed: only `.accumulated_usage` is ever read


Classifier = Callable[[str], ClassifierResult]


@dataclass(frozen=True)
class _NoStructuredOutput(Exception):
    """Raised if a classification call didn't honor `structured_output_model`.

    Should be unreachable in practice -- Strands forces the call via a
    dedicated tool -- but `plan_missions()` must never silently treat a
    missing classification as "no relevant domains".
    """

    task_id: str

    def __str__(self) -> str:
        return f"classification call for task {self.task_id!r} returned no structured_output"


def default_classifier(model: str, max_output_tokens: int) -> Classifier:
    """Production `Classifier`: a fresh `Agent` per call.

    Freshness matters because `AgentResult.metrics.accumulated_usage` is
    cumulative over an `Agent` instance's whole lifetime, not just the last
    call -- reusing one long-lived planner `Agent` across rounds would leak
    prior calls' usage into every later `Budget.settle()`. A new `Agent` per
    call makes "accumulated" and "this call's usage" the same thing.

    Passes `max_output_tokens` through as a Strands `Limits(output_tokens=...)`
    cap -- without it, `plan_missions()` reserves budget against a ceiling
    nothing on the actual call enforces. Note this is a *soft* cap per
    Strands' own semantics: it stops the loop from continuing once tripped,
    it cannot truncate a single oversized response already in flight. Still
    real protection here since a classification call rarely needs more than
    one turn.
    """

    def classify(goal: str) -> ClassifierResult:
        from strands import Agent  # local import: keep strands off the test import path
        from strands.types.agent import Limits

        agent = Agent(model=model, tools=[], structured_output_model=TaskClassification)
        return agent(goal, limits=Limits(output_tokens=max_output_tokens))

    return classify


def _usage_from_accumulated(accumulated: dict) -> Usage:
    """Translate Strands' `EventLoopMetrics.accumulated_usage` (Bedrock/
    Converse-style camelCase keys) into `Budget.Usage` (Anthropic-API-style
    snake_case, used everywhere else in this codebase). This is the one place
    that bridges the two.
    """
    return Usage(
        input_tokens=accumulated.get("inputTokens", 0),
        output_tokens=accumulated.get("outputTokens", 0),
        cache_creation_input_tokens=accumulated.get("cacheWriteInputTokens", 0),
        cache_read_input_tokens=accumulated.get("cacheReadInputTokens", 0),
    )


async def plan_missions(
    task: AnalystTask,
    budget: Budget,
    *,
    model: str,
    max_output_tokens: int = 500,
    classify: Classifier | None = None,
) -> list[SubagentMission]:
    """Classify `task` into zero or more `SubagentMission`s, one per relevant
    `ToolFamily`. Charges at most one LLM call against `budget` under
    `role="planner"`.

    Returns `[]` without calling the model if the budget can't cover the
    reservation -- the Planner stops immediately, it does not retry or
    degrade to a cheaper model on its own.
    """
    reservation = await budget.reserve(
        role=PLANNER_ROLE,
        model=model,
        task_id=task.task_id,
        max_output_tokens=max_output_tokens,
    )
    if reservation is None:
        return []

    classify = classify or default_classifier(model, max_output_tokens)
    try:
        # `classify` is a synchronous callable (production wraps a blocking
        # Strands `Agent.__call__`) -- run it off the event loop thread so one
        # in-flight classification doesn't stall every other coroutine sharing
        # this loop (other plan_missions() calls, subagents settling the same
        # Budget).
        result = await asyncio.to_thread(classify, task.goal)
    except Exception:
        # Nothing was actually spent -- release, don't settle, so this isn't
        # misrecorded as a zero-cost call that happened.
        await budget.release(reservation)
        raise

    usage = _usage_from_accumulated(result.metrics.accumulated_usage)
    await budget.settle(reservation, usage)

    classification = result.structured_output
    if classification is None:
        raise _NoStructuredOutput(task.task_id)

    # dict.fromkeys(...) dedupes while preserving order -- a classifier that
    # (legitimately or not) repeats a family must not mint two missions that
    # collide on the same derived task_id.
    return [
        SubagentMission(
            task_id=f"{task.task_id}:{family}",
            hypothesis_id=task.hypothesis_id,
            tool_family=family,
            goal=task.goal,
            scope=task.scope,
        )
        for family in dict.fromkeys(classification.tool_families)
    ]
