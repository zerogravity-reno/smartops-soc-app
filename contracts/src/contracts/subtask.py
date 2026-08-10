"""Subtask contract: the interface between the Analyst/Triage agent and per-domain subagents.

This module defines the *shape* of a mission and its result only. Dispatch, budget
charging, retries, and aggregation are separate components that consume these types.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator

ToolFamily = Literal["edr", "ndr", "vt", "siem"]


class Scope(BaseModel):
    """The slice of the environment a mission is allowed to look at."""

    entities: list[str] = Field(min_length=1)
    time_window: tuple[datetime, datetime]

    @field_validator("entities")
    @classmethod
    def _entities_are_non_empty(cls, entities: list[str]) -> list[str]:
        # `min_length=1` only bounds the list; an entity of "" or "  " would
        # otherwise pass through as a real scope boundary -- e.g. into a
        # subagent's query construction -- and silently widen a search
        # instead of failing loudly.
        if any(not entity.strip() for entity in entities):
            raise ValueError("entities must not contain empty or blank strings")
        return entities

    @model_validator(mode="after")
    def _window_is_ordered_and_aware(self) -> Self:
        start, end = self.time_window
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("time_window datetimes must be timezone-aware")
        if start >= end:
            raise ValueError("time_window start must be before end")
        return self


class SubtaskStatus(StrEnum):
    """Terminal status of a subagent's attempt at a mission.

    ok       - executed at least one tool call and produced a usable result.
    no_data  - executed successfully but the domain had nothing relevant.
    error    - a tool/LLM invocation failed (including budget exhaustion) after
               retries were exhausted; `error` must be set.
    rejected - the subagent never attempted execution because the mission was
               unworkable for its domain. Distinct from `error`: no tool call was
               ever attempted or charged against budget.
    """

    OK = "ok"
    NO_DATA = "no_data"
    ERROR = "error"
    REJECTED = "rejected"


class SubagentMission(BaseModel):
    """A unit of work handed from the Analyst to exactly one domain subagent.

    Deliberately excludes any pre-authored tool call, query, or parameters: only
    `goal` and `scope` are set upstream. The receiving subagent is solely responsible
    for deriving, executing, and repairing its own tool call(s) against `goal` +
    `scope`.
    """

    schema_version: int = 1
    task_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    tool_family: ToolFamily
    goal: str = Field(min_length=1)
    scope: Scope
    context: str | None = None
    budget_cost: int = Field(
        default=1,
        ge=0,
        description=(
            "Advisory estimate only, set by the Analyst for its own round-planning. "
            "Never charged directly -- the shared Budget is only ever charged by a "
            "subagent at the point of an actual tool/LLM invocation."
        ),
    )


class Evidence(BaseModel):
    """One piece of raw tool output. Never shown to an LLM directly.

    Subagents attach these to their SubtaskResult; the aggregator is what actually
    writes them into the case file's evidence store, keyed by `id`.
    """

    id: str = Field(min_length=1)
    tool_family: ToolFamily
    raw: Any
    collected_at: datetime


class _StatusErrorContract(BaseModel):
    """Shared status/error consistency rule for anything a subagent produces."""

    status: SubtaskStatus
    error: str | None = None

    @model_validator(mode="after")
    def _error_matches_status(self) -> Self:
        if self.status == SubtaskStatus.ERROR and not self.error:
            raise ValueError("status=error requires a non-empty `error`")
        if self.status != SubtaskStatus.ERROR and self.error:
            raise ValueError("`error` must be unset unless status=error")
        return self


class SubagentAnswer(_StatusErrorContract):
    """The shape a subagent's LLM is forced into via structured output.

    Deliberately excludes `task_id` (the mission already knows it) and `evidence`
    (raw tool output is assembled by code from what the tool calls actually
    returned, never authored by the model) -- the model only ever sees and produces
    a short digest plus the citation ids it collected along the way.
    """

    summary: str = Field(min_length=1)
    citation_ids: list[str] = Field(default_factory=list)


class SubtaskResult(_StatusErrorContract):
    """Full result returned by a subagent, consumed only by the aggregator."""

    task_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    citation_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def _evidence_ids_are_unique(self) -> Self:
        ids = [e.id for e in self.evidence]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"evidence ids must be unique, duplicated: {sorted(dupes)}")
        return self

    @model_validator(mode="after")
    def _citations_resolve_to_evidence(self) -> Self:
        known_ids = {e.id for e in self.evidence}
        dangling = set(self.citation_ids) - known_ids
        if dangling:
            raise ValueError(f"citation_ids reference unknown evidence: {sorted(dangling)}")
        return self

    @classmethod
    def from_answer(cls, *, task_id: str, answer: SubagentAnswer, evidence: list[Evidence]) -> Self:
        """Assemble the aggregator-facing result from a model's forced answer plus
        the evidence the subagent's own tool-call loop collected."""
        return cls(task_id=task_id, evidence=evidence, **answer.model_dump())
