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

EntityKind = Literal["host", "user", "ip", "file_hash", "domain", "url", "process"]
"""What kind of observable an entity is.

Typed rather than a bare string because a `ToolFamily`'s *dispatchability* is a
fact about the observables in scope, not a judgement: VirusTotal cannot be
queried without a hash, IP, domain, or URL, no matter what any model decides.
Consumers derive that from `Entity.kind`; see `smartops.broker`, which owns the
family -> required-kinds mapping (this module deliberately holds shape only).

Proposed by the Broker as its consumer, pending review against Yousef's
Context Contract Template. `process` and `url` are the least settled members.
"""


class Entity(BaseModel):
    """One observable a mission is allowed to look at."""

    kind: EntityKind
    value: str = Field(min_length=1)

    @field_validator("value")
    @classmethod
    def _value_is_not_blank(cls, value: str) -> str:
        # `min_length=1` bounds length but accepts "   ". A whitespace-only
        # value would pass through as a real scope boundary -- e.g. into a
        # subagent's query construction -- and silently widen a search
        # instead of failing loudly.
        if not value.strip():
            raise ValueError("entity value must not be blank")
        # Return the *stripped* value, not the original. Validating `strip()`
        # while storing the raw string let surrounding whitespace survive into
        # every downstream query -- a URL path segment, an SPL predicate -- so
        # `"ip: 10.2.4.9"` looked up a different indicator than was typed, with
        # no error. Normalising here fixes it for every producer at once rather
        # than in each caller.
        return value.strip()


class Scope(BaseModel):
    """The slice of the environment a mission is allowed to look at."""

    entities: list[Entity] = Field(min_length=1)
    time_window: tuple[datetime, datetime]

    def kinds(self) -> set[EntityKind]:
        """The distinct observable kinds in scope. Consumers use this to decide
        whether a domain can be queried at all."""
        return {entity.kind for entity in self.entities}

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
    gaps: list[ToolFamily] = Field(
        default_factory=list,
        description=(
            "Domains that could close a gap this subagent hit. Advisory only -- "
            "the Broker decides whether to dispatch them. Typed to ToolFamily so "
            "an untrusted model response can't smuggle free text through this field."
        ),
    )


class SubtaskResult(_StatusErrorContract):
    """Full result returned by a subagent, consumed only by the aggregator."""

    task_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    citation_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    gaps: list[ToolFamily] = Field(
        default_factory=list,
        description=(
            "Mirrors `SubagentAnswer.gaps`. Declared on BOTH models deliberately: "
            "`from_answer()` splats `**answer.model_dump()`, and pydantic's default "
            "`extra='ignore'` would SILENTLY DROP a field present only on the answer, "
            "losing the signal between the subagent and the aggregator with no error."
        ),
    )

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
