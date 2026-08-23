"""Subtask contract: the interface between the Analyst/Triage agent and per-domain subagents.

This module defines the *shape* of a mission and its result only. Dispatch, budget
charging, retries, and aggregation are separate components that consume these types.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    Field,
    create_model,
    field_validator,
    model_validator,
)

from contracts.findings import (
    Assessment,
    CimCategory,
    Findings,
    SiemAssessment,
    SiemFindings,
    VtAssessment,
    VtFindings,
)

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


MAX_ENTITY_VALUE_LENGTH = 512
"""Upper bound on an `Entity.value`. An observable is not a payload.

Comfortably above every kind's realistic maximum -- SHA-512 hex is 128
characters, IPv6 with an embedded IPv4 is 45, a DNS name caps at 253 -- and far
below the room an injected instruction wants. `url` is the only kind for which
this is a judgement rather than a fact.
"""

_FORBIDDEN_IN_ENTITY_VALUE = frozenset("<>")
"""The two characters checked first, for a message more specific than "not
ASCII printable": a prompt fence uses them as structure.

Prompt builders quote untrusted prose inside a named fence and escape it on the
way in. Entity *values* deliberately are not escaped: the model has to retype
them verbatim into an SPL predicate or a reputation lookup, and mutating one
changes which indicator gets queried -- the exact silent failure
`_value_is_not_blank` below already records once. So the structure is refused
here instead, where it fails loudly and once for every producer.

`<` and `>` are also members of the ASCII-printable allowlist
`_value_carries_no_structure` enforces below -- they are excluded from it, and
this set is why. Checking them first, ahead of the broader range test, is what
lets the raised message say "prompt fence" rather than the less actionable
"outside the ASCII-printable range."

No legitimate observable needs these: RFC 3986 excludes raw `<` and `>` from a
URI, and they cannot appear in a hostname, DNS name, address, or hex digest. The
one real casualty is a `process` value carrying shell redirection -- and
`EntityKind` above already records `process` as one of its least settled members,
so this is revisitable rather than free.
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

    @field_validator("value")
    @classmethod
    def _value_carries_no_structure(cls, value: str) -> str:
        """Refuse anything that could carry structure into a prompt.

        Runs after `_value_is_not_blank`, on the stripped value: validators for
        one field fire in definition order, so this sees the normalised string
        and an interior newline is still caught while a trailing one is not an
        error.

        **This is an allowlist, not a blocklist -- an earlier version was a
        blocklist and it was wrong.** That version rejected only C0/C1 controls
        plus ASCII `<` / `>`, behind a comment claiming "an entity is a
        single-line observable." False as implemented: seven bypass classes
        measured surviving it and rendering byte-identical into the
        `<entities>` fence -- U+2028/U+2029 (line/paragraph separator, forges a
        line break), U+FF1C/U+FF1E and U+3008/U+3009 (fullwidth and CJK angle
        brackets, a homoglyph pseudo-tag), U+202E (right-to-left override,
        display spoofing), U+200B (zero-width space), U+00A0 (no-break space).
        NFKC normalisation was evaluated as a fix and rejected on evidence: it
        catches exactly one of those seven, the fullwidth pair. A blocklist
        only ever enumerates the bypasses someone already thought of; the
        allowlist below is closed by construction instead.

        So: every character of the stripped value must be ASCII printable,
        `0x20`-`0x7E`, minus `<` and `>` (checked first, in
        `_FORBIDDEN_IN_ENTITY_VALUE`, so that rejection can say "prompt fence"
        instead of the less actionable "outside the ASCII-printable range").
        Each message names the offending class rather than saying "invalid" --
        these values arrive by hand, and an analyst who pasted a URL with a
        stray newline needs to know which rule bit them. The offending
        character is reported as `U+XXXX` rather than printed literally,
        because by definition it may not be printable or may not render in
        whatever is reading the message.

        **The cost, recorded rather than hidden:** an internationalized domain
        in its Unicode form is now refused -- `domain:münchen.de` fails
        this check where `domain:xn--mnchen-3ya.de` (its punycode form)
        passes. Arguably not a compromise: punycode is the canonical ASCII
        form a SIEM or DNS query actually resolves against, so ASCII-only is
        the more correct shape for an observable, not merely the safer one.
        """
        if len(value) > MAX_ENTITY_VALUE_LENGTH:
            raise ValueError(
                f"entity value is {len(value)} characters, over the "
                f"{MAX_ENTITY_VALUE_LENGTH}-character limit -- an observable this "
                f"long is far more likely to be pasted junk than an indicator"
            )
        forbidden = next((c for c in value if c in _FORBIDDEN_IN_ENTITY_VALUE), None)
        if forbidden is not None:
            raise ValueError(
                f"entity value contains {forbidden!r} (U+{ord(forbidden):04X}), which "
                f"a prompt fence uses as structure. Percent-encode it (%3C / %3E) if "
                f"it is genuinely part of the observable"
            )
        # The allowlist. Every C0/C1 control (`\n`, `\r`, `\t`, and the rest)
        # falls outside 0x20-0x7E already, so this replaces that check as well
        # as catching what it always missed: line/paragraph separators,
        # homoglyph brackets, bidi overrides, and invisible/no-break
        # whitespace -- see the seven codepoints in the docstring above, all
        # of which render byte-identical to a real observable in the fence a
        # blocklist cannot see past.
        bad = next((c for c in value if not (0x20 <= ord(c) <= 0x7E)), None)
        if bad is not None:
            if ord(bad) < 0x20 or 0x7F <= ord(bad) <= 0x9F:
                raise ValueError(
                    f"entity value contains the control character U+{ord(bad):04X}; "
                    f"an entity is a single-line observable, so newlines, tabs, and "
                    f"control characters are not accepted"
                )
            raise ValueError(
                f"entity value contains U+{ord(bad):04X}, outside the ASCII-printable "
                f"range (U+0020-U+007E) this contract allows. Look-alike characters "
                f"and invisible or bidi-control codepoints render byte-identical to a "
                f"real observable inside a prompt fence, so this is an allowlist "
                f"rather than a blocklist of what someone already thought to forbid. "
                f"If this is an internationalized domain, use its ASCII punycode form "
                f"(xn--...), which is what a SIEM or DNS query actually resolves"
            )
        return value


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


class QueryRun(BaseModel):
    """One query a subagent chose to run, and what it was after.

    `category` is the model classifying *its own action* -- something it knows
    without inspecting a single row -- which is what lets code bucket the result
    sets in `findings.SiemFindings` with no per-sourcetype parser.

    Reporting the query text also makes index scoping a visible, checkable fact on
    every result. The 2026-08-11 run issued every SPL as `index=*` and nothing
    short of a raw span dump revealed it.
    """

    query: str = Field(min_length=1)
    category: CimCategory | None = Field(
        default=None,
        description=(
            "Which CIM category this query was retrieving. Null for domains with "
            "no CIM taxonomy, such as a reputation lookup."
        ),
    )


class SubagentAnswer(_StatusErrorContract):
    """The shape a subagent's LLM is forced into via structured output.

    Deliberately excludes `task_id` (the mission already knows it) and `evidence`
    (raw tool output is assembled by code from what the tool calls actually
    returned, never authored by the model).

    **There is no `summary` field, and that is the point.** It used to be the only
    place findings could go, so prose was the only available shape -- prose becomes
    narrative, and narrative wants a conclusion, which is the Analyst's job and not
    this one's. Findings now travel as typed rows assembled by code; what the model
    contributes is `queries_run` and a small `assessment`.

    This class is a **base**: each family's concrete answer model adds a typed
    `assessment` field, built by `make_answer_model()`. It is not handed to Strands
    directly -- see that factory for why a parameterized generic cannot be.
    """

    queries_run: list[QueryRun] = Field(
        default_factory=list,
        description="Every query this subagent ran, in the order it ran them.",
    )
    citation_ids: list[str] = Field(default_factory=list)
    gaps: list[ToolFamily] = Field(
        default_factory=list,
        description=(
            "Domains that could close a gap this subagent hit. Advisory only -- "
            "the Broker decides whether to dispatch them. Typed to ToolFamily so "
            "an untrusted model response can't smuggle free text through this field."
        ),
    )


def make_answer_model(family: ToolFamily, assessment_model: type[Assessment]) -> type[SubagentAnswer]:
    """Build the concrete answer model a family's subagent is forced into.

    **Why a factory and not `SubagentAnswer[P]`.** Strands derives the structured
    output tool's name from `model.__name__` with no sanitisation
    (`strands/tools/structured_output/structured_output_utils.py`), and a
    parameterized pydantic generic is named `SubagentAnswer[SiemAssessment]` --
    brackets included. Bedrock requires tool names to match
    `^[a-zA-Z0-9_-]{1,64}$`, so that call fails at the provider. A concrete model
    with a plain name is what has to reach Strands.

    Mirrors `smartops.broker.make_investigate_tool()`: one factory over the
    registry rather than a hand-written class per family.
    """
    return create_model(
        f"{family.capitalize()}Answer",
        __base__=SubagentAnswer,
        assessment=(assessment_model, ...),
    )


class SubtaskResult(_StatusErrorContract):
    """Full result returned by a subagent, consumed only by the aggregator."""

    task_id: str = Field(min_length=1)
    reason: str | None = Field(
        default=None,
        description=(
            "Why this status, in plain language. **Written by code, never by a "
            "model** -- it is not a summary of findings and must not become one. "
            "It exists because `_StatusErrorContract` forbids `error` unless "
            "status=error, which left a rejection with nowhere to say why it was "
            "rejected. Required for `rejected`, since an unexplained rejection is "
            "indistinguishable from a bug."
        ),
    )
    findings: Annotated[SiemFindings | VtFindings, Field(discriminator="tool_family")] | None = Field(
        default=None,
        description=(
            "The per-family typed payload, projected from `evidence` by code. A "
            "discriminated union (keyed on each subclass's `tool_family`) rather than "
            "a plain `Findings` annotation: pydantic needs the discriminator both to "
            "dump every subclass field (a bare `Findings` annotation would dump only "
            "the base class's, silently to `{}`) and, the newer half of this, to "
            "reload one -- `SubtaskResult.model_validate_json()` on a saved report "
            "otherwise cannot tell a saved entry was `SiemFindings` and silently "
            "reconstructs the empty base class instead, which is exactly what made "
            "`broker.load_run_artifacts()` unsafe until this was added. Extending to a "
            "new family (edr/ndr) means adding it to this union, not a silent gap --"
            " an unlisted subclass now fails loudly at construction, not on reload."
        ),
    )
    assessment: Annotated[SiemAssessment | VtAssessment, Field(discriminator="tool_family")] | None = Field(
        default=None,
        description=(
            "The model's own small judgement, carried over from the concrete "
            "per-family answer model `make_answer_model()` built. Same discriminated-"
            "union reasoning as `findings` above -- a plain `Assessment` annotation "
            "would silently lose every subclass field such as `SiemAssessment.covered` "
            "both on dump and (the newer half) on reload. Not decorative: a fetch "
            "plan's completion rules read `covered` / `not_covered` to judge whether a "
            "step retrieved what was asked for, and `BrokerReport` is assembled from "
            "`SubtaskResult`s, so anything not carried here never reaches the Analyst. "
            "`None` for a rejected or errored subtask, where no model ever ran."
        ),
    )
    queries_run: list[QueryRun] = Field(
        default_factory=list,
        description=(
            "Mirrors `SubagentAnswer.queries_run`, and declared on BOTH models for "
            "the same reason as `gaps` below."
        ),
    )
    blocked_queries: list[str] = Field(
        default_factory=list,
        description=(
            "Queries a guard cancelled before they ran, assembled by code and "
            "never model-authored. Deliberately NOT merged into `queries_run`, "
            "which means 'queries this subagent ran'. It is here because a "
            "cancelled call yields an error tool result, `_EvidenceCollector` "
            "drops those, and so an attempt to query outside the allowlist "
            "previously left no trace anywhere -- making it invisible both to an "
            "analyst reading the report and to the benchmark metric whose whole "
            "job is to catch it."
        ),
    )
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

    @model_validator(mode="after")
    def _rejection_says_why(self) -> Self:
        if self.status == SubtaskStatus.REJECTED and not (self.reason and self.reason.strip()):
            raise ValueError("status=rejected requires a non-empty `reason`")
        return self

    @classmethod
    def from_answer(
        cls,
        *,
        task_id: str,
        answer: SubagentAnswer,
        evidence: list[Evidence],
        findings: Findings | None = None,
        reason: str | None = None,
    ) -> Self:
        """Assemble the aggregator-facing result from a model's forced answer plus
        the evidence the subagent's own tool-call loop collected.

        **Fields are mapped explicitly rather than splatted.** This used to be
        `cls(..., **answer.model_dump())`, which worked only while both models
        carried the same field names. The answer now carries `assessment` and the
        result carries `findings`, and pydantic's default `extra="ignore"` would
        drop the mismatch **silently** -- the same failure the `gaps` docstring
        below documents, which is why `gaps` is declared on both models.

        `findings` is passed in rather than read off the answer because it is
        assembled by code from `evidence`; a model never authors it.

        `assessment` is read off `answer` with `getattr`, not attribute access,
        because it exists only on the concrete per-family model
        `make_answer_model()` builds -- the `SubagentAnswer` base this method is
        typed against has no such field, and a bare `answer.assessment` would
        raise `AttributeError` for any caller that (legitimately, per tests)
        constructs a plain `SubagentAnswer`.
        """
        known_ids = {e.id for e in evidence}
        cids = [cid for cid in answer.citation_ids if cid in known_ids] if known_ids else [e.id for e in evidence]
        return cls(
            task_id=task_id,
            status=answer.status,
            error=answer.error,
            reason=reason,
            findings=findings,
            assessment=getattr(answer, "assessment", None),
            queries_run=list(answer.queries_run),
            citation_ids=cids,
            gaps=list(answer.gaps),
            evidence=evidence,
        )


class CompletionRule(BaseModel):
    """Rule evaluated by code to judge whether a fetch step is satisfied."""

    requires: Literal["rows_or_confirmed_empty", "rows_required"] = "rows_or_confirmed_empty"
    min_rows: int = 0
    categories: list[CimCategory] = Field(
        default_factory=list,
        description=(
            "CIM categories this step is responsible for. When set, only rows in "
            "these categories count toward `min_rows` -- so a step planned to "
            "resolve a domain is not closed by process events somebody else "
            "retrieved. Empty, the default, counts every category the family "
            "returned, which is the only sensible rule for a family whose "
            "findings are not bucketed this way (`vt`). Rows the subagent never "
            "tagged land in `SiemFindings.uncategorised` and deliberately do NOT "
            "satisfy a named category: that bucket exists to record attribution "
            "failure, and letting it stand in for a category would put the "
            "false-completion problem back where it was."
        ),
    )


class FetchStep(BaseModel):
    """One bounded retrieval step in a Broker's fetch plan."""

    step_id: str = Field(min_length=1)
    family: ToolFamily
    objective: str = Field(min_length=1)
    completion: CompletionRule = Field(default_factory=CompletionRule)
    depends_on: list[str] = Field(
        default_factory=list,
        description=(
            "step_ids this step must not start before. Empty -- the default, and "
            "the usual case -- declares the step independent, which is what lets a "
            "scheduler overlap it with every other independent step. It exists "
            "because a code-driven step loop has to decide an order, and without a "
            "declared dependency the only safe order is sequential, which would "
            "make scheduling a property of the topology rather than of the plan. "
            "Advisory where the executing agent schedules itself by emitting tool "
            "calls (the model already orders those); load-bearing where code "
            "schedules the steps. Unknown, self-referential, and cyclic entries "
            "are dropped by the scheduler rather than deadlocking it -- a plan is "
            "model-authored and cannot be trusted to be a DAG."
        ),
    )


class FetchPlan(BaseModel):
    """The Broker's explicit fetch plan, authored via `plan_fetch` before dispatch."""

    steps: list[FetchStep] = Field(min_length=1)
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def _step_ids_are_unique(self) -> Self:
        """`step_id` is the key everything downstream is filed under, so a
        duplicate is not a cosmetic problem -- it is unrecoverable.

        A model naming its steps per family (`step-1` for siem, `step-1` for vt)
        is an entirely plausible thing to do, and before this validator existed it
        produced two failures at once: dispatch resolved a step by first match, so
        the shadowed step **vanished** from `step_outcomes` -- a plan step with no
        outcome in the report -- and the wrong-family refusal told the model to
        retry the exact id it had just used, which loops until the turn budget
        runs out. Rejecting the plan at construction turns both into one loud,
        recoverable failure before anything is fetched.
        """
        seen: dict[str, int] = {}
        for step in self.steps:
            seen[step.step_id] = seen.get(step.step_id, 0) + 1
        collisions = [f"{sid!r} appears {n} times" for sid, n in seen.items() if n > 1]
        if collisions:
            raise ValueError(
                f"duplicate step_id in fetch plan: {'; '.join(collisions)}. "
                "Every step_id must be unique across the whole plan, not just "
                "within one family"
            )
        return self


class StepOutcome(BaseModel):
    """Evaluated outcome for one step in a fetch plan."""

    step: FetchStep
    completed: bool = False
    dispatches: int = 0
    rows_retrieved: int = 0
    confirmed_empty: bool = False
    status: SubtaskStatus | None = None
    reason: str | None = None
    evaluated: bool = True
    """False for any step that never went through `broker.evaluate_step()` -- the
    single implementation of the completion rule, and the only place this flag is
    set to True. Two paths mint an outcome without evaluating one: `plan_fetch`,
    which records a step the moment it is planned and long before anything is
    dispatched to it, and `broker.py`'s synthesized-plan fallback, which
    reconstructs a `FetchStep` per dispatched family after the model never called
    `plan_fetch`. `completed` on such a step is not a judgement, real or
    fabricated; it is just `False`, because nobody -- code or model -- ever
    evaluated a rule against it. A consumer must check this before trusting
    `completed`: `completed=False, evaluated=False` means "unknown", not "ran
    and fell short" (that is `completed=False, evaluated=True`).
    """
    refused_for_budget: bool = False
    """True when the step's most recent dispatch never actually executed
    because the shared `Budget` refused to reserve it (see
    `smartops.broker.BUDGET_REFUSAL_ERROR`). Distinct from an unmet completion
    rule on purpose: `completed=False` alone reads as "criteria not met", which
    is a fetch-quality problem, but a budget refusal is a cost problem -- the
    step was never attempted. Conflating the two turns a budget shortfall into
    what looks like a data gap.
    """


class CostSummary(BaseModel):
    """Summary of investigation spend by role and remaining budget."""

    spend_by_role: dict[str, int] = Field(default_factory=dict)
    total_spend_micro_usd: int = 0
    budget_remaining_micro_usd: int = 0


class BrokerReport(BaseModel):
    """Return contract to the Analyst: full record of one investigation run."""

    schema_version: int = 1
    task_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    plan: FetchPlan | None = None
    plan_repairs: int = 0
    """How many `depends_on` defects a code scheduler had to repair before the
    plan could be walked: each dropped edge (naming an unknown step, or the step
    itself) and each step released early to break a dependency cycle counts one.

    A plan is model-authored, so repairing it silently is the right call at
    runtime -- deadlocking on a bad edge would be worse. But **plan quality is
    one of the things the A/B compares**, so a repaired plan is a datum, not a
    detail, and it existed only as a `logger.warning` that no artifact captured.

    Zero where nothing was repaired *and* where nothing schedules from the plan:
    an arm whose model orders its own dispatches never walks `depends_on`, so it
    has no defect to find and honestly reports none.
    """
    step_outcomes: list[StepOutcome] = Field(default_factory=list)
    results: list[SubtaskResult] = Field(default_factory=list)
    dispatched: list[ToolFamily] = Field(default_factory=list)
    classification: Any
    cost: CostSummary
    queries_run: list[QueryRun] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

