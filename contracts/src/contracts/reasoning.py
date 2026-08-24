"""Analysis-layer contracts: what a subagent-analyst concludes about a hypothesis.

The Task Broker *fetches* evidence; it is fenced out of drawing conclusions
(`smartops.broker` system prompt). This module defines the shapes of the layer
that does the concluding: three domain **subagent-analysts** (identity, network,
endpoint) each return an `AnalystVerdict` on whether their slice of the fetched
evidence supports or refutes the hypothesis, and a thin combiner rolls the three
into one `HypothesisAssessment`.

Shape only. Routing, prompt construction, model invocation, and parsing live in
`smartops.subagent_analysts` and consume these types.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

AnalystDomain = Literal["identity", "network", "endpoint"]
"""The three analysis domains, distinct from the fetch-side `ToolFamily`.

Not derived from `ToolFamily` (`edr/ndr/vt/siem`) nor from `EntityKind`: a domain
is an *analysis* concern that draws from several CIM categories and entity kinds
at once. `smartops.subagent_analysts.routing` owns the domain -> evidence mapping.
"""

Stance = Literal["supports", "refutes", "inconclusive"]
"""A verdict's position on the hypothesis.

`inconclusive` is a first-class outcome, not a failure: an analyst that was handed
too little evidence must say so rather than guess, and the combiner treats it
differently from a genuine `supports`/`refutes`.
"""


class InvestigationContext(BaseModel):
    """The "why" handed to the analysts, alongside the fetched evidence.

    Today only `{hypothesis_id, goal, scope}` is carried end to end (see
    `AnalystTask`); hypothesis prose and any seed-event detail were deliberately
    excluded until a consumer needed them. The analysts are that consumer, so
    this is the minimal channel: the hypothesis in plain language now, with
    `seed_event` reserved for the raw alert/event the investigation started from.

    Both fields are attacker-influenceable (a hypothesis is written about, and a
    seed event derived from, alert data), so a consumer MUST fence and escape
    them into a prompt as untrusted data -- see
    `smartops.subagent_analysts.prompts`.
    """

    hypothesis: str = Field(min_length=1)
    seed_event: dict[str, Any] | None = None


class AnalystVerdict(BaseModel):
    """One domain analyst's conclusion about the hypothesis.

    `reasoning_trace` holds the model's `<think>...</think>` chain, kept for audit
    and never fed back into any prompt -- the same context-isolation rule the
    fetch side applies to raw `Evidence`.
    """

    domain: AnalystDomain
    stance: Stance
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    key_observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(
        default_factory=list,
        description="Evidence header ids the verdict rests on, e.g. 'auth_events#1'.",
    )
    reasoning_trace: str | None = Field(
        default=None,
        description="The model's <think> chain. Persisted for audit, never re-fed.",
    )
    prompt_tokens: int = Field(
        default=0,
        ge=0,
        description="Prompt tokens the model reported for this verdict's call(s); 0 if no model was called.",
    )
    generation_tokens: int = Field(
        default=0,
        ge=0,
        description="Generation tokens the model reported for this verdict's call(s); 0 if no model was called.",
    )


class DomainFinding(BaseModel):
    """One domain analyst's evidence-grounded findings, with no hypothesis in view.

    Tier 1 of the hypothesis-blind pipeline (see
    docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md): the
    domain analyst never sees the hypothesis, so there is no `stance` here --
    only what the evidence itself shows. A later Aggregator cycle turns a list
    of these plus a hypothesis into an `AnalystVerdict` per domain.
    """

    domain: AnalystDomain
    observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(
        default_factory=list,
        description="Evidence header ids the finding rests on, e.g. 'auth_events#1'.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence that these observations are real and correctly grounded -- "
            "not confidence in any stance; there is no stance at this layer."
        ),
    )
    rationale: str = ""
    reasoning_trace: str | None = Field(
        default=None,
        description="The model's <think> chain. Persisted for audit, never re-fed.",
    )
    prompt_tokens: int = Field(default=0, ge=0)
    generation_tokens: int = Field(default=0, ge=0)


class HypothesisAssessment(BaseModel):
    """The rolled-up conclusion for one hypothesis, from the three domain verdicts.

    Return contract of the analysis layer, the counterpart to `BrokerReport` on
    the fetch side. `overall_stance` and `confidence` are produced by a thin
    combiner over `verdicts`; the per-domain verdicts are retained so the
    roll-up is auditable rather than a bare label.
    """

    schema_version: int = 1
    task_id: str = Field(
        min_length=1,
        description=(
            "The `BrokerReport.task_id` this assessment was drawn from -- the join "
            "key back to `report.json`. Required, and deliberately so: every "
            "assessment.json written before this field carried only a hardcoded "
            "`hypothesis_id` of 'cli-hypothesis', which left co-location in a "
            "directory as the sole link between a verdict and its evidence. An "
            "assessment that cannot name its report is not auditable."
        ),
    )
    run_id: str | None = Field(
        default=None,
        description=(
            "The timestamped run directory this assessment belongs to, stamped by "
            "`smartops.main._persist_assessment` at write time. Optional because "
            "`analyze()` legitimately does not know it -- the run directory is "
            "chosen by the persistence layer, not the analysis layer. It makes the "
            "artifact self-describing if it is ever copied out of its folder."
        ),
    )
    hypothesis_id: str = Field(min_length=1)
    overall_stance: Stance
    confidence: float = Field(ge=0.0, le=1.0)
    verdicts: list[AnalystVerdict] = Field(default_factory=list)

    def total_prompt_tokens(self) -> int:
        return sum(v.prompt_tokens for v in self.verdicts)

    def total_generation_tokens(self) -> int:
        return sum(v.generation_tokens for v in self.verdicts)
