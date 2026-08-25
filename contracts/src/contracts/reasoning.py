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

Disposition = Literal["benign", "suspicious", "malicious", "inconclusive"]
"""What a slice of evidence shows, judged without reference to any hypothesis.

Deliberately a different axis from `Stance`, not a renaming of it. A `Stance` is
relative to a claim -- and a claim shown to the analyst is a claim the analyst can
be led by ("20 auth events means malicious" plus 20 auth events reliably yields
`supports`). A `Disposition` is a reading of the rows themselves, which is
answerable from the evidence alone and so cannot be anchored by a hypothesis the
analyst never saw.

The two are not convertible in either direction, and nothing here should try:
benign evidence can refute one hypothesis and support another, and the mapping
depends on the hypothesis. Making that call is the Analyst Agent's job, which is
exactly the separation `HypothesisFindings` exists to preserve.

`inconclusive` is first-class for the same reason it is in `Stance`: an analyst
handed too little to read must say so rather than guess. It is also the default,
so a finding that failed to parse or had no evidence cannot silently read as
`benign`.
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
    citation_evidence: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Each kept citation mapped to the `Evidence.id`s it resolves to, "
            "frozen when the verdict was finalised. This is what makes the "
            "grounding durable rather than merely enforced at runtime: the gate "
            "really does drop fabricated citations, but that decision was never "
            "recorded, so a stored verdict could not be traced to the rows it "
            "rested on without recomputing the routing. A list per citation "
            "because one `reputation#1` header covers every VT verdict in a slice."
        ),
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
    """One domain analyst's judgement of its evidence, with no hypothesis in view.

    The blind half of the pipeline (see
    docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md). The
    analyst never sees the hypothesis -- told "20 auth events means malicious",
    a model shown 20 auth events reports malicious, and that is the hypothesis
    talking, not the evidence.

    Blind does **not** mean silent. The analyst still judges: it reads the rows
    and says what they are. What it cannot do is judge the *hypothesis*, which
    is why `disposition` is a reading of the evidence (benign/suspicious/
    malicious) and not a `Stance` (supports/refutes). Those are different axes,
    and only the second one can be led. `HypothesisFindings` attaches these
    judgements to the hypothesis they were formed without.
    """

    domain: AnalystDomain
    disposition: Disposition = Field(
        default="inconclusive",
        description=(
            "What this domain's evidence shows, judged on its own terms. NOT a "
            "position on any hypothesis -- see `Disposition`."
        ),
    )
    observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(
        default_factory=list,
        description="Evidence header ids the finding rests on, e.g. 'auth_events#1'.",
    )
    citation_evidence: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Each kept citation mapped to the `Evidence.id`s it resolves to, "
            "frozen when the finding was finalised. Same role as "
            "`AnalystVerdict.citation_evidence`: it is what makes the grounding "
            "durable rather than merely enforced at runtime. Deferred in the "
            "2026-08-24 artifact-contract work as speculative because nothing "
            "consumed a `DomainFinding` yet; `HypothesisFindings` now does, and "
            "the whole point of that contract is that its consumer can trace a "
            "judgement to the rows behind it."
        ),
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence in `disposition`, given the evidence seen. While this "
            "layer had no judgement to be confident about, the field measured "
            "grounding quality instead ('these observations are real and "
            "correctly grounded'); it now means what a consumer actually "
            "weighs. Safe to redefine rather than version because "
            "`gather_finding()` had no production callers, so no `DomainFinding` "
            "has ever been persisted. A second field for grounding confidence "
            "was considered and dropped: an 8B model asked for two calibrated "
            "numbers returns one number twice, and grounding quality is now "
            "separately observable from whether `citation_evidence` resolves."
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


class Exhibit(BaseModel):
    """The actual rows behind one citation, rendered as the analyst saw them.

    An `Evidence.id` is a pointer, and a pointer is only useful to a consumer
    holding the evidence store. The Analyst Agent is a separate component and may
    hold nothing; without the rows it can weigh a judgement only by trusting it.

    Carrying every routed block instead would be the other failure -- on
    `cli-20260825T100434` each domain was routed 32-35 blocks and cited one, so
    the full pack is ~13-19k characters per domain against ~250 for the cited
    blocks. Only what was cited travels.

    `rows` is the same projected, `_sanitise`d text the domain analyst read, not
    a re-render: an exhibit that formatted the rows differently from the evidence
    the judgement was formed on would be a different exhibit.
    """

    citation: str = Field(
        min_length=1, description="The header id, e.g. 'auth_events#1'."
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description=(
            "The `Evidence.id`s this block was projected from, for a consumer that "
            "does hold the store and wants the untruncated rows."
        ),
    )
    row_count: int = Field(
        ge=0,
        description=(
            "Rows in the underlying set, which is NOT the number rendered in "
            "`rows` -- exhibits are row-capped. Carried separately so a consumer "
            "can see that a cited set was empty, which is invisible from an id "
            "alone and which the grounding gate does not check for."
        ),
    )
    rows: str = Field(
        default="",
        description="The rendered block: its `# header` line and the capped rows beneath it.",
    )


class DomainJudgement(BaseModel):
    """One domain's judgement as it crosses to the Analyst Agent.

    The wire projection of a `DomainFinding`. Same judgement, minus what is ours
    rather than the consumer's, plus the evidence needed to check it.

    Dropped from `DomainFinding`: `reasoning_trace`, `prompt_tokens`,
    `generation_tokens`. The token counts are our telemetry. The trace is stronger
    than that -- it is documented "persisted for audit, never re-fed", and putting
    a model's private chain-of-thought into a contract handed to another model is
    exactly re-feeding it. A projection rather than a `model_dump(exclude=...)` so
    the published schema does not advertise fields the consumer must know to
    ignore.

    Added: `exhibits`. See `Exhibit`.
    """

    domain: AnalystDomain
    disposition: Disposition
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    exhibits: list[Exhibit] = Field(
        default_factory=list,
        description="The cited evidence, one entry per kept citation.",
    )


class HypothesisFindings(BaseModel):
    """Three blind domain judgements, attached to the hypothesis they never saw.

    **The contract handed up to the Analyst Agent.** That agent is a separate
    component, owned elsewhere; this is the boundary, and everything about the
    shape follows from which side of it a decision belongs on.

    What is here: what each domain's evidence shows, judged on the evidence
    alone, and the means to verify that judgement against the rows behind it.

    What is deliberately NOT here: any position on the hypothesis. There is no
    `overall_stance` and no combiner, because deciding whether these findings
    support or refute the hypothesis is the Analyst Agent's job. That absence is
    the contract, not an omission -- `HypothesisAssessment` is the shape that
    carries a decided stance, and it is a different shape for that reason.

    The hypothesis appears here only as an id and, optionally, its prose. It is
    the *attachment point*: the analysts formed their judgements without it, and
    this is where the two are joined. A consumer that renders `hypothesis` into
    a prompt MUST fence and escape it -- it is attacker-influenceable, the same
    as `InvestigationContext.hypothesis`.

    All three domains always appear in `findings`, including ones that got no
    evidence. An empty domain is reported as `inconclusive` with no
    observations, never silently omitted: "we looked and found nothing" and "we
    did not look" are different facts, and the consumer cannot recover the
    difference from a missing entry.
    """

    schema_version: int = 1
    task_id: str = Field(
        min_length=1,
        description=(
            "The `BrokerReport.task_id` these findings were drawn from -- the join "
            "key back to `report.json`, and the prefix every `Evidence.id` in "
            "`citation_evidence` is built from. See "
            "docs/superpowers/specs/2026-08-25-evidence-link-contract-design.md."
        ),
    )
    run_id: str | None = Field(
        default=None,
        description=(
            "The timestamped run directory these findings belong to. Unlike "
            "`HypothesisAssessment.run_id`, `gather()` sets this at construction "
            "wherever the caller knows it, rather than leaving it for the "
            "persistence layer to stamp on write. Stamping on write is fine for an "
            "artifact whose next stop is our own disk; this one is handed to "
            "another system and may never be persisted here at all, so a null "
            "`run_id` would make it unidentifiable at exactly the moment it "
            "crosses the boundary. Still optional, because a caller genuinely may "
            "not know it -- but it should be the exception now, not the default."
        ),
    )
    hypothesis_id: str = Field(min_length=1)
    hypothesis: str | None = Field(
        default=None,
        description=(
            "The hypothesis prose, if the producer had it. Carried so the artifact "
            "is self-describing rather than resolvable only against a live "
            "`InvestigationContext`. Attacker-influenceable -- fence and escape it "
            "before it reaches any prompt."
        ),
    )
    findings: list[DomainJudgement] = Field(
        default_factory=list,
        description="One per analysis domain, including domains that saw no evidence.",
    )

    def total_prompt_tokens(self) -> int:
        return sum(v.prompt_tokens for v in self.verdicts)

    def total_generation_tokens(self) -> int:
        return sum(v.generation_tokens for v in self.verdicts)
