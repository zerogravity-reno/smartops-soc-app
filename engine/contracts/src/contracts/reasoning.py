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

import json
from datetime import UTC, datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, Field, model_validator

from contracts.findings import CimCategory
from contracts.subtask import ToolFamily

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
"""The vocabulary the **Analyst Agent** decides in. Nothing here emits one.

Declared in this package because this is the shared contract both sides of the
`HypothesisFindings` boundary import -- not because the tier below that boundary
fills it in. The three domain sub-analysts used to: each judged its own slice and
returned a `Disposition` on it. That authority was removed on 2026-08-31. They
translate their rows into plain English now (`DomainFinding.narrative`), and the
Analyst Agent -- which sees every domain AND the hypothesis -- is the only thing
that decides anything.

Kept rather than deleted along with the field it used to type, for two reasons.
Deleting it would leave the consumer's decision space undefined at the one
boundary whose whole job is to write that boundary down. And the contrast with
`Stance` is still the clearest statement of why the tier below is blind: a
`Stance` is relative to a claim, and a claim shown to an analyst is a claim the
analyst can be led by ("20 auth events means malicious" plus 20 auth events
reliably yields `supports`), while a `Disposition` is a reading of the rows
themselves. Neither converts into the other -- benign evidence can refute one
hypothesis and support another, and which it does depends on the hypothesis.
That is precisely why the tier holding the hypothesis is the tier that decides.

`inconclusive` is first-class for the same reason it is in `Stance`: a consumer
handed too little to read must be able to say so rather than guess.
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

    `reasoning_trace` holds the model's `<think>...</think>` chain, available for
    audit and never fed back into any prompt -- the same context-isolation rule the
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
        description=(
            "The model's <think> chain. Never re-fed into any prompt, and never on "
            "the wire -- `DomainJudgement` drops it. Persisted for audit only by a "
            "caller that passes `analyze.gather(trace_sink=...)`, which writes "
            "`traces.json` beside the run's other artifacts; a caller that passes "
            "no sink discards it. It said 'Persisted for audit' unconditionally, "
            "which was true of an older artifact format that dumped this model "
            "directly and false once the wire projection landed."
        ),
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
    """One domain analyst's plain-English account of its evidence.

    The blind half of the pipeline (see
    docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md). The
    analyst never sees the hypothesis -- told "20 auth events means malicious",
    a model shown 20 auth events reports malicious, and that is the hypothesis
    talking, not the evidence.

    Blind used to mean "may judge the rows, may not judge the claim": this
    carried a `Disposition` and a `confidence` in it. **Both were removed on
    2026-08-31.** Deciding which rows matter is already the judgement the Analyst
    Agent exists to make -- with sight of every domain and of the hypothesis --
    and a sub-analyst makes it blind, on one slice, with nothing able to check
    it. The 2026-08-30 live run is what settled the shape: the parser defaulted
    an absent `DISPOSITION` to `inconclusive`, so a domain that had read its rows
    correctly still crossed the wire carrying a verdict no model had formed.

    What is left is what this tier can be held to: `narrative` (what the rows
    say) and `observations` (one checkable line per distinct thing they state),
    each traceable to the rows behind it. `HypothesisFindings` attaches those to
    the hypothesis they were formed without.
    """

    domain: AnalystDomain
    narrative: str = Field(
        default="",
        description=(
            "Plain English: what these rows show, in order, naming the hosts, "
            "accounts, addresses and times. What happened -- explicitly NOT a "
            "reading of what it means, whether it is normal, or whether it is "
            "an attack. Replaces `rationale`, which was prose justifying a "
            "`disposition` this tier no longer forms."
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

    `query` is the one thing here the analyst did *not* see, and deliberately so
    -- see `formatting.format_result_set`.
    """

    citation: str = Field(
        min_length=1, description="The header id, e.g. 'auth_events#1'."
    )
    query: str = Field(
        default="",
        description=(
            "The query that retrieved this set. Carried HERE rather than in "
            "`rows` because the two consumers differ: the domain analyst is "
            "blind to the hypothesis and a query written to test it leaks it "
            "(see `formatting.format_result_set`), while the Analyst Agent is "
            "not blind and cannot judge an empty set without knowing what was "
            "asked. Empty for a `reputation#N` exhibit, which is a reputation "
            "lookup rather than a search, and for exhibits written before this "
            "field existed."
        ),
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

    **The name predates the shape.** It was named while this tier judged, and it
    was deliberately NOT renamed when the judging was removed on 2026-08-31: a
    rename would churn the contracts export, `analyze`, `main`, the published
    schema and every test that names the type, for no behavioural gain. Read it
    as "one domain's contribution", and read the fields for what it now is.
    There is no verdict in it -- no `disposition`, no `confidence`, no stance.
    See `Disposition` for where the deciding happens instead.
    """

    domain: AnalystDomain
    narrative: str = Field(
        default="",
        description=(
            "Plain English: what these rows show, in order. What happened, NOT "
            "what it means -- weighing it against the hypothesis is yours."
        ),
    )
    observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    exhibits: list[Exhibit] = Field(
        default_factory=list,
        description="The cited evidence, one entry per kept citation.",
    )
    summaries: list[str] = Field(
        default_factory=list,
        description=(
            "One computed account per non-empty set routed to this domain, cited "
            "or not: totals, distinct counts, top and rarest values and the time "
            "range, calculated in code over every row. Not model-authored, so it "
            "holds what the narrative may have left out."
        ),
    )


class StepSummary(BaseModel):
    """What became of one planned fetch step, as the Analyst Agent needs to see it.

    A projection of `contracts.subtask.StepOutcome`, code-assembled, carrying the
    four facts that change how a judgement should be weighed and nothing else.
    Dropped: `dispatches`, `refused_for_budget`, `status`, `reason` and the full
    `FetchStep` -- dispatch counts and budget refusals are our operational
    concern, not an input to reasoning about evidence.

    `evaluated` is here and is load-bearing: `completed=False, evaluated=False`
    means nobody ever judged this step, which is a different fact from
    `completed=False, evaluated=True` ("ran and fell short"). See
    `StepOutcome.evaluated`.
    """

    step_id: str = Field(min_length=1)
    family: ToolFamily
    objective: str = Field(min_length=1)
    completed: bool = False
    evaluated: bool = True
    confirmed_empty: bool = False
    rows_retrieved: int = Field(default=0, ge=0)


class DomainGap(BaseModel):
    """A domain that could not be searched, and why.

    **The third retrieval state.** `RetrievalSummary` already separates "we
    looked and found nothing" from "we did not look"; this separates both from
    "we *could not* look, because the instrument is not there." Without it a
    consumer reading a thin `endpoint` narrative cannot tell a quiet host from a
    host nobody was able to observe -- and the two justify opposite conclusions.

    Not hypothetical. On `botsv3-coinhive-*` (2026-09-02) `edr` and `ndr` are
    `{"disabled": true}` in `mcp_servers.json`, the Broker planned an
    `edr_host_processes` step it had no tool to dispatch, and the siem subagents
    themselves reported `gaps=['edr']`. Every one of those facts was recorded on
    the fetch side and none of it crossed this boundary, so the Analyst Agent was
    handed an endpoint judgement built entirely from SIEM process rows with no
    indication that a dedicated endpoint instrument was expected and absent.

    **A gap is not the same as a domain being irrelevant, and not the same as a
    failure.** A missing `edr` does not mean endpoint questions went unanswered:
    SIEM carries Sysmon process events and answered them on that run. What it
    means is that the answer rests on one instrument rather than two, which is a
    fact about confidence that only the Analyst Agent can price.

    Deliberately NOT shown to the domain analysts. They are blind by
    construction, and "no EDR instrument exists here" is a hint about what to
    expect to find. It belongs on the record, not in a prompt.
    """

    family: ToolFamily
    reason: Literal["not_configured", "no_tools_resolved", "no_observable_in_scope"]
    """Why the domain could not be searched. Closed set, and each member is a
    different kind of problem for the reader:

    `not_configured` -- nothing is wired up for this family in this deployment
    (no MCP server built and no native tools), so no tool was ever offered to
    the Broker. An instrumentation gap: it will recur on every run until
    something is deployed, and no retry can help.

    `no_tools_resolved` -- the family IS configured but its server returned no
    usable tools. Transient or operational rather than structural;
    `registry.warm_mcp_clients()` retries this case before it is reported, so
    seeing it here means the retries were exhausted.

    `no_observable_in_scope` -- the tool exists and works, but this task's scope
    carries none of the observables it needs (`vt` cannot be queried without a
    hash, address, domain, or URL). A fact about the task, not the deployment,
    and the *correct* outcome rather than a defect -- it is recorded so the
    reader knows the domain was considered and ruled out on preconditions rather
    than forgotten.
    """
    detail: str = Field(
        default="",
        min_length=0,
        description=(
            "The refusal message produced at the point of refusal, verbatim. "
            "Code-assembled, never model-authored -- it is the same string the "
            "fetch side already recorded on `SubtaskResult.reason` or "
            "`StepOutcome.reason`, carried across rather than re-derived, so the "
            "artifact and the run log cannot disagree about why."
        ),
    )
    advised_by: list[ToolFamily] = Field(
        default_factory=list,
        description=(
            "Families whose subagents flagged this one as able to close a gap "
            "they hit, via `SubagentAnswer.gaps`. Evidence that the gap mattered "
            "to the investigation rather than being a domain nobody wanted: a "
            "`not_configured` edr that three siem steps all asked for is a "
            "different fact from one nothing missed. Empty when the family was "
            "planned or dispatched but no subagent asked for it."
        ),
    )
    served_domains: list[AnalystDomain] = Field(
        default_factory=list,
        description=(
            "The analysis domains this instrument would have supplied evidence "
            "for, from `subagent_analysts.routing.domains_for_family()` -- so "
            "`edr` names `endpoint`. A statement about what the missing "
            "instrument COULD have covered, not about what any query retrieved."
        ),
    )
    unanswered_domains: list[AnalystDomain] = Field(
        default_factory=list,
        description=(
            "The subset of `served_domains` that received no evidence from ANY "
            "source. This is the field that resolves what the gap actually cost, "
            "and the two ends of it mean opposite things:\n\n"
            "**Empty** -- something else covered every domain this instrument "
            "would have served, so the investigation is not missing an answer, "
            "only a second opinion. A missing `edr` whose `endpoint` domain was "
            "filled by SIEM process events lands here, which is the normal case "
            "in a SIEM-only deployment.\n\n"
            "**Non-empty** -- those domains have no evidence AND the instrument "
            "that would most directly have produced it was unavailable, so "
            "\"nothing happened\" and \"nobody could look\" are "
            "indistinguishable for them. That ambiguity is the finding. It is "
            "recorded rather than resolved because resolving it needs a fact "
            "nobody here has: whether the environment was quiet, or merely "
            "unobserved. A consumer must not read an empty narrative for one of "
            "these domains as evidence of absence."
        ),
    )


class RetrievalSummary(BaseModel):
    """What was looked for, and what the looking turned up.

    The fetch side, projected for the consumer of `HypothesisFindings`. Without
    it that contract carried three judgements and no account of the retrieval
    behind them, so an `inconclusive` was unreadable: a domain reports it both
    when the rows genuinely decide nothing and when nothing was ever retrieved
    for it, and only the fetch record tells those apart. Deciding which one
    happened is exactly the kind of call this contract exists to leave to the
    Analyst Agent -- so it has to be given the facts to make it.

    Deliberately not the whole `BrokerReport`: the consumer needs to know what
    was asked and what came back, not to be able to re-run the fetch. Costs,
    per-query records, raw `SubtaskResult`s and the classification stay in
    `report.json`, joined by `HypothesisFindings.task_id`.
    """

    dispatched: list[ToolFamily] = Field(
        default_factory=list,
        description="Families actually dispatched, observed at dispatch time.",
    )
    steps: list[StepSummary] = Field(default_factory=list)
    covered: list[CimCategory] = Field(
        default_factory=list,
        description=(
            "Categories at least one subagent asserted it retrieved data for, "
            "unioned across dispatches. Model-authored (see "
            "`SiemAssessment.covered`) -- a claim about coverage, not a count of "
            "rows."
        ),
    )
    not_covered: list[CimCategory] = Field(
        default_factory=list,
        description=(
            "Categories that were asked for and that NO dispatch retrieved. "
            "Disjoint from `covered` by construction, and that subtraction is the "
            "point: a plain union of every subagent's own `not_covered` is noise, "
            "because a step scoped to one category honestly reports the other "
            "three as not covered. On `cli-20260825T100434` -- four siem steps, "
            "one category each -- the union put all four categories in BOTH "
            "lists, which tells a consumer nothing. One dispatch retrieving a "
            "category settles it for the investigation."
        ),
    )
    gaps: list[DomainGap] = Field(
        default_factory=list,
        description=(
            "Domains that could not be searched at all, with the reason. See "
            "`DomainGap`: this is what tells a reader that a hypothesis was not "
            "searched in full because an instrument is missing, as distinct from "
            "a domain that was searched and had nothing to say. Empty means "
            "every family the investigation wanted was available -- NOT that "
            "every family was dispatched, which `dispatched` answers."
        ),
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
    evidence. An empty domain appears with an **empty narrative and no
    observations**, never silently omitted: "we looked and found nothing" and
    "we did not look" are different facts, and the consumer cannot recover the
    difference from a missing entry.

    It can no longer recover it from the entry itself either, which is what
    makes **`RetrievalSummary` the only signal separating those two facts.** An
    empty domain used to at least say `inconclusive`; with the verdict gone
    (2026-08-31) an empty finding is silent by construction, so `retrieval` is
    no longer a supplement to `findings` -- it is the whole answer to "was
    anything ever fetched for this domain?". A reader who takes it for a
    redundant projection of the fetch side and deletes it takes that
    distinction with it.
    """

    schema_version: int = 2
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
    retrieval: RetrievalSummary | None = Field(
        default=None,
        description=(
            "What the fetch side looked for and turned up. See `RetrievalSummary`: "
            "without it an `inconclusive` judgement cannot be told apart from a "
            "domain that was never given anything to read. Optional because "
            "artifacts written before this field exist and must still load."
        ),
    )

    def for_analyst(self, max_chars: int | None = None) -> AnalystPayload:
        """Project onto the wire: prose, observations and computed summaries.

        The record keeps `citations`, `exhibits` and `retrieval`; the message
        carries neither. See `AnalystPayload` for why the two differ and
        `DomainNarrative` for what the difference costs.

        A method rather than a free function so the projection lives on the shape
        it projects from -- a field added above is one edit away from this list,
        and the test that pins the field set fails until someone decides whether
        it crosses the boundary. That is the intended friction: `_as_judgement`
        once gained fields by being edited in sympathy with the model rather than
        by decision.

        `max_chars` caps the payload's JSON at the Analyst Agent's share of its
        window (B1). Narratives and observations always cross; what is left is
        split evenly across the domains holding summaries, each keeps its
        summaries in order (cited sets first) while its share lasts, and says how
        many it omitted. `None` sends every summary.
        """
        payload = AnalystPayload(
            task_id=self.task_id,
            run_id=self.run_id,
            hypothesis_id=self.hypothesis_id,
            hypothesis=self.hypothesis,
            findings=[
                DomainNarrative(
                    domain=f.domain,
                    narrative=f.narrative,
                    observations=list(f.observations),
                )
                for f in self.findings
            ],
        )
        with_summaries = [f for f in self.findings if f.summaries]
        if not with_summaries:
            return payload
        if max_chars is None:
            share = None
        else:
            spare = max_chars - len(payload.model_dump_json(indent=2))
            # -90 keeps room for the omission note itself.
            share = max(spare, 0) // len(with_summaries) - 90
        for narrative, f in zip(payload.findings, self.findings, strict=True):
            used = 0
            for summary in f.summaries:
                # +8: the indent, quotes and comma each list item costs on the wire.
                cost = len(json.dumps(summary)) + 8
                if share is not None and used + cost > share:
                    break
                narrative.summaries.append(summary)
                used += cost
            omitted = len(f.summaries) - len(narrative.summaries)
            if omitted:
                narrative.summaries.append(
                    f"… {omitted} set summaries omitted for size (full in findings.json)"
                )
        return payload

    # No token totals here, deliberately. Two such methods stood on this model
    # and both summed `self.verdicts` -- a field of `HypothesisAssessment`, not of
    # this one -- so either raised `AttributeError` on call. Copied across with
    # the rest of the shape and never exercised, because their only caller was
    # `main._print_assessment`, which has since been deleted along with the rest
    # of the hypothesis-shown path. Not repaired against `findings` either:
    # `DomainJudgement` drops the token counts on purpose (see its docstring), so
    # there is nothing on this side of the wire to sum. Token spend is our
    # telemetry, and it stays on `DomainFinding`.


class DomainNarrative(BaseModel):
    """One domain's account of its rows, stripped to what the consumer reads.

    The transmission shape. `DomainJudgement` is the record; this is the message.

    Mohammed's call on 2026-09-01, taken with the trade-off stated twice and
    accepted: the Analyst Agent is sent the prose and the observations, and
    nothing else. It is recorded here rather than argued again, and it is cheap
    to reverse -- add a field back and regenerate.

    Reversed in part on 2026-10-05 (B1): `summaries` now crosses too. On check-B1c
    the endpoint analyst was shown 4 rows whose parent `splunkd.exe` ran from
    the Administrator's Desktop, cited their set and
    described it as "system checks". Whatever a narrative drops is otherwise
    unrecoverable here. Raw rows still stay out. They are capped to the Analyst
    Agent's window by `for_analyst(max_chars)`, cited sets first; on 072fd610
    round 2 that kept T7's `processes#1` (powershell's parents: Desktop and
    Public `splunkd.exe`) and dropped 11 of its 12 other sets.

    **What this costs, so a future reader is not surprised by it.** Dropping
    `citations` removes the handle for checking a claim against the rows behind
    it; the ids still exist in `findings.json`, but a consumer holding only this
    message cannot resolve one. Dropping the envelope's `retrieval` removes the
    only signal separating "we looked and found nothing" from "we never looked":
    both arrive as an empty `narrative` with no `observations`, and on
    2026-09-01, with Splunk unreachable, that is exactly what two of three
    domains produced.

    Deliberately named for what it carries, unlike `DomainJudgement`, which was
    left misnamed in v2 to avoid churning the published schema and every test
    that names it.
    """

    domain: AnalystDomain
    narrative: str = Field(
        default="",
        description=(
            "Plain English: what these rows show, in order, naming the hosts, "
            "accounts, addresses and times. What happened -- NOT a reading of "
            "what it means."
        ),
    )
    observations: list[str] = Field(
        default_factory=list,
        description="One line per distinct thing the rows state.",
    )
    summaries: list[str] = Field(
        default_factory=list,
        description=(
            "One computed account per non-empty set routed to this domain, cited "
            "or not: totals, distinct counts, top and rarest values and the time "
            "range, calculated in code over every row. Not model-authored, so it "
            "holds what the narrative may have left out."
        ),
    )


class AnalystPayload(BaseModel):
    """What is actually sent to the Analyst Agent.

    `HypothesisFindings` is the durable record written to `findings.json`: it
    carries `citations`, `exhibits` and `retrieval`, and it is the audit trail.
    This is the projection of it that crosses the boundary.

    The reason the two differ is size, and it is not a small effect. On the
    2026-09-01 live run the record was 42,200 characters, of which **30,809 --
    73% -- were `exhibits`**: the 584 raw rows the tier exists to compress into
    prose. Sending those on undoes the compression that is this tier's whole
    justification for existing. The projection is 5,684 characters.

    Build it with `HypothesisFindings.for_analyst()`, never by hand: a field
    added to the record should not silently start crossing the boundary.
    """

    schema_version: int = Field(
        default=1,
        description=(
            "This contract's own version, counted independently of "
            "`HypothesisFindings.schema_version`. It is 1 because `AnalystPayload` "
            "is a NEW shape, not a successor: `findings.json` stays at v2 beside "
            "this file and is not superseded by it. The two land in the same run "
            "directory, so a reader seeing 2 in one and 1 in the other will "
            "reasonably wonder which is stale -- neither is. They are separate "
            "contracts on separate version lines, and they will drift apart the "
            "first time either shape changes without the other."
        ),
    )
    task_id: str
    run_id: str | None = None
    hypothesis_id: str
    hypothesis: str | None = None
    findings: list[DomainNarrative] = Field(default_factory=list)
    # NOTE: `RetrievalSummary.gaps` deliberately does NOT cross this boundary
    # yet -- whether it should is an open question for the producing team, see
    # docs/open-questions-for-team.md (2026-09-02). Until that is settled the
    # gap is on the record only, so `findings.json` carries it and this does not.


class AnalystPayloadBatch(BaseModel):
    """Every hypothesis from one task file, in one message.

    **The unit of handover is the task file, not the hypothesis.** A file arrives
    carrying several hypotheses about one alert -- "did this happen", "was it
    legitimate instead", "was it authorised" -- and the Analyst Agent has to weigh
    them against each other. Three separate `AnalystPayload` files leave that
    grouping implicit: the recipient gets three messages and has to infer, from
    nothing in the payloads themselves, that they belong to one question.

    That inference is exactly what this shape removes. It is also the answer to a
    question left open on 2026-09-02: `HypothesisFindings` has no case-level id,
    the received template has none either, and the working assumption had been
    that the grouping lived with the producer. It does not have to -- a batch
    carries it explicitly, without a `HypothesisFindings` version bump, because
    the grouping goes on the envelope rather than into any per-hypothesis shape.

    **`AnalystPayload` is unchanged and is the member type.** It stays at its own
    `schema_version` 1 and keeps its own `task_id`, `run_id` and `hypothesis_id`,
    so every member is still independently resolvable back to the run directory
    that produced it. This envelope adds grouping and nothing else -- it does not
    merge, summarise, or reconcile the members, because comparing hypotheses is
    the Analyst Agent's job and doing any of it here would be this tier forming
    the judgement it exists not to form.

    Written per task-file run, including a run of one, so the consumer has a
    single predictable input shape rather than a batch sometimes and a bare
    payload other times. The per-task `analyst-payload.json` files are still
    written beside each run's own report and evidence -- that is the per-run-dir
    record, joined by `run_id`, and this is the message.

    `batch_id` is OURS, not the producer's: the template carries no such field,
    so this is a name we mint for a grouping the file implies. Raised with the
    producing team rather than presented as settled -- if their generator has its
    own case or alert id, that is the value that belongs here.
    """

    schema_version: int = 1
    batch_id: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payloads: list[AnalystPayload] = Field(min_length=1)

    @model_validator(mode="after")
    def _hypotheses_are_distinct(self) -> Self:
        """One batch must not carry the same hypothesis twice.

        `TaskInputFile` already refuses a duplicate `hypothesis_id` at load, so
        this cannot fire from a well-formed task file. It is here because this
        shape can also be assembled by hand or by a future producer, and a
        duplicate would be unrecoverable in exactly the way it is on the input
        side: the id is the join key, so two members sharing one are
        indistinguishable to the recipient.
        """
        ids = [p.hypothesis_id for p in self.payloads]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"hypothesis_id must be unique within a batch, duplicated: {dupes}")
        return self
