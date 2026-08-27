"""Run the three domain analysts, on either of two paths.

Both paths pack a domain's evidence, build a prompt, invoke the model, parse the
reply, and re-ask once if the first reply carried no parseable block. That
machinery is `_invoke_with_one_reask`, and the grounding gate applied to what
comes back is `_apply_grounding`; each is defined once and used by both paths,
so a change to either cannot land on one path and miss the other. They differ in
what the analyst is shown and therefore in what it may conclude:

- **Hypothesis-shown** — `run_one` -> `AnalystVerdict` (a `Stance` on the
  hypothesis), rolled up by `analyze` + `combine` into a `HypothesisAssessment`.
- **Hypothesis-blind** — `gather_finding` -> `DomainFinding` (a `Disposition` on
  the evidence), assembled by `gather` into `HypothesisFindings`, the contract
  handed up to the Analyst Agent. There is no combiner on this path: deciding
  supports/refutes is the Analyst Agent's job, not this layer's.

The blind path's guarantee is structural rather than disciplinary --
`gather_finding` and `build_facts_user_turn` have no hypothesis parameter, so
there is nothing to leak.

Failure is contained per analyst on both paths: a call that errors or stays
unparseable becomes an `inconclusive` result that says why, so one domain never
sinks the whole run -- the same discipline the Broker applies to a failing
subagent.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from contracts import (
    AnalystVerdict,
    BrokerReport,
    CimCategory,
    DomainFinding,
    DomainJudgement,
    Exhibit,
    HypothesisAssessment,
    HypothesisFindings,
    InvestigationContext,
    RetrievalSummary,
    Scope,
    Stance,
    StepSummary,
)

from .model import AnalystModel
from .packing import exhibits_for, pack_evidence
from .parse import FindingParseError, VerdictParseError, parse_finding, parse_verdict, split_reasoning
from .prompts import build_facts_user_turn, build_user_turn, facts_system_prompt, system_prompt
from .routing import DomainSlice, route

logger = logging.getLogger(__name__)

_OBSERVATION_CITE_RE = re.compile(r"\[([A-Za-z_]+#\d+)\]")
"""A `[header_id]` citation embedded in an observation line.

Both prompt footers ask for one per observation (`prompts.py:65`, `:238`), and
`parse._parse_observations` keeps the line verbatim, brackets included.
"""


def _resolve_observation_citations(
    observations: list[str], valid_ids: dict[str, list[str]]
) -> tuple[list[str], set[str]]:
    """Drop observations whose citations are all invented; keep the valid ids.

    Returns `(surviving_observations, valid_ids_found_inline)`.

    An observation whose cited ids ALL fail to resolve is dropped outright
    rather than kept-and-flagged: it is supported only by a fabrication, it is
    exactly what the grounding gate exists to stop, and `main._print_assessment`
    plus `_persist_assessment` would otherwise make it the durable,
    operator-facing record. An observation with a mix keeps only the ids that
    resolve. An observation citing nothing at all is left untouched -- the
    trailing `CITATIONS:` line may still ground the verdict as a whole, and
    dropping uncited prose is a different (and unmade) decision.
    """
    kept: list[str] = []
    found: set[str] = set()
    for observation in observations:
        cited = set(_OBSERVATION_CITE_RE.findall(observation))
        if not cited:
            kept.append(observation)
            continue
        # `.keys()`, not the mapping: `valid_ids` carries each header id's
        # evidence ids now, and only the ids themselves are the validity test.
        resolving = cited & valid_ids.keys()
        if not resolving:
            logger.warning(
                "dropped an observation citing only unresolvable id(s): %s",
                ", ".join(sorted(cited)),
            )
            continue
        text = observation
        for invented in sorted(cited - resolving):
            text = text.replace(f"[{invented}]", "").replace("  ", " ").strip()
        kept.append(text)
        found |= resolving
    return kept, found

_PACK_TOKEN_BUDGET = 20_000
"""The budget `pack_evidence` packs to, restated here to compare against what the
model actually counted. Kept equal to `packing.pack_evidence`'s default; the
comparison is a check on the estimate, not a second source of truth for it."""

_REASK = (
    "\n\nYour previous reply did not end with the required VERDICT block. "
    "Reply again, ending with exactly:\n"
    "VERDICT: supports | refutes | inconclusive\n"
    "CONFIDENCE: <0.0-1.0>\n"
    "RATIONALE: <one or two sentences>\n"
    "OBSERVATIONS:\n- <observation> [citation]\n"
    "CITATIONS: <comma-separated header ids>"
)


@dataclass(frozen=True)
class _Attempt:
    """What one bounded analyst call produced: a parsed reply, or why not.

    Carries the token counts either way, because a reply that never parsed was
    still generated and still billed.
    """

    parsed: Any | None
    prompt_tokens: int
    generation_tokens: int
    rationale: str | None = None
    reasoning_trace: str | None = None


def _invoke_with_one_reask(
    model: AnalystModel,
    *,
    domain: str,
    system: str,
    user: str,
    reask: str,
    parse: Callable[..., Any],
    parse_error: type[Exception],
    call_label: str,
    noun: str,
    token_budget: int = _PACK_TOKEN_BUDGET,
) -> _Attempt:
    """Invoke one analyst, re-asking once if the reply carries no parseable block.

    Shared by both paths. It takes `user` **already built** rather than a context
    to build it from: the blind path's guarantee is that no hypothesis parameter
    exists anywhere on it, and a shared helper that could accept a context would
    turn that structural property into a promise about what callers pass. The
    prompt is assembled by each caller, from its own builder, and only the
    finished string crosses this boundary.

    Returns a `_Attempt` rather than a result object because the two paths return
    different contracts with different fields; building them is the caller's job.
    """
    try:
        response = model.invoke(system, user)
    except Exception as exc:
        logger.warning("domain=%s | %s model call failed", domain, call_label, exc_info=True)
        return _Attempt(
            None, 0, 0, f"{domain} analyst could not run: {type(exc).__name__}: {exc}"
        )

    prompt_tokens, generation_tokens = response.prompt_tokens, response.generation_tokens
    # `pack_evidence` chose a row cap from `estimate_tokens`, which is len//4 and
    # optimistic on evidence rows. The model reports the real count, so compare
    # them: the ladder cannot be re-run now (the call is spent), but an estimate
    # that was low is worth a line, because the alternative is finding out via a
    # provider length rejection that arrives as a generic model error -- or not
    # finding out at all, if the provider truncates the tail and the analyst
    # judges confidently over evidence it was never shown.
    if prompt_tokens > token_budget:
        logger.warning(
            "domain=%s | packed to fit ~%d tokens but the model counted %d; the "
            "chars-per-token estimate ran low for this evidence",
            domain,
            token_budget,
            prompt_tokens,
        )

    try:
        return _Attempt(parse(response.generation, domain=domain), prompt_tokens, generation_tokens)
    except parse_error:
        logger.info("domain=%s | first reply had no parseable %s, re-asking once", domain, noun)

    try:
        retry = model.invoke(system, user + reask)
        # Bill both calls: the failed first attempt was still generated and paid for.
        prompt_tokens += retry.prompt_tokens
        generation_tokens += retry.generation_tokens
        return _Attempt(parse(retry.generation, domain=domain), prompt_tokens, generation_tokens)
    except parse_error:
        logger.warning("domain=%s | re-ask still produced no parseable %s", domain, noun)
        # The FIRST reply's trace, not the retry's: it is the one that shows what
        # the analyst was thinking when it read the evidence.
        reasoning, _ = split_reasoning(response.generation)
        return _Attempt(
            None,
            prompt_tokens,
            generation_tokens,
            f"{domain} analyst produced no parseable {noun} after a re-ask",
            reasoning,
        )
    except Exception as exc:
        logger.warning("domain=%s | re-ask call failed", domain, exc_info=True)
        return _Attempt(
            None,
            prompt_tokens,
            generation_tokens,
            f"{domain} analyst re-ask failed: {type(exc).__name__}: {exc}",
        )


def _apply_grounding(
    reply: Any,
    valid_ids: dict[str, list[str]],
    prompt_tokens: int,
    generation_tokens: int,
    *,
    observations_field: str,
    stance_field: str,
    decisive: Callable[[Any], bool],
    drop_log: str,
    downgrade_log: str,
    note: str,
) -> Any:
    """The anti-hallucination gate, shared by both paths.

    - Drop any citation that does not resolve to a header id we actually emitted
      (the model can only legitimately cite what it was shown).
    - Check observation-level citations too, and count their valid ids toward
      grounding. Filtering only the trailing CITATIONS: line let a fabricated
      `[auth_events#7]` reach the operator, and -- the converse -- downgraded a
      reply that had cited correctly inline but omitted the CITATIONS: line.
    - Freeze what each kept citation resolves to, so the gate's decision survives
      into the artifact instead of being reproducible only by re-running `route()`
      with identical ordering.
    - Downgrade a decisive reply whose citations ALL fail to resolve, capping
      confidence. A decisive claim with nothing behind it is not one we let stand.

    The two paths differ in exactly three ways, and all three are parameters
    rather than branches: which field holds the observations, what counts as
    decisive, and what the appended note says. `inconclusive` is exempt on both,
    needing no citation.
    """
    kept = [c for c in reply.citations if c in valid_ids]
    dropped = [c for c in reply.citations if c not in valid_ids]
    if dropped:
        logger.warning(drop_log, reply.domain, len(dropped), ", ".join(dropped))

    observations, inline_ids = _resolve_observation_citations(
        list(getattr(reply, observations_field)), valid_ids
    )
    citations = sorted(set(kept) | inline_ids)

    updates: dict = {
        "citations": citations,
        observations_field: observations,
        "citation_evidence": {c: list(valid_ids.get(c, ())) for c in citations},
        "prompt_tokens": prompt_tokens,
        "generation_tokens": generation_tokens,
    }

    current = getattr(reply, stance_field)
    if decisive(current) and not citations:
        logger.warning(downgrade_log, reply.domain, current)
        updates[stance_field] = "inconclusive"
        updates["confidence"] = min(reply.confidence, 0.3)
        updates["rationale"] = f"{reply.rationale} [{note}]".strip() if reply.rationale else note

    return reply.model_copy(update=updates)


def run_one(
    model: AnalystModel,
    context: InvestigationContext,
    scope: Scope,
    slice_: DomainSlice,
) -> AnalystVerdict:
    """One domain analyst, invoked synchronously (boto3 is sync)."""
    domain = slice_.domain

    # No evidence routed to this domain -> the answer is inconclusive by
    # definition. Return it directly rather than spending a model call on a prompt
    # whose only honest reply is "nothing to analyze" (and which tempts the model
    # to invent a citation for absent evidence).
    if not slice_.has_evidence():
        return AnalystVerdict(
            domain=domain,
            stance="inconclusive",
            confidence=0.0,
            rationale=f"no {domain} evidence was retrieved, so the hypothesis cannot be assessed from this domain",
        )

    evidence_text, valid_ids, _, _ = pack_evidence(slice_)
    attempt = _invoke_with_one_reask(
        model,
        domain=domain,
        system=system_prompt(domain),
        user=build_user_turn(context, scope, evidence_text),
        reask=_REASK,
        parse=parse_verdict,
        parse_error=VerdictParseError,
        call_label="analyst",
        noun="verdict",
    )
    if attempt.parsed is not None:
        return _finalize(
            attempt.parsed, valid_ids, attempt.prompt_tokens, attempt.generation_tokens
        )
    return AnalystVerdict(
        domain=domain,
        stance="inconclusive",
        confidence=0.0,
        rationale=attempt.rationale,
        reasoning_trace=attempt.reasoning_trace,
        prompt_tokens=attempt.prompt_tokens,
        generation_tokens=attempt.generation_tokens,
    )


def _finalize(
    verdict: AnalystVerdict,
    valid_ids: dict[str, list[str]],
    prompt_tokens: int,
    generation_tokens: int,
) -> AnalystVerdict:
    """Anti-hallucination gate + token stamping applied to a parsed verdict.

    - Drop any citation that does not resolve to a header id we actually emitted
      (the model can only legitimately cite what it was shown).
    - Grounding downgrade: a `supports`/`refutes` verdict whose citations ALL fail
      to resolve is treated as ungrounded and downgraded to `inconclusive` with
      capped confidence -- a decisive claim with no evidence behind it is not one we
      let stand. `inconclusive` needs no citation.
    """
    return _apply_grounding(
        verdict,
        valid_ids,
        prompt_tokens,
        generation_tokens,
        observations_field="key_observations",
        stance_field="stance",
        # A `Stance` is supports/refutes/inconclusive, so this is the decisive
        # pair spelled out rather than `!= "inconclusive"`. Kept explicit because
        # the blind path's `Disposition` has four members and needs the other
        # test; see `_finalize_finding`.
        decisive=lambda stance: stance in ("supports", "refutes"),
        drop_log="domain=%s | dropped %d invented citation(s): %s",
        downgrade_log=(
            "domain=%s | %s verdict has no resolvable citation; "
            "downgrading to inconclusive"
        ),
        note="ungrounded: no cited evidence resolved to the provided evidence",
    )


def combine(verdicts: list[AnalystVerdict]) -> tuple[Stance, float]:
    """Roll per-domain verdicts into one stance + confidence.

    Thin by design (the full Aggregator is later work): confidence-weighted vote
    of the non-inconclusive verdicts. Ties and an all-inconclusive panel resolve
    to `inconclusive`. Confidence is the winning side's share of the decided
    weight, or the mean confidence when nothing was decided.
    """
    if not verdicts:
        return "inconclusive", 0.0

    support_confs = [v.confidence for v in verdicts if v.stance == "supports"]
    refute_confs = [v.confidence for v in verdicts if v.stance == "refutes"]
    support, refute = sum(support_confs), sum(refute_confs)

    if support == refute:  # includes the all-inconclusive case (both 0)
        mean = sum(v.confidence for v in verdicts) / len(verdicts)
        return "inconclusive", round(mean, 3)

    # Confidence = the winning side's MEAN verdict confidence, scaled by its margin
    # over the losing side. Unopposed, the margin is 1 and confidence is just the
    # mean of the deciding domains (two 0.88 supports -> ~0.88, NOT 1.0). Opposition
    # lowers it toward inconclusive. This replaces "winning share of decided weight",
    # which pinned an unopposed verdict to 1.0 no matter how unsure each domain was.
    winning_confs, win, lose = (
        (support_confs, support, refute)
        if support > refute
        else (refute_confs, refute, support)
    )
    stance: Stance = "supports" if support > refute else "refutes"
    margin = (win - lose) / (win + lose)
    confidence = (sum(winning_confs) / len(winning_confs)) * margin
    return stance, round(confidence, 3)


async def analyze(
    report: BrokerReport,
    context: InvestigationContext,
    scope: Scope,
    model: AnalystModel,
) -> HypothesisAssessment:
    """Route the report, run the three analysts concurrently, and combine."""
    routed = route(report, scope)
    verdicts = await asyncio.gather(
        *(asyncio.to_thread(run_one, model, context, scope, slice_) for slice_ in routed.slices())
    )
    verdicts = list(verdicts)
    overall_stance, confidence = combine(verdicts)
    return HypothesisAssessment(
        task_id=report.task_id,
        hypothesis_id=report.hypothesis_id,
        overall_stance=overall_stance,
        confidence=confidence,
        verdicts=verdicts,
    )


# ---------------------------------------------------------------------------
# Tier 1 of the hypothesis-blind redesign (see
# docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md).
# Mirrors run_one()'s shape but never receives the hypothesis. Not yet called
# from analyze() -- that wiring is the Aggregator cycle, a later plan.
# ---------------------------------------------------------------------------

_FINDING_REASK = (
    "\n\nYour previous reply did not end with the required block. "
    "Reply again, ending with exactly:\n"
    "OBSERVATIONS:\n- <observation> [header_id]\n"
    "CONFIDENCE: <0.0-1.0>\n"
    "RATIONALE: <one or two sentences>\n"
    "CITATIONS: <comma-separated header ids>"
)


def gather_finding(
    model: AnalystModel,
    scope: Scope,
    slice_: DomainSlice,
) -> DomainFinding:
    """One hypothesis-blind domain analyst, invoked synchronously.

    Same empty-slice short-circuit, one-bounded-re-ask, and citation-validation
    discipline as `run_one`, but this call never receives the hypothesis: its
    system/user prompts come from `facts_system_prompt`/`build_facts_user_turn`,
    which have no hypothesis parameter at all.
    """
    domain = slice_.domain

    if not slice_.has_evidence():
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"no {domain} evidence was retrieved",
        )

    evidence_text, valid_ids, _, _ = pack_evidence(slice_)
    attempt = _invoke_with_one_reask(
        model,
        domain=domain,
        system=facts_system_prompt(domain),
        # `build_facts_user_turn` takes no context, and the finished string is all
        # that reaches the shared helper -- there is no parameter to leak through.
        user=build_facts_user_turn(scope, evidence_text),
        reask=_FINDING_REASK,
        parse=parse_finding,
        parse_error=FindingParseError,
        call_label="facts",
        noun="finding",
    )
    if attempt.parsed is not None:
        return _finalize_finding(
            attempt.parsed, valid_ids, attempt.prompt_tokens, attempt.generation_tokens
        )
    return DomainFinding(
        domain=domain,
        confidence=0.0,
        rationale=attempt.rationale,
        reasoning_trace=attempt.reasoning_trace,
        prompt_tokens=attempt.prompt_tokens,
        generation_tokens=attempt.generation_tokens,
    )


def _finalize_finding(
    finding: DomainFinding,
    valid_ids: dict[str, list[str]],
    prompt_tokens: int,
    generation_tokens: int,
) -> DomainFinding:
    """Drop any citation that does not resolve, and downgrade what is left ungrounded.

    Mirrors `_finalize`'s grounding gate on the blind path. This used to say
    there was "no stance to downgrade here" and defer the equivalent gate to the
    Aggregator -- true while a `DomainFinding` carried only observations, and
    false since it gained a `disposition`. A confident `malicious` resting on
    nothing is exactly the claim `_finalize` refuses to let stand for a verdict,
    and deferring it was doubly wrong: the Aggregator is the Analyst Agent, which
    is not ours, and a component that never sees evidence cannot check grounding
    anyway.

    `inconclusive` is exempt, needing no citation, same as in `_finalize`.
    """
    return _apply_grounding(
        finding,
        valid_ids,
        prompt_tokens,
        generation_tokens,
        observations_field="observations",
        stance_field="disposition",
        # NOT the decisive pair: a `Disposition` is benign/suspicious/malicious/
        # inconclusive, and "benign, and I am 95% sure" rests on evidence exactly
        # as much as "malicious" does -- an uncitable benign call is the one most
        # likely to close an investigation.
        decisive=lambda disposition: disposition != "inconclusive",
        drop_log="domain=%s | dropped %d invented citation(s) from a finding: %s",
        downgrade_log=(
            "domain=%s | disposition '%s' had no citation that resolves; "
            "downgrading to inconclusive"
        ),
        note="downgraded: no cited evidence resolved",
    )


def _as_judgement(finding: DomainFinding, slice_: DomainSlice) -> DomainJudgement:
    """Project one finding onto the wire, attaching the evidence it cited.

    The projection is where `reasoning_trace` and the token counts stop: they are
    our audit record, not the Analyst Agent's input. See `DomainJudgement`.
    """
    exhibits = [
        Exhibit(
            citation=block.header_id,
            evidence_ids=list(block.evidence_ids),
            row_count=block.row_count,
            rows=block.text,
            # Carried here, not inside `rows`: the query is kept out of what the
            # blind analyst reads (it leaks the hypothesis -- see
            # `formatting.format_result_set`) and put back for the Analyst Agent,
            # which is not blind and cannot weigh a rows=0 exhibit without
            # knowing what was asked.
            query=block.query,
        )
        # Driven by `finding.citations`, which `_finalize_finding` has already
        # stripped of anything unresolvable -- so an exhibit cannot exist for a
        # citation the grounding gate refused.
        for block in exhibits_for(slice_, finding.citations)
    ]

    # A decisive disposition whose every cited block is EMPTY. Warned about, not
    # downgraded, and the distinction is the point: an empty result set is
    # legitimate negative evidence -- "no failed logons in the window" genuinely
    # supports `benign` -- so penalising it would punish correct reasoning about
    # an absence. What it cannot support is a claim that something was observed,
    # and telling those two apart requires reading the claim against the rows,
    # which is defect (c) and is not decidable here. So this surfaces the case
    # rather than judging it; `Exhibit.row_count` carries it to the consumer,
    # which now has the rows and can.
    if (
        finding.disposition != "inconclusive"
        and exhibits
        and all(e.row_count == 0 for e in exhibits)
    ):
        logger.warning(
            "domain=%s | disposition '%s' at confidence %.2f rests entirely on "
            "cited block(s) with zero rows: %s",
            finding.domain,
            finding.disposition,
            finding.confidence,
            ", ".join(e.citation for e in exhibits),
        )

    return DomainJudgement(
        domain=finding.domain,
        disposition=finding.disposition,
        confidence=finding.confidence,
        rationale=finding.rationale,
        observations=list(finding.observations),
        citations=list(finding.citations),
        exhibits=exhibits,
    )


async def gather(
    report: BrokerReport,
    scope: Scope,
    model: AnalystModel,
    *,
    run_id: str | None = None,
    hypothesis_id: str | None = None,
    hypothesis: str | None = None,
) -> HypothesisFindings:
    """Run the three blind analysts and attach their judgements to the hypothesis.

    The blind-path counterpart to `analyze()`, and the producer of the contract
    handed up to the Analyst Agent. Same routing, same concurrency, same
    per-analyst failure containment -- the differences are the two that matter:

    - **No `InvestigationContext`.** `gather_finding` takes `(model, scope,
      slice_)` and `build_facts_user_turn` takes `(scope, evidence_text)`, so
      the hypothesis cannot reach an analyst even by mistake. It is not passed
      in and then withheld; there is no parameter to pass it through.
    - **No `combine()`.** Nothing here decides whether the findings support or
      refute anything. That is the Analyst Agent's job, and `HypothesisFindings`
      carries no field for it.

    Each finding is projected to a `DomainJudgement` before it leaves: the audit
    fields stay here, and the rows behind each kept citation travel with it, so
    the consumer can check a judgement without holding the evidence store.

    `hypothesis_id` defaults to the report's, which is the normal case; both it
    and `hypothesis` are accepted explicitly for a caller assessing a report
    against a hypothesis other than the one it was fetched for. The prose is
    attacker-influenceable and is only carried, never rendered here. Pass
    `run_id` whenever it is known -- see the field's own note on why this
    contract sets it here rather than at write time.
    """
    routed = route(report, scope)
    slices = routed.slices()
    findings = await asyncio.gather(
        *(asyncio.to_thread(gather_finding, model, scope, slice_) for slice_ in slices)
    )
    return HypothesisFindings(
        task_id=report.task_id,
        run_id=run_id,
        hypothesis_id=hypothesis_id or report.hypothesis_id,
        hypothesis=hypothesis,
        # `slices` is always the three domains in a fixed order and
        # `gather_finding` returns a finding for an empty slice rather than None,
        # so all three are always present, which the contract requires. Zipped
        # strictly: a finding paired with the wrong slice would attach another
        # domain's rows to this domain's judgement.
        findings=[
            _as_judgement(f, s) for f, s in zip(findings, slices, strict=True)
        ],
        retrieval=_retrieval_summary(report),
    )


def _retrieval_summary(report: BrokerReport) -> RetrievalSummary:
    """Project the fetch side of the report for the Analyst Agent.

    Code-assembled from what the Broker recorded, so nothing here is a fresh
    judgement -- `completed`/`evaluated` come from `broker.evaluate_step()` and
    `covered`/`not_covered` from each subagent's own `Assessment`.

    `covered` is the union across dispatches; `not_covered` is the union MINUS
    that, so the two are disjoint. Carrying both unions was the first cut and
    real data killed it: on `cli-20260825T100434` four siem steps each scoped to
    one category honestly reported the other three as not covered, so all four
    categories landed in both lists and the field said nothing. One dispatch
    retrieving a category settles it for the investigation.
    """
    covered: list[CimCategory] = []
    unmet: list[CimCategory] = []
    for result in report.results:
        assessment = result.assessment
        # `VtAssessment` has no CIM buckets -- a reputation lookup is not
        # categorised that way (see `SiemAssessment.covered`), so `getattr`
        # rather than a type test per family.
        for source, target in (("covered", covered), ("not_covered", unmet)):
            for category in getattr(assessment, source, ()) or ():
                if category not in target:
                    target.append(category)
    not_covered = [category for category in unmet if category not in covered]

    return RetrievalSummary(
        dispatched=list(report.dispatched),
        steps=[
            StepSummary(
                step_id=outcome.step.step_id,
                family=outcome.step.family,
                objective=outcome.step.objective,
                completed=outcome.completed,
                evaluated=outcome.evaluated,
                confirmed_empty=outcome.confirmed_empty,
                rows_retrieved=outcome.rows_retrieved,
            )
            for outcome in report.step_outcomes
        ],
        covered=covered,
        not_covered=not_covered,
    )
