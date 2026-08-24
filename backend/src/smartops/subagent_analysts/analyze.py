"""Run the three domain analysts and combine their verdicts.

`run_one` is one analyst end to end: pack its evidence, build the prompt, invoke
the model, parse the verdict, with one bounded re-ask if the model's first reply
carried no parseable verdict block. `analyze` runs all three concurrently and a
thin `combine` rolls their stances into one `HypothesisAssessment`.

Failure is contained per analyst: a call that errors or stays unparseable becomes
an INCONCLUSIVE verdict that says why, so one domain never sinks the whole
assessment -- the same discipline the Broker applies to a failing subagent.
"""

from __future__ import annotations

import asyncio
import logging
import re

from contracts import (
    AnalystVerdict,
    BrokerReport,
    DomainFinding,
    HypothesisAssessment,
    InvestigationContext,
    Scope,
    Stance,
)

from .model import AnalystModel
from .packing import pack_evidence
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

_REASK = (
    "\n\nYour previous reply did not end with the required VERDICT block. "
    "Reply again, ending with exactly:\n"
    "VERDICT: supports | refutes | inconclusive\n"
    "CONFIDENCE: <0.0-1.0>\n"
    "RATIONALE: <one or two sentences>\n"
    "OBSERVATIONS:\n- <observation> [citation]\n"
    "CITATIONS: <comma-separated header ids>"
)


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

    system = system_prompt(domain)
    evidence_text, valid_ids, _ = pack_evidence(slice_)
    user = build_user_turn(context, scope, evidence_text)

    try:
        response = model.invoke(system, user)
    except Exception as exc:
        logger.warning("domain=%s | analyst model call failed", domain, exc_info=True)
        return AnalystVerdict(
            domain=domain,
            stance="inconclusive",
            confidence=0.0,
            rationale=f"{domain} analyst could not run: {type(exc).__name__}: {exc}",
        )

    prompt_tokens, generation_tokens = response.prompt_tokens, response.generation_tokens
    try:
        verdict = parse_verdict(response.generation, domain=domain)
        return _finalize(verdict, valid_ids, prompt_tokens, generation_tokens)
    except VerdictParseError:
        logger.info("domain=%s | first reply had no verdict block, re-asking once", domain)

    try:
        retry = model.invoke(system, user + _REASK)
        # Bill both calls: the failed first attempt was still generated and paid for.
        prompt_tokens += retry.prompt_tokens
        generation_tokens += retry.generation_tokens
        verdict = parse_verdict(retry.generation, domain=domain)
        return _finalize(verdict, valid_ids, prompt_tokens, generation_tokens)
    except VerdictParseError:
        logger.warning("domain=%s | re-ask still produced no parseable verdict", domain)
        reasoning, _ = split_reasoning(response.generation)
        return AnalystVerdict(
            domain=domain,
            stance="inconclusive",
            confidence=0.0,
            rationale=f"{domain} analyst produced no parseable verdict after a re-ask",
            reasoning_trace=reasoning,
            prompt_tokens=prompt_tokens,
            generation_tokens=generation_tokens,
        )
    except Exception as exc:
        logger.warning("domain=%s | re-ask call failed", domain, exc_info=True)
        return AnalystVerdict(
            domain=domain,
            stance="inconclusive",
            confidence=0.0,
            rationale=f"{domain} analyst re-ask failed: {type(exc).__name__}: {exc}",
            prompt_tokens=prompt_tokens,
            generation_tokens=generation_tokens,
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
    kept = [c for c in verdict.citations if c in valid_ids]
    dropped = [c for c in verdict.citations if c not in valid_ids]
    if dropped:
        logger.warning(
            "domain=%s | dropped %d invented citation(s): %s",
            verdict.domain,
            len(dropped),
            ", ".join(dropped),
        )

    # Observation-level citations are checked too, and their valid ids count
    # toward grounding. Filtering only the trailing CITATIONS: line let a
    # fabricated `[auth_events#7]` reach the operator and assessment.json, and
    # -- the converse -- downgraded a verdict that had cited correctly inline
    # but omitted the CITATIONS: line entirely.
    observations, inline_ids = _resolve_observation_citations(
        list(verdict.key_observations), valid_ids
    )
    kept = sorted(set(kept) | inline_ids)

    updates: dict = {
        "citations": kept,
        # Freeze what each kept citation resolves to. The gate already dropped
        # the fabrications; recording the survivors is what makes that decision
        # survive into assessment.json, instead of being reproducible only by
        # re-running route() with identical ordering.
        "citation_evidence": {c: list(valid_ids.get(c, [])) for c in kept},
        "key_observations": observations,
        "prompt_tokens": prompt_tokens,
        "generation_tokens": generation_tokens,
    }
    if verdict.stance in ("supports", "refutes") and not kept:
        logger.warning(
            "domain=%s | %s verdict has no resolvable citation; downgrading to inconclusive",
            verdict.domain,
            verdict.stance,
        )
        note = "ungrounded: no cited evidence resolved to the provided evidence"
        updates["stance"] = "inconclusive"
        updates["confidence"] = min(verdict.confidence, 0.3)
        updates["rationale"] = f"{verdict.rationale} [{note}]".strip() if verdict.rationale else note

    return verdict.model_copy(update=updates)


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

    system = facts_system_prompt(domain)
    evidence_text, valid_ids, _ = pack_evidence(slice_)
    user = build_facts_user_turn(scope, evidence_text)

    try:
        response = model.invoke(system, user)
    except Exception as exc:
        logger.warning("domain=%s | facts model call failed", domain, exc_info=True)
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"{domain} analyst could not run: {type(exc).__name__}: {exc}",
        )

    prompt_tokens, generation_tokens = response.prompt_tokens, response.generation_tokens
    try:
        finding = parse_finding(response.generation, domain=domain)
        return _finalize_finding(finding, valid_ids, prompt_tokens, generation_tokens)
    except FindingParseError:
        logger.info("domain=%s | first reply had no parseable finding, re-asking once", domain)

    try:
        retry = model.invoke(system, user + _FINDING_REASK)
        prompt_tokens += retry.prompt_tokens
        generation_tokens += retry.generation_tokens
        finding = parse_finding(retry.generation, domain=domain)
        return _finalize_finding(finding, valid_ids, prompt_tokens, generation_tokens)
    except FindingParseError:
        logger.warning("domain=%s | re-ask still produced no parseable finding", domain)
        reasoning, _ = split_reasoning(response.generation)
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"{domain} analyst produced no parseable finding after a re-ask",
            reasoning_trace=reasoning,
            prompt_tokens=prompt_tokens,
            generation_tokens=generation_tokens,
        )
    except Exception as exc:
        logger.warning("domain=%s | re-ask call failed", domain, exc_info=True)
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"{domain} analyst re-ask failed: {type(exc).__name__}: {exc}",
            prompt_tokens=prompt_tokens,
            generation_tokens=generation_tokens,
        )


def _finalize_finding(
    finding: DomainFinding,
    valid_ids: dict[str, list[str]],
    prompt_tokens: int,
    generation_tokens: int,
) -> DomainFinding:
    """Drop any citation that does not resolve to a real evidence header id.

    No stance to downgrade here -- that concept doesn't exist at this layer, so
    this is deliberately simpler than `_finalize`. The equivalent grounding gate
    for a decided stance reappears at the Aggregator, in a later cycle.
    """
    kept = [c for c in finding.citations if c in valid_ids]
    dropped = [c for c in finding.citations if c not in valid_ids]
    if dropped:
        logger.warning(
            "domain=%s | dropped %d invented citation(s) from a finding: %s",
            finding.domain,
            len(dropped),
            ", ".join(dropped),
        )
    observations, inline_ids = _resolve_observation_citations(
        list(finding.observations), valid_ids
    )
    return finding.model_copy(
        update={
            "citations": sorted(set(kept) | inline_ids),
            "observations": observations,
            "prompt_tokens": prompt_tokens,
            "generation_tokens": generation_tokens,
        }
    )
