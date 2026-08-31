"""Run the three domain analysts. **This is the production path.**

`gather()` is what `smartops.main` calls. It routes a `BrokerReport` to the three
domains, runs them concurrently, and assembles `HypothesisFindings` -- the
contract handed up to the Analyst Agent.

The analysts are **blind**: they never receive the hypothesis. An analyst told
"20 auth events means malicious" and then shown 20 auth events reports malicious,
which is the hypothesis talking rather than the evidence.

**They also no longer judge.** Until 2026-08-31 each one returned a `Disposition`
(benign/suspicious/malicious/inconclusive) about its own rows. That authority was
removed: deciding which rows matter is the judgement the Analyst Agent exists to
make, with sight of every domain and of the hypothesis, and a sub-analyst made it
blind, on one slice, with nothing able to check it. A `DomainFinding` now carries
a `narrative` -- what the rows say, in plain English -- and `observations`, one
checkable line each. Nothing here forms a verdict about anything.

**There is no combiner here, deliberately.** Deciding whether these findings
support or refute the hypothesis is the Analyst Agent's job, on the far side of
the `HypothesisFindings` contract. `analyze()` and `combine()` used to sit here
and roll three verdicts into one `HypothesisAssessment`; they were deleted once
nothing called them. See `contracts.reasoning.HypothesisFindings`.

The blind guarantee is structural, not disciplinary: `gather_finding(model,
scope, slice_)` and `build_facts_user_turn(scope, evidence_text)` have no
hypothesis parameter, so there is nothing to leak. `_invoke_with_one_reask` takes
an already-built prompt STRING for the same reason -- a shared helper that could
accept an `InvestigationContext` would downgrade the guarantee to a promise about
what callers pass. Keep it that way.

Two helpers here are shared with the hypothesis-shown arm in `shown.py`, which
`blind_compare` measures this path against: `_invoke_with_one_reask` (pack,
invoke, re-ask once) and `_apply_grounding` (the citation gate). Each is defined
once so a change cannot land on one arm and miss the other. `shown.py` still has
a `Stance` and a `confidence` to downgrade; this arm has neither, so the shared
gate is parameterised rather than branched -- see `_apply_grounding`.

Failure is contained per analyst: a call that errors or stays unparseable becomes
a finding with no observations whose narrative says why, so one domain never
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

from smartops.telemetry import analyst_span, record_analyst_finding

from .model import AnalystModel
from .packing import (
    _CONTEXT_WINDOW,
    _GENERATION_RESERVE,
    _PACK_TOKEN_BUDGET,
    _SAFETY_MARGIN,
    exhibits_for,
    pack_evidence,
)
from .parse import FindingParseError, parse_finding, split_reasoning
from .prompts import _NARRATIVE_ANSWER_BLOCK, build_facts_user_turn, facts_system_prompt
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
    trailing `CITATIONS:` line may still ground the finding as a whole, and
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

# `_PACK_TOKEN_BUDGET`, `_CONTEXT_WINDOW`, `_GENERATION_RESERVE` and
# `_SAFETY_MARGIN` are imported from `.packing` rather than restated here: this
# module used to carry its own `_PACK_TOKEN_BUDGET = 20_000` "kept equal to
# `packing.pack_evidence`'s default" by convention alone, which is exactly the
# kind of duplication that can silently diverge -- and `packing.py`'s own
# default was a bare `20_000` with no derivation behind it either, until a live
# Splunk run measured how wrong the estimate underneath it was (see
# `packing._CHARS_PER_TOKEN`). Importing these names means the warning below
# moves automatically if the derived budget, the context window, or either
# reserve ever do.

_DANGER_THRESHOLD = _CONTEXT_WINDOW - _GENERATION_RESERVE - _SAFETY_MARGIN
"""The real line a full PROMPT (system + user + evidence) must stay under.

`_PACK_TOKEN_BUDGET` bounds the EVIDENCE alone, so comparing the model's real,
full prompt count against it flagged every full pack as an estimator failure --
even a correct one, since the system prompt and generation reserve (both
already carved out of `_PACK_TOKEN_BUDGET`) are reason enough for the full
count to exceed the evidence-only budget on their own. This is the same
arithmetic restated the other way: subtracting the system-prompt and user-turn-
scaffold reserves from `prompt_tokens` before comparing to `_PACK_TOKEN_BUDGET`
is algebraically the window minus the generation reserve minus the safety
margin, which is what is computed directly here."""

@dataclass(frozen=True)
class _Attempt:
    """What one bounded analyst call produced: a parsed reply, or why not.

    Carries the token counts either way, because a reply that never parsed was
    still generated and still billed.

    `rationale` is the failure note, and keeps that name although the blind arm's
    prose field was renamed to `narrative` on 2026-08-31: `shown.py:364` reads
    `attempt.rationale` and builds an `AnalystVerdict`, which still has a
    `rationale`. One neutral field feeding two differently-named contract fields
    is the smaller evil; renaming it would edit the arm this rework must not
    touch.
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
    # `pack_evidence` chose a row cap from `estimate_tokens`, which is
    # `len // packing._CHARS_PER_TOKEN` and still an estimate even recalibrated.
    # The model reports the real count, so compare them: the ladder cannot be
    # re-run now (the call is spent), but an estimate that was low is worth a
    # line, because the alternative is finding out via a provider length
    # rejection that arrives as a generic model error -- or not finding out at
    # all, if the provider truncates the tail and the analyst writes a confident
    # account of evidence it was never shown.
    if prompt_tokens > _DANGER_THRESHOLD:
        # Compared against `_DANGER_THRESHOLD`, not `token_budget`: `token_budget`
        # bounds the evidence alone, while `prompt_tokens` is the full system+user
        # prompt Bedrock actually counted, so the two differ by design at a full
        # pack -- the system prompt and generation reserve are real tokens that
        # were never part of the evidence budget to begin with. What actually
        # matters is whether the WINDOW itself is close to full, which is the
        # exact 2026-08-30 network case -- 31,850 counted against a 32,768 window
        # left 918 tokens, under 3%, for the generation -- restated as a number
        # the log line itself can show rather than one a reader has to go compute.
        headroom = _CONTEXT_WINDOW - prompt_tokens
        logger.warning(
            "domain=%s | prompt counted %d tokens (evidence alone was packed to "
            "an estimated ~%d); only %d of the %d-token window (%.1f%%) is left "
            "for the model's %d-token generation reserve -- the closer this is "
            "to zero, the nearer the call came to failing outright",
            domain,
            prompt_tokens,
            token_budget,
            headroom,
            _CONTEXT_WINDOW,
            100 * headroom / _CONTEXT_WINDOW,
            _GENERATION_RESERVE,
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
    drop_log: str,
    downgrade_log: str,
    note: str,
    prose_field: str = "rationale",
    stance_field: str | None = None,
    decisive: Callable[[Any], bool] | None = None,
) -> Any:
    """The anti-hallucination gate, shared by both paths.

    - Drop any citation that does not resolve to a header id we actually emitted
      (the model can only legitimately cite what it was shown).
    - Check observation-level citations too, and count their valid ids toward
      grounding. Filtering only the trailing CITATIONS: line let a fabricated
      `[auth_events#7]` reach the operator, and -- the converse -- flagged a
      reply that had cited correctly inline but omitted the CITATIONS: line.
    - Freeze what each kept citation resolves to, so the gate's decision survives
      into the artifact instead of being reproducible only by re-running `route()`
      with identical ordering.
    - Mark a reply that asserted something and has NO citation left. What
      "marking" means is the one place the two arms now genuinely differ, and it
      is a parameter rather than a branch:

      **`shown.py` passes `stance_field` and `decisive`.** It still returns an
      `AnalystVerdict` with a `Stance` and a `confidence`, so a decisive claim
      with nothing behind it is downgraded to `inconclusive` with capped
      confidence. `inconclusive` is exempt, needing no citation.

      **The blind arm passes neither**, because since 2026-08-31 it has no
      verdict to downgrade and no confidence to cap. What it asserted is its
      observations, so that is the test, and the only consequence is the note:
      the narrative is KEPT and the note appended to it. Blanking the narrative
      was considered and rejected -- it is the audit record of what the model
      claimed, and destroying it destroys the only evidence that a fabrication
      happened. `observations: []`, `citations: []` and `exhibits: []` are what
      tell the consumer not to trust it.

    Do not "simplify" this by stripping the stance arm; `shown.py` is the harness
    whose measurements are the evidence the blind design rests on, and it must
    keep working.
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

    if stance_field is not None:
        assert decisive is not None, "a stance_field needs a decisive() to read it"
        current = getattr(reply, stance_field)
        ungrounded = decisive(current) and not citations
        log_args: tuple = (reply.domain, current)
    else:
        # BOTH operands are the PRE-filter values on purpose: a reply that cited
        # only invented ids has had every one of them dropped by now, and
        # `_resolve_observation_citations` may have dropped the observations that
        # carried them too, so testing only the survivors would let exactly the
        # fabrication case slip through silently. Reading the post-filter
        # `observations` here was the original defect -- an observation whose only
        # citation was invented is dropped first and then reads as "empty, not
        # ungrounded", so the note never landed on the one finding that most needs
        # it. A reply that asserted nothing and cited nothing -- the empty-slice
        # and failure findings -- is not ungrounded, it is empty, and gets no
        # note; both have empty pre-filter observations, so they stay unmarked.
        asserted = getattr(reply, observations_field) or reply.citations
        ungrounded = bool(asserted) and not citations
        log_args = (reply.domain,)

    if ungrounded:
        logger.warning(downgrade_log, *log_args)
        if stance_field is not None:
            updates[stance_field] = "inconclusive"
            updates["confidence"] = min(reply.confidence, 0.3)
        prose = getattr(reply, prose_field)
        updates[prose_field] = f"{prose} [{note}]".strip() if prose else note

    return reply.model_copy(update=updates)


# ---------------------------------------------------------------------------
# The blind analyst call and the artifact it feeds (see
# docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md).
#
# This said "not yet called from analyze() -- that wiring is the Aggregator
# cycle, a later plan", which was true when the blind tier landed dark beside the
# shown one and became actively misleading afterwards: `main` moved onto
# `gather()` and this is the ONLY path that runs. `analyze()` is gone.
# ---------------------------------------------------------------------------

_FINDING_REASK = (
    "\n\nYour previous reply did not end with the required block. "
    "Reply again, ending with exactly:\n" + _NARRATIVE_ANSWER_BLOCK
)
"""Built from `prompts._NARRATIVE_ANSWER_BLOCK`, not a second hand-written copy.

This is appended to the user turn (`model.invoke(system, user + reask)`), so it
is the LAST and most explicit instruction the model reads on a re-ask -- a
divergence here overrides the first-ask footer rather than merely duplicating
it. It used to be written out independently, in a different field set and order
from the footer's, and the two drifted: that is what cost the 2026-08-30 live
run its answer. Deriving it from the same constant the footer uses makes the two
incapable of saying different things; `test_analyst_prompts.py` pins that they
still agree on field set and order."""


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

    # Outside the span deliberately: no model call happens on this branch, so a
    # span here would report a zero-token, zero-latency "analyst call" that never
    # ran, which is exactly the never-attempted state the rest of this pipeline
    # works to keep distinguishable.
    if not slice_.has_evidence():
        # An EMPTY finding, not a sentence saying it is empty. The narrative is
        # the model's account of rows it read, and no model ran here -- writing
        # "no identity evidence was retrieved" into it would put words into a
        # translator's mouth exactly as the old `inconclusive` default put a
        # verdict there. `RetrievalSummary` on `HypothesisFindings` is what now
        # separates "we looked and found nothing" from "we did not look"; see
        # `contracts.reasoning.HypothesisFindings`, which records that this field
        # became load-bearing here.
        return DomainFinding(domain=domain)

    with analyst_span(domain):
        finding = _gather_finding_traced(model, scope, slice_, domain)
        record_analyst_finding(finding)
        return finding


def _gather_finding_traced(
    model: AnalystModel,
    scope: Scope,
    slice_: DomainSlice,
    domain: AnalystDomain,
) -> DomainFinding:
    """The body of `gather_finding`, split out so the span wraps exactly the work.

    A separate function rather than more indentation under the `with`: the two
    return paths below both need their finding stamped onto the span, and
    threading that through an inlined block means either duplicating the
    `record_analyst_finding` call or assigning to a variable declared before the
    context manager. Neither reads as well as a body that just returns.
    """
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
    # UNLIKE the empty-slice branch above, this one keeps its sentence. A model
    # ran, was billed, and failed; that is not a retrieval fact and
    # `RetrievalSummary` has nowhere to record it, so blanking the narrative here
    # would delete the only account of what went wrong. `observations` stays
    # empty, which is what says nothing was read.
    return DomainFinding(
        domain=domain,
        narrative=attempt.rationale or "",
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
    """Drop any citation that does not resolve, and mark what is left ungrounded.

    Mirrors `_finalize`'s grounding gate on the blind path. It used to say there
    was "no stance to downgrade here" and defer the equivalent gate to the
    Aggregator; that was true while a `DomainFinding` carried only observations,
    false while it carried a `disposition`, and is true again in a different
    sense now that the disposition is gone -- there is nothing to downgrade, but
    the gate still has work to do, and deferring it was always doubly wrong. The
    Aggregator is the Analyst Agent, which is not ours, and a component that
    never sees the evidence cannot check grounding anyway.

    What is left after a total citation failure is the note. The narrative is
    KEPT (see `_apply_grounding`): it is the record of what the model claimed,
    and it is `observations: []`/`citations: []`/`exhibits: []` beside it that
    tell the consumer the claim rests on nothing. No `stance_field` and no
    `decisive` are passed, because this arm has no verdict and no confidence.
    """
    return _apply_grounding(
        finding,
        valid_ids,
        prompt_tokens,
        generation_tokens,
        observations_field="observations",
        prose_field="narrative",
        drop_log="domain=%s | dropped %d invented citation(s) from a finding: %s",
        downgrade_log=(
            "domain=%s | finding has no citation that resolves; keeping the "
            "narrative and marking it ungrounded"
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

    # Observations whose every cited block is EMPTY. Warned about, not removed,
    # and the distinction is the point: an empty result set is legitimate
    # negative evidence -- "no failed logons in the window" is a true and useful
    # thing to report -- so penalising it would punish a correct account of an
    # absence. What it cannot support is a claim that something WAS observed, and
    # telling those two apart requires reading the claim against the rows, which
    # is defect (c) and is not decidable here. So this surfaces the case rather
    # than judging it; `Exhibit.row_count` carries it to the consumer, which now
    # has the rows and can.
    #
    # The test used to be `finding.disposition != "inconclusive"` -- "the analyst
    # committed to something". With the disposition gone, the same defect is
    # stated directly: this tier commits to something by writing an observation,
    # so an observation standing on nothing but zero-row blocks is the case.
    if finding.observations and exhibits and all(e.row_count == 0 for e in exhibits):
        logger.warning(
            "domain=%s | %d observation(s) rest entirely on cited block(s) with "
            "zero rows: %s",
            finding.domain,
            len(finding.observations),
            ", ".join(e.citation for e in exhibits),
        )

    return DomainJudgement(
        domain=finding.domain,
        narrative=finding.narrative,
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
    trace_sink: Callable[[list[DomainFinding]], None] | None = None,
) -> HypothesisFindings:
    """Run the three blind analysts and attach their findings to the hypothesis.

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
    the consumer can check a narrative against the rows it was written from.

    `hypothesis_id` defaults to the report's, which is the normal case; both it
    and `hypothesis` are accepted explicitly for a caller assessing a report
    against a hypothesis other than the one it was fetched for. The prose is
    attacker-influenceable and is only carried, never rendered here. Pass
    `run_id` whenever it is known -- see the field's own note on why this
    contract sets it here rather than at write time.

    **`trace_sink`** receives the raw `DomainFinding`s before projection, and is
    the only way to reach the model's `reasoning_trace`: `_as_judgement` drops it
    on the way to the wire, deliberately, so a caller that wants it for audit has
    to be handed it here or never see it. It WAS never seeing it -- the contract
    claimed the trace was "persisted for audit" while nothing persisted it, a
    claim that had been true of an older artifact format that dumped
    `DomainFinding` directly.

    A sink rather than a second return value: the wire artifact is what `gather`
    is *for*, and widening the return type would make every caller acknowledge
    audit data it does not want. A sink is also the shape that keeps the default
    behaviour -- discard -- explicit at the call site rather than implicit here.
    Exceptions from it are not caught: a caller that asked for its traces to be
    written and had that fail should hear about it.
    """
    routed = route(report, scope)
    slices = routed.slices()
    findings = await asyncio.gather(
        *(asyncio.to_thread(gather_finding, model, scope, slice_) for slice_ in slices)
    )
    # Before `_as_judgement` below drops `reasoning_trace`, which is the last
    # point at which anything can.
    if trace_sink is not None:
        trace_sink(list(findings))
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

    **This is now the only thing that separates "we looked and found nothing"
    from "we did not look."** It was a supplement while an empty domain came back
    as `inconclusive` with a sentence explaining itself; since 2026-08-31 an
    empty domain comes back as an empty narrative with no observations, and this
    summary carries the reason instead. See
    `contracts.reasoning.HypothesisFindings`.

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
