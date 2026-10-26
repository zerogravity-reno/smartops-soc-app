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
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, get_args

from contracts import (
    AnalystVerdict,
    BrokerReport,
    CimCategory,
    DomainFinding,
    DomainGap,
    DomainRecord,
    Exhibit,
    HypothesisAssessment,
    HypothesisFindings,
    InvestigationContext,
    RetrievalSummary,
    Scope,
    Stance,
    StepSummary,
    SubtaskStatus,
    ToolFamily,
    mission_family,
)

# `family_is_configured` distinguishes a family with nothing wired up from one
# whose server merely returned nothing -- see `_domain_gaps`. Imported from the
# broker rather than reimplemented: it is the same predicate
# `available_broker_tools()` gates on, and the two must agree about what
# "configured" means or a gap would be classified differently from the way it
# was caused. No cycle -- `smartops.broker` imports nothing from this package.
from smartops.broker import _finding_counts, family_is_configured
from smartops.domains import DOMAINS
from smartops.telemetry import analyst_span, record_analyst_finding

from .model import AnalystModel, AnalystResponse
from smartops.tools.native.virustotal import is_private_ip
from smartops.tools.native.decoder import commands_in, encoded_in, hashes_in, private_addresses_in

from contracts.reasoning import (
    ADDRESSES_FOOTER,
    COMMANDS_FOOTER,
    ENCODED_FOOTER,
    HASHES_FOOTER,
    NAMES_FOOTER,
    NO_ROWS_FOOTER,
)

from .formatting import NO_TIME_MARKER, _middle, _truncate, name_expansions

ENCODED_LINE_CAP = 8
COMMAND_LINE_CAP = 8
COMMAND_CHAR_CAP = 400
NO_ROWS_LINE_CAP = 3
HASH_LINE_CAP = 8
ADDRESS_LINE_CAP = 8
from .packing import (
    _CONTEXT_WINDOW,
    _GENERATION_RESERVE,
    _PACK_TOKEN_BUDGET,
    _SAFETY_MARGIN,
    blocks,
    exhibits_for,
    pack_evidence,
)
from .parse import FindingParseError, parse_finding, split_reasoning
from .prompts import (
    _ANSWER_RULES,
    _NARRATIVE_ANSWER_BLOCK,
    build_facts_user_turn,
    facts_system_prompt,
)
from .routing import DomainSlice, domains_for_family, route

logger = logging.getLogger(__name__)

_OBSERVATION_CITE_RE = re.compile(r"\[?\b([A-Za-z_]+#\d+)\]?")
"""A header id cited in an observation line, bracketed or not.

Both prompt footers ask for `[header_id]` (`prompts.py:65`, `:238`), and
`parse._parse_observations` keeps the line verbatim, brackets included. **The
brackets are not load-bearing and must not be required.** This pattern demanded
them until 2026-09-01, and the live run `cli-20260901T075503` showed what that
costs: the model wrote its ids in prose that run -- `(dns_resolutions#11 and
#34)`, `Processes#16 and #18` -- so `findall` matched nothing, every observation
took `_resolve_observation_citations`'s "cited nothing at all" branch, and the
per-claim gate validated NOTHING across all three domains. Two endpoint
observations claiming 1,573,654 and 240,882 events crossed the boundary citing
sets that never resolved.

A bare `category#N` is safe to match. Every id carries a category prefix -- the
prompt bans writing `#1` alone precisely because a bare number cannot be
resolved -- and nothing else in this prose has the `word#digits` shape.

Case is normalised at the point of use: the same run wrote `Processes#16`, and
`valid_ids` keys are lowercase, so a capitalised id would have missed even
bracketed.
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
        # Lowercased because `valid_ids` keys are: a reply writing `Processes#16`
        # is citing `processes#16` and must be held to it, not waved through.
        cited = {c.lower() for c in _OBSERVATION_CITE_RE.findall(observation)}
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
            # Bracketed or bare, and any case -- `.replace(f"[{invented}]", ...)`
            # silently no-opped on both `Processes#16` and an unbracketed id,
            # leaving the invented reference sitting in the kept line.
            text = re.sub(rf"\[?{re.escape(invented)}\]?", "", text, flags=re.IGNORECASE)
            text = text.replace("  ", " ").strip()
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


_SENTENCE = re.compile(r"(?<=[.!?])\s+")
# The first copy of a looped sentence follows its block header ("NARRATIVE: Host …").
_BLOCK_HEADER = re.compile(r"^\s*(?:</think>)?\s*[A-Z]+:\s*")
# ponytail: shorter sentences repeat legitimately ("- none" under two blocks), so
# only longer ones are collapsed; a looping short phrase still gets through.
_REPEAT_MIN_CHARS = 40


def _collapse_repeats(text: str) -> tuple[str, Counter]:
    """`text` with each long sentence kept only where it first appears, plus the repeats.

    a818a3fd T4 endpoint (B15, B-1): both replies wrote "Host … ran processes under
    user …, started by OneDrive.exe; one command line, starting powershell.exe,
    repeated." until the token limit, with the prompt rule against it in place.
    Lines keep their order, so block headers and their contents stay put.
    """
    seen: set[str] = set()
    repeats: Counter = Counter()
    lines = []
    for line in text.split("\n"):
        kept = []
        for sentence in _SENTENCE.split(line):
            key = " ".join(_BLOCK_HEADER.sub("", sentence).split())
            if len(key) >= _REPEAT_MIN_CHARS and key in seen:
                repeats[key] += 1
                continue
            seen.add(key)
            kept.append(sentence)
        if kept:
            lines.append(" ".join(kept))
    return "\n".join(lines), repeats


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

    def parse_whole(reply: AnalystResponse) -> Any:
        # A reply cut off at `max_gen_len` parses as if whole: c7dbf51d's T1 ran
        # one observation into ", , , , had no matching events" until the limit and
        # shipped 2.7k characters of it. Cut off means re-ask, never parse.
        text, repeats = _collapse_repeats(reply.generation)
        if repeats:
            logger.warning("domain=%s | dropped %d repeated sentence(s) from the reply", domain, sum(repeats.values()))
        if reply.stop_reason == "length":
            # Name the loop, not just the limit: "keep it short" did not stop it (B-1).
            looped = ""
            if repeats:
                sentence, n = repeats.most_common(1)[0]
                looped = f' You wrote "{sentence}" {n + 1} times; write each sentence once.'
            raise parse_error(
                "your reply hit the token limit and was cut off. Keep it short: "
                "list a set of empty results once, and do not repeat citations." + looped
            )
        return parse(text, domain=domain)

    def salvage(reply: AnalystResponse) -> tuple[Any, str]:
        # The finished lines of a cut-off reply: drop the line the limit cut through.
        head, _, tail = _collapse_repeats(reply.generation)[0].rstrip().rpartition("\n")
        return parse(head, domain=domain), tail

    try:
        return _Attempt(parse_whole(response), prompt_tokens, generation_tokens)
    except parse_error as exc:
        logger.info(
            "domain=%s | first reply had no parseable %s (%s), re-asking once",
            domain,
            noun,
            exc,
        )
        # The re-ask names WHAT broke, not just what the block should look like.
        # `parse_finding` now raises for five distinct reasons -- no narrative, a
        # placeholder observation, observations citing nothing, an unanchored
        # narrative paragraph, no answer block -- and a fixed "did not end with the
        # required block" tells the model none of them. Each message already says
        # which rule broke and shows the offending text; putting it LAST, after the
        # rules and before the block, makes it the most specific instruction the
        # model reads. Applies to both arms: `shown.py`'s `_REASK` gets the same
        # treatment because the helper is shared.
        reask = f"{reask}\n\nWhat was wrong with your previous reply: {exc}"

    try:
        retry = model.invoke(system, user + reask)
        # Bill both calls: the failed first attempt was still generated and paid for.
        prompt_tokens += retry.prompt_tokens
        generation_tokens += retry.generation_tokens
        try:
            return _Attempt(parse_whole(retry), prompt_tokens, generation_tokens)
        except parse_error:
            if retry.stop_reason != "length":
                raise
            # Cut off twice (N2, 78cd60ec T1 endpoint): keep what was finished and
            # drop the line the limit cut through, rather than lose the domain. The
            # first reply too, when it was cut off: its loop may have ended sooner (B-1).
            for label, reply in (("re-ask", retry), ("first", response)):
                if reply.stop_reason != "length":
                    continue
                try:
                    salvaged, tail = salvage(reply)
                except parse_error:
                    continue
                logger.warning(
                    "domain=%s | re-ask also hit the token limit; kept the finished %s "
                    "of the %s reply and dropped its cut-off last line (%d chars): %r",
                    domain, noun, label, len(tail), tail[:300],
                )
                return _Attempt(salvaged, prompt_tokens, generation_tokens)
            raise
    except parse_error as exc:
        # The reason, not just the fact: b3aa0dd2 lost endpoint twice and the log could not say why.
        logger.warning("domain=%s | re-ask still produced no parseable %s: %s", domain, noun, exc)
        # What the replies actually said (B15): 874ab334 lost endpoint three times on
        # "no NARRATIVE block" with both calls at the token limit, and nothing kept
        # the answer, so whether it looped, reordered or never closed its thinking
        # could not be told.
        for label, reply in (("first", response), ("re-ask", retry)):
            _, answer = split_reasoning(reply.generation)
            logger.warning(
                "domain=%s | %s reply: stop_reason=%s generation_tokens=%d answer_chars=%d head=%r tail=%r",
                domain, label, reply.stop_reason, reply.generation_tokens, len(answer), answer[:300], answer[-300:],
            )
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
    "\n\nYour previous reply was not accepted. Reply again, obeying these rules and "
    "ending with exactly the block below.\n\n"
    + _ANSWER_RULES
    + "\n\n"
    + _NARRATIVE_ANSWER_BLOCK
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
            attempt.parsed,
            valid_ids,
            attempt.prompt_tokens,
            attempt.generation_tokens,
            slice_,
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


# Digits that are part of a citation, not a claim. `_OBSERVATION_CITE_RE` above
# matches a full `category#N`; this also strips the BARE `#N` continuations the
# model writes when it runs ids together (`[uncategorised#2, #4, ... #23]`, on
# the 2026-09-02 authorization run). Without it the gate reads `23` as a figure
# the observation asserts, and reports it unsupported -- a false positive drawn
# from punctuation.
_CITATION_DIGITS_RE = re.compile(r"[A-Za-z_]*#\d+")

# Times, stripped before figures are read. Every false positive in a trial run
# of this gate over the nine recorded findings was a fragment of one: `15` and
# `35` out of `15:35`, `02` out of `+02:00`, `11` and `19` out of `11:00-19:00`.
# Order matters -- the full ISO form first, so its date is consumed whole rather
# than leaving `2018` and `08` behind.
_MONTHS = (
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?"
    r"|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
)

_TIME_TOKEN_RE = re.compile(
    # ISO, longest first so its date is consumed whole rather than leaving 2018
    # and 08 behind.
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"
    r"|\d{4}-\d{2}-\d{2}"
    # Prose dates. The model keeps writing "August 20, 2018" despite the rule to
    # copy times verbatim, and a DATE IS NOT A COUNT: reading 20 and 2018 as
    # figures the observation asserts made every dated line unsupported on the
    # 2026-09-05 re-measure, which emptied all three domains. Whether the model
    # obeys the verbatim rule is a separate question from whether this gate may
    # treat a calendar date as a claim about the rows. It may not.
    rf"|(?:{_MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+\d{{4}})?"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\.?(?:,?\s+\d{{4}})?"
    r"|\b(?:19|20)\d{2}\b"
    r"|\b\d{1,2}(?:st|nd|rd|th)\b"
    r"|[+-]\d{2}:\d{2}"
    r"|\d{1,2}:\d{2}(?::\d{2})?",
    re.IGNORECASE,
)

# What counts as a figure the observation is asserting. Two digits or more:
# single digits are too common in prose ("3 hosts") to check usefully, and a
# fabricated count that matters has never been one digit.
_FIGURE_RE = re.compile(r"(?<![\w.-])(\d{2,})(?![\w.-])")

# Whether an observation states a time at all. Deliberately the clock form
# rather than the date: a set can legitimately be described as covering a day
# named in the scope, but a clock time can only come from a row.
_TIME_CLAIM_RE = re.compile(r"\d{1,2}:\d{2}")


# A protocol is a closed set of names, so like a figure it can be checked against
# the rows: 20592fea's network replay said "used UDP port 5353" over rows carrying
# no protocol, read off the port (B11).
_PROTOCOL_RE = re.compile(r"\b(tcp|udp|icmp)\b", re.I)


def _unsupported_protocols(text: str, shown: str) -> list[str]:
    """Protocol names `text` states that `shown` never prints."""
    printed = {p.lower() for p in _PROTOCOL_RE.findall(shown)}
    return sorted({p.lower() for p in _PROTOCOL_RE.findall(text)} - printed)


def _figures(text: str) -> set[str]:
    """Multi-digit figures an observation asserts, less its citations and times."""
    stripped = _TIME_TOKEN_RE.sub(" ", _CITATION_DIGITS_RE.sub(" ", text))
    # Only thousands separators: stripping every comma fused "4720,4722,4724" into
    # one figure no row holds, and dropped three true observations (25965109).
    return set(_FIGURE_RE.findall(re.sub(r"(?<=\d),(?=\d{3}\b)", "", stripped)))


def _drop_unsupported_figures(
    observations: list[str], slice_: DomainSlice, domain: str
) -> list[str]:
    """Drop observations asserting a number, or a time, their own rows do not carry.

    The citation gate above checks that an id RESOLVES. This checks that what the
    observation says about the rows behind that id is actually in them, which is
    the failure the resolving-id check cannot see: on the 2026-09-02
    authorization run the endpoint finding's lead observation read "Host BSTOLL-L
    ran 124 processes under user bstoll between 11:04 and 17:17, with 18 distinct
    images and 46 repeated command lines [processes#2]" -- a real id, a resolving
    citation, and 124/18/46 are the three figures in the endpoint prompt's own
    worked example. `processes#2` holds 100 rows totalling 654 events, carries no
    timestamp at all, and contains none of those numbers.

    `formatting.summarise_rows` is what makes this checkable rather than merely
    strict: the true counts, distinct counts and time range of the WHOLE set are
    now rendered into the block the analyst read, so a figure absent from that
    text was not in front of the model in any form.

    Two rules, both keyed to the sets the observation itself cites:

    - **Figures.** A multi-digit number appearing nowhere in those blocks is
      unsupported. Citation digits and timestamps are stripped first; commas are
      normalised, so `88,851` is checked against `88851`.
    - **Times.** An observation stating a clock time whose cited blocks all
      report `NO_TIME_MARKER` has invented it. This is the `processes#2` failure
      exactly, and it is checked separately because a time range is not a figure.

    An observation citing nothing is left alone, matching
    `_resolve_observation_citations`: dropping uncited prose is a different
    decision, and this gate should not make it by a side door.

    Blind arm only. `shown.py` shares `_apply_grounding` but not this -- its
    verdicts are measured against the blind ones by `blind_compare`, and gating
    one arm's output and not the other's would change what that measures.
    """
    if not observations:
        return observations

    kept: list[str] = []
    for observation in observations:
        cited = sorted({c.lower() for c in _OBSERVATION_CITE_RE.findall(observation)})
        if not cited:
            # Dropped, where `_resolve_observation_citations` above leaves it
            # alone. That function's docstring calls dropping uncited prose "a
            # different (and unmade) decision" -- this is where it is made, and
            # the measurement that made it: 4 of the 9 observations in the
            # 2026-09-02 consent endpoint finding cited nothing, and one of them
            # put "240,882 total events" on the wire resting on no set at all. An
            # uncited line is a claim nothing can check, which is exactly what
            # this gate drops everywhere else.
            #
            # Here rather than in the parser because the parser cannot tell an
            # uncited observation from an un-bulleted prose line swept into the
            # block; raising there over the latter costs a re-ask and can cost the
            # domain. `parse._check_observations` still raises when NO observation
            # cites anything, which is unambiguous.
            logger.warning(
                "domain=%s | dropped an observation citing no evidence: %s",
                domain,
                observation[:120],
            )
            continue

        blocks = exhibits_for(slice_, cited)
        if not blocks:
            kept.append(observation)
            continue
        # Tokenised on BOTH sides, then compared as sets. A raw substring test
        # (`f not in haystack`) was the first shape of this and it silently
        # passed any figure that occurs INSIDE a longer number: `18` is "found"
        # in `count=2018`, in `1080`, in an IP octet. That is not hypothetical --
        # `18` is one of the three fabricated figures in the 2026-09-02 defect
        # this gate exists to catch (124 / 18 / 46), and it was never caught,
        # because `processes#2` happens to contain a longer number containing it.
        #
        # The failure was invisible for a second reason worth recording: every
        # hand-verification of this gate checked the observations it DROPPED and
        # none of the ones it KEPT, so false negatives were never in view.
        #
        # `_figures` on both sides also makes the two symmetric -- times and
        # citation digits are stripped from the evidence exactly as they are from
        # the claim, so a timestamp in the rows cannot "support" a count. The
        # residue is that a count equal to a year (`2018` events) is stripped
        # from both and therefore unchecked; that is a narrow, deliberate hole,
        # and it fails open rather than dropping a sound line.
        asserted = _figures(observation)
        cited_text = " ".join(b.text for b in blocks)
        supported_by_rows = _figures(cited_text)
        unsupported = sorted(asserted - supported_by_rows) + _unsupported_protocols(observation, cited_text)
        if unsupported:
            # Both halves, deliberately. The unsupported figures say WHY the line
            # went; the supported ones say how much of it was sound, which is the
            # only way a reader can tell an invented line from a mostly-right one
            # this gate took whole. Dropping whole is the decision (a line is not
            # rewritten to remove a clause -- that puts words in the analyst's
            # mouth, which is the failure the `inconclusive` default already
            # taught this package), so the log is where the salvage lives.
            logger.warning(
                "domain=%s | dropped an observation asserting figure(s) absent from "
                "the rows it cites (%s): unsupported=%s supported=%s",
                domain,
                ", ".join(cited),
                ", ".join(unsupported),
                ", ".join(sorted(asserted - set(unsupported))) or "none",
            )
            continue

        if _TIME_CLAIM_RE.search(_CITATION_DIGITS_RE.sub(" ", observation)) and all(
            NO_TIME_MARKER in b.text for b in blocks
        ):
            logger.warning(
                "domain=%s | dropped an observation stating a time for set(s) whose "
                "rows carry none: %s",
                domain,
                ", ".join(cited),
            )
            continue

        kept.append(observation)
    return kept


def _finalize_finding(
    finding: DomainFinding,
    valid_ids: dict[str, list[str]],
    prompt_tokens: int,
    generation_tokens: int,
    slice_: DomainSlice,
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
    grounded = _apply_grounding(
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
    # Second gate, and a different question. `_apply_grounding` asks whether the
    # cited id exists; this asks whether the rows behind it say what the
    # observation claims they say. Run after, so it only ever sees observations
    # whose citations already resolve.
    survivors = _drop_unsupported_figures(
        # Identical lines once: 148b0e69's T1 carried one observation eight times.
        list(dict.fromkeys(grounded.observations)), slice_, grounded.domain
    )
    # The narrative keeps every sentence but those asserting a figure or time the
    # code-computed summaries do not print; the rest is the record of what the
    # model claimed, and each dropped sentence is logged whole.
    narrative = _drop_unsupported_sentences(grounded.narrative, slice_, grounded.domain)
    if len(survivors) == len(grounded.observations) and narrative == grounded.narrative:
        return grounded
    return grounded.model_copy(update={"observations": survivors, "narrative": narrative})


def _drop_unsupported_sentences(narrative: str, slice_: DomainSlice, domain: str) -> str:
    """The narrative less each sentence stating a figure or a clock time that
    appears nowhere in the evidence the analyst read.

    The prompt asks for no figures; c7dbf51d's narratives carried them anyway,
    and T5's contradicted itself ("four times", then "11 under SYSTEM" where no
    block prints 11). The same rule as `_drop_unsupported_figures`, over every
    block rather than the cited ones, since narrative sentences cite nothing.
    Summaries alone were tried and dropped true sentences naming event codes.

    ponytail: spelled-out counts ("twice", "four times") pass, and so does a
    figure that happens to occur elsewhere in the rows; a word-number list if
    the first keeps turning up.
    """
    shown = " ".join(b.text for b in blocks(slice_))
    shown_figures = _figures(shown)
    parts = re.split(r"(?<=[.!?])(\s+)", narrative)
    kept: list[str] = []
    for sentence, gap in zip(parts[::2], [*parts[1::2], ""]):
        bare = _CITATION_DIGITS_RE.sub(" ", sentence)
        unsupported = sorted(_figures(sentence) - shown_figures) + [
            t for t in _TIME_CLAIM_RE.findall(bare) if t not in shown
        ] + _unsupported_protocols(sentence, shown)
        if unsupported:
            logger.warning(
                "domain=%s | dropped a narrative sentence asserting %s, which no "
                "computed summary prints: %s", domain, ", ".join(unsupported), sentence,
            )
            continue
        kept.append(sentence + gap)
    return narrative if len(kept) * 2 >= len(parts) + 1 else "".join(kept).rstrip()


def _as_record(finding: DomainFinding, slice_: DomainSlice, scope: Scope | None = None) -> DomainRecord:
    """Project one finding onto the wire, attaching the evidence it cited.

    The projection is where `reasoning_trace` and the token counts stop: they are
    our audit record, not the Analyst Agent's input. See `DomainRecord`.
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
    # Beside real rows, empty exhibits are noise: T1 on c7dbf51d cited 26 zero-row
    # sets and each crossed to the Analyst (F8). The no-rows footer below names
    # them instead. Kept whole when every exhibit is empty -- that IS the negative
    # evidence. `citations` is untouched, so the verdict gate sees the same ids.
    if any(e.row_count for e in exhibits):
        exhibits = [e for e in exhibits if e.row_count]

    # Code-written lines go in `facts`, not the narrative (B14): as narrative footers
    # they were 62-73% of 874ab334's narratives, and since narratives always cross,
    # every observation was cut. `pack_for_analyst` trims facts by priority instead.
    facts: list[str] = []
    # A name in the narrative can stand for several files (B1c).
    sets = [*slice_.siem_sets, *(("uncategorised", rs) for rs in slice_.untagged_sets)]
    names = name_expansions(finding.narrative, sets)
    if names:
        facts += [NAMES_FOOTER, *names]
    # Each encoded command these rows hold, with what it decodes to (B10). Facts
    # only -- what a parent path means is the Analyst's call.
    tagged = encoded_in(row for _, rs in sets for row in rs.rows)
    if tagged:
        # Capped (B10c: 39 lines/11.3k chars crowded every summary out on dce405e5),
        # rarest parent first: the parent behind the fewest distinct commands. By
        # event count instead, one-off Ansible winrshost wrappers outranked the
        # Desktop splunkd.exe's single command and pushed it past the cap.
        spread = Counter(p for e in tagged.values() for p in e["parents"])
        ranked = sorted(tagged.items(), key=lambda kv: (min((spread[p] for p in kv[1]["parents"]), default=math.inf), kv[1]["events"]))
        facts.append(ENCODED_FOOTER)
        facts += [
            f"~ encoded command {sig}: {e['events']} events"
            + (", parent " + ", ".join(f"{_middle(p)}={n}" for p, n in sorted(e["parents"].items())) if e["parents"] else "")
            + f"; decodes to: {_truncate(e['plain'], COMMAND_CHAR_CAP)}"
            for sig, e in ranked[:ENCODED_LINE_CAP]
        ]
        if len(ranked) > ENCODED_LINE_CAP:
            facts.append(f"~ … {len(ranked) - ENCODED_LINE_CAP} more encoded commands not shown (rows in report.json)")
    # And the plain ones: interpreter/LOLBin command lines, rarest first, capped.
    # The download on 148b0e69 sat in four tasks' rows and reached no narrative.
    commands = list(commands_in(row for _, rs in sets for row in rs.rows).items())
    if commands:
        facts.append(COMMANDS_FOOTER)
        facts += [f"~ {n} events: {_truncate(cmd, COMMAND_CHAR_CAP)}" for cmd, n in commands[:COMMAND_LINE_CAP]]
        if len(commands) > COMMAND_LINE_CAP:
            facts.append(f"~ … {len(commands) - COMMAND_LINE_CAP} more command lines not shown (rows in report.json)")
    values = [e.value.lower() for e in scope.entities] if scope else []
    # Each file's SHA256, the scope's own files first (B22): OneDrive.exe's hash sat in
    # c90ca5f9's rows and never reached the Analyst, so no task asked VirusTotal.
    hashes = sorted(hashes_in(row for _, rs in sets for row in rs.rows).items(),
                    key=lambda kv: not any(v in kv[0][0].lower() or v == kv[0][1].lower() for v in values))
    if hashes:
        facts.append(HASHES_FOOTER)
        facts += [f"~ {_middle(file) if file != '-' else '(file not named)'}: SHA256 {sha}, {n} events"
                  for (file, sha), n in hashes[:HASH_LINE_CAP]]
        if len(hashes) > HASH_LINE_CAP:
            facts.append(f"~ … {len(hashes) - HASH_LINE_CAP} more hashes not shown (rows in report.json)")
    # Stated by code, the scope's own addresses first (B21): c90ca5f9 called
    # 192.168.40.211 "external" once VirusTotal stopped looking it up (B18).
    scoped = [e.value for e in scope.entities if e.kind == "ip" and is_private_ip(e.value)] if scope else []
    seen = private_addresses_in(row for _, rs in sets for row in rs.rows)
    addresses = [*dict.fromkeys(scoped), *(a for a in seen if a not in scoped)]
    if addresses:
        facts.append(ADDRESSES_FOOTER)
        facts += [f"~ {a}: private address, not internet-routable" + (f", {seen[a]} events" if a in seen else ", in this task's scope")
                  for a in addresses[:ADDRESS_LINE_CAP]]
        if len(addresses) > ADDRESS_LINE_CAP:
            facts.append(f"~ … {len(addresses) - ADDRESS_LINE_CAP} more private addresses not shown (rows in report.json)")
    # Searches that came back empty: a count, then the few naming this task's own
    # entities first. On 5aae1a35 T1's search for PID 220's creation was empty and
    # uncited, so the Analyst never read that its own question went unanswered;
    # listing every one instead was 26 lines in 874ab334 L2 and 47 in L3.
    empty = [rs.query for _, rs in sets if rs.row_count == 0 and rs.query]
    if empty:
        empty.sort(key=lambda q: not any(v in q.lower() for v in values))
        facts.append(NO_ROWS_FOOTER)
        facts.append(f"~ {len(empty)} search{'es' if len(empty) != 1 else ''} returned no rows, including:")
        facts += [f"~ {_truncate(q, COMMAND_CHAR_CAP)}" for q in empty[:NO_ROWS_LINE_CAP]]

    return DomainRecord(
        domain=finding.domain,
        narrative=finding.narrative,
        observations=list(finding.observations),
        citations=list(finding.citations),
        facts=facts,
        exhibits=exhibits,
        # Every routed set, cited or not: a narrative that drops a set's rare rows
        # otherwise leaves the Analyst Agent no way to recover them (B1). Cited sets
        # first, so `for_analyst`'s size cap drops uncited ones first.
        summaries=[
            b.summary
            for b in sorted(blocks(slice_), key=lambda b: b.header_id not in finding.citations)
            if b.summary
        ],
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

    Each finding is projected to a `DomainRecord` before it leaves: the audit
    fields stay here, and the rows behind each kept citation travel with it, so
    the consumer can check a narrative against the rows it was written from.

    `hypothesis_id` defaults to the report's, which is the normal case; both it
    and `hypothesis` are accepted explicitly for a caller assessing a report
    against a hypothesis other than the one it was fetched for. The prose is
    attacker-influenceable and is only carried, never rendered here. Pass
    `run_id` whenever it is known -- see the field's own note on why this
    contract sets it here rather than at write time.

    **`trace_sink`** receives the raw `DomainFinding`s before projection, and is
    the only way to reach the model's `reasoning_trace`: `_as_record` drops it
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
    # Before `_as_record` below drops `reasoning_trace`, which is the last
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
            _as_record(f, s, scope)
            for f, s in zip(findings, slices, strict=True)
        ],
        retrieval=_retrieval_summary(report, scope, slices),
    )


def _domain_gaps(
    report: BrokerReport, scope: Scope, slices: list[DomainSlice]
) -> list[DomainGap]:
    """Families the investigation could not search, and why.

    **Classified structurally, never by reading the refusal text.** The `reason`
    strings are carried into `DomainGap.detail` verbatim, but which of the three
    reasons applies is decided from facts: whether the family has anything wired
    up (`family_is_configured`), and whether the scope carries an observable it
    requires (`DOMAINS[...].required_kinds`). Matching on message text would
    make an error-message edit silently re-classify a gap.

    Two ways a family reaches this list, and both were observed on
    `botsv3-coinhive-*` (2026-09-02):

    * **Planned but never dispatched.** The Broker authored an
      `edr_host_processes` step while `investigate_edr` was withheld from it --
      `available_broker_tools()` only offers configured families -- so no
      dispatch, no `SubtaskResult`, and the step sits in `step_outcomes` with
      `evaluated=False`. Nothing else in the report says why.
    * **Dispatched and rejected outright.** `vt` was dispatched for a task whose
      scope was `user` + `host`, and `domain_runner`'s entity precondition
      refused it before any tool call. A family every one of whose results is
      `rejected` retrieved nothing at all, which is a gap however honest the
      refusal was.

    A family that returned `no_data` is deliberately NOT a gap: it was searched
    and had nothing, which is exactly the case `covered`/`confirmed_empty`
    already speak to.

    **What the gap cost is answered from `slices`, not from the fetch side.**
    Those are the routed slices the domain analysts actually read, so
    "did anything else cover this domain?" is decided by the same evidence the
    narrative was written from rather than by a second, parallel judgement. A
    missing `edr` whose `endpoint` slice is full of SIEM process events is a gap
    with nothing unanswered -- the substitution worked -- while one whose
    `endpoint` slice is empty leaves "nothing happened" and "nobody could look"
    indistinguishable, which is the ambiguity `unanswered_domains` records.
    """
    gaps: list[DomainGap] = []
    kinds = scope.kinds()
    has_evidence = {s.domain: s.has_evidence() for s in slices}

    # Which families did any subagent ask for? `SubagentAnswer.gaps` was
    # advisory-only and read by nothing but a log line and a print; this is where
    # it finally crosses the boundary.
    advisers: dict[ToolFamily, list[ToolFamily]] = {}
    for result in report.results:
        source = mission_family(result.task_id)
        for wanted in result.gaps:
            if source is not None and source not in advisers.setdefault(wanted, []):
                advisers[wanted].append(source)

    planned = {outcome.step.family for outcome in report.step_outcomes}
    considered = planned | set(report.dispatched) | set(advisers)

    for family in sorted(considered):
        results = [r for r in report.results if mission_family(r.task_id) == family]
        if results and any(r.status != SubtaskStatus.REJECTED for r in results):
            continue  # it ran; whatever it found, it was not a gap

        # Order matters, and it is not arbitrary: a family can satisfy more than
        # one of these at once, and the *binding* reason is the one that would
        # still hold if the others were fixed.
        #
        # `not_configured` is checked first for that reason. On the
        # `botsv3-coinhive-authorization` run, `ndr` was both unconfigured
        # (`{"disabled": true}`) and unsupported by the scope (`user` + `host`,
        # where ndr needs an ip/domain/url). Reporting the scope was actively
        # misleading -- it implies that a task carrying an IP would have got an
        # answer, when no ndr instrument exists to answer with. Fix the scope and
        # nothing changes; deploy an ndr and the scope question becomes real.
        required = DOMAINS[family].required_kinds
        if not family_is_configured(family):
            reason = "not_configured"
        elif required is not None and not (required & kinds):
            reason = "no_observable_in_scope"
        else:
            reason = "no_tools_resolved"

        # The message from wherever the refusal was actually recorded, so the
        # artifact quotes the run rather than paraphrasing it.
        detail = next(
            (r.reason for r in results if r.reason),
            next(
                (
                    o.reason
                    for o in report.step_outcomes
                    if o.step.family == family and o.reason
                ),
                "",
            ),
        )
        served = list(domains_for_family(family))
        gaps.append(
            DomainGap(
                family=family,
                reason=reason,
                detail=detail or "",
                advised_by=advisers.get(family, []),
                served_domains=served,
                # `has_evidence.get(d, False)` -- a domain absent from `slices`
                # has certainly not been covered, so treat it as unanswered
                # rather than quietly dropping it from the caveat.
                unanswered_domains=[d for d in served if not has_evidence.get(d, False)],
            )
        )
    return gaps


def _retrieval_summary(
    report: BrokerReport, scope: Scope, slices: list[DomainSlice]
) -> RetrievalSummary:
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
        # Rows code projected into a category settle it, whatever the model's own
        # assessment says: a818a3fd T1 printed "not covered: script_blocks" beside
        # two script_blocks rows the endpoint narrative cites (B-6).
        for name, rows in _finding_counts(result.findings):
            if rows and name in get_args(CimCategory) and name not in covered:
                covered.append(name)
    not_covered = [category for category in unmet if category not in covered]

    return RetrievalSummary(
        gaps=_domain_gaps(report, scope, slices),
        unanswerable=list(report.plan.unanswerable) if report.plan else [],
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
                proven_empty=dict(outcome.proven_empty),
            )
            for outcome in report.step_outcomes
        ],
        covered=covered,
        not_covered=not_covered,
    )
