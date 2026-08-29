"""Split the model's reasoning from its answer and parse the verdict block.

The model is prompted with a seeded `<think>` tag, so its `generation` is
`…reasoning… </think> …VERDICT block…`. `split_reasoning` separates the two;
`parse_verdict` reads the labelled block into an `AnalystVerdict`.

Parsing is deliberately lenient about surrounding prose (an 8B model will not
always stop cleanly after the block) but strict about the one thing that must be
present: a recognisable stance. A generation with no stance raises
`VerdictParseError`, which `analyze` turns into one bounded re-ask.
"""

from __future__ import annotations

import logging
import re

from contracts import (
    AnalystDomain,
    Disposition,
    DomainFinding,
)

logger = logging.getLogger(__name__)

_THINK_CLOSE = "</think>"

# `CONFIDENCE` and its value can be separated by markdown emphasis the 8B model
# adds (`**CONFIDENCE:** 0.7`), so allow non-digit noise between them -- but
# `[^\n\d]` rather than `\D`, so that noise cannot cross a newline. `\D*` used
# to walk straight past a valueless `CONFIDENCE: unclear` into the next digit
# anywhere later in the text, including inside a citation like
# `auth_events#1`, manufacturing confidence=1.0 from a reply that gave none.
_CONFIDENCE_RE = re.compile(r"CONFIDENCE[^\n\d]*([0-9]*\.?[0-9]+)", re.IGNORECASE)
# Every label the prompts emit: `_VERDICT_FOOTER` for a hypothesis-shown verdict,
# `_FINDING_FOOTER` for a blind finding. Closed on purpose: the terminator used to
# be a generic uppercase run, `[A-Z][A-Z ]+:`, which under IGNORECASE matches any
# ordinary prose line ending in a colon -- so a rationale reading "Note the
# following: ..." was cut at "Note the following", and an un-bulleted observation
# line containing a colon ended the OBSERVATIONS capture and took every later
# observation with it. Enumerating the labels is what makes a colon in prose just
# a colon. Closed also means it must be kept in step: a label added to a footer
# and not added here silently stops terminating.
_LABEL = r"(?:VERDICT|DISPOSITION|CONFIDENCE|RATIONALE|OBSERVATIONS|CITATIONS)"

# What may sit between the newline and the label word. The model emphasises
# (`**OBSERVATIONS:**`) and, on a real blind draw, writes the label as a markdown
# heading (`### CONFIDENCE: 0.85`) -- which used to neither terminate the
# OBSERVATIONS block nor register as a field, so the observation list ended,
# literally, with the label line.
#
# `#` belongs HERE and not in `_strip_md`: header ids are `auth_events#1`, so
# stripping `#` globally would destroy every citation in the file. Same reasoning
# that keeps underscores out of `_strip_md`. Safe in this position because the
# match is anchored to a newline and must still be followed by a known label and
# a colon -- which is a heading label, not prose.
_LABEL_PREFIX = r"[*_`#\s]*"

# A field stops at the next LABEL line.
_RATIONALE_RE = re.compile(
    rf"RATIONALE\s*:\s*(.+?)(?:\n{_LABEL_PREFIX}{_LABEL}\s*:|\Z)", re.IGNORECASE | re.DOTALL
)
_CITATIONS_RE = re.compile(r"CITATIONS\s*:\s*(.+)", re.IGNORECASE)
# `parse_finding`'s own OBSERVATIONS pattern, module-level like every other
# pattern here rather than recompiled on every call. Deliberately not
# `_OBSERVATIONS_RE`: that one assumes OBSERVATIONS immediately precedes
# CITATIONS, but a hypothesis-blind finding's OBSERVATIONS may come before
# CONFIDENCE/RATIONALE, so this stops at any subsequent label instead -- any
# subsequent *known* label, per `_LABEL`.
_FINDING_OBSERVATIONS_RE = re.compile(
    rf"OBSERVATIONS\s*:\s*(.+?)(?:\n{_LABEL_PREFIX}{_LABEL}\s*:|\Z)", re.IGNORECASE | re.DOTALL
)


def _strip_md(text: str) -> str:
    """Remove markdown emphasis the model wraps the verdict block in.

    The 8B model sometimes emits `**VERDICT:** supports`, `**CONFIDENCE:** 0.7`,
    etc. Stripping `*` and backticks before field extraction makes the labelled
    parse tolerant of that. Underscores are deliberately kept -- header ids like
    `auth_events#1` and `dns_resolutions#1` depend on them.
    """
    return text.replace("*", "").replace("`", "")


def split_reasoning(generation: str) -> tuple[str | None, str]:
    """Return `(reasoning, answer)`.

    The seeded `<think>` means the opening tag may be absent from the returned
    text; only the closing `</think>` reliably marks the boundary. If it is
    missing, the whole generation is treated as the answer and reasoning is None.
    """
    if _THINK_CLOSE in generation:
        reasoning, _, answer = generation.partition(_THINK_CLOSE)
        reasoning = reasoning.replace("<think>", "").strip()
        return (reasoning or None), answer.strip()
    return None, generation.strip()


_DISPOSITION_RE = re.compile(r"DISPOSITION\s*:\s*(.+)", re.IGNORECASE)

# Ordered longest-discriminator-first for the same reason `_STANCE_KEYWORDS` is:
# a line may mention more than one word, and the leading word is checked before
# any substring scan. `inconclusive`/`insufficient`/`unclear` come first so that
# "inconclusive, though some rows look suspicious" does not register as
# `suspicious`.
_DISPOSITION_KEYWORDS: tuple[tuple[str, Disposition], ...] = (
    ("inconclusive", "inconclusive"),
    ("insufficient", "inconclusive"),
    ("unclear", "inconclusive"),
    ("malicious", "malicious"),
    ("suspicious", "suspicious"),
    ("benign", "benign"),
)


def _normalise_disposition(raw: str) -> Disposition | None:
    """Same leading-word-then-substring discipline as `_normalise_stance`.

    Returns None rather than a default so the caller decides what a missing
    disposition means -- `parse_finding` treats it as `inconclusive`, which is
    the honest reading of "the analyst did not say".
    """
    text = raw.strip().lower()
    leading = re.split(r"[\s,.;:\-]+", text, maxsplit=1)[0] if text else ""
    for needle, disposition in _DISPOSITION_KEYWORDS:
        if needle in leading:
            return disposition
    for needle, disposition in _DISPOSITION_KEYWORDS:
        if needle in text:
            return disposition
    return None


def _parse_citations(answer: str) -> list[str]:
    """The header ids on the trailing `CITATIONS:` line.

    Split on commas *or* whitespace. Commas alone -- which is what the prompt
    asks for and what this used to assume -- turned `CITATIONS: auth_events#1
    auth_events#2` into the single token `auth_events#1 auth_events#2`, which
    matches no id in `valid_citation_ids()`. So a correctly grounded finding
    lost every citation and `_finalize_finding` downgraded it to
    `inconclusive`: the model's only mistake was punctuation, and the penalty
    was its whole judgement. A separator no id can contain is safe to be
    generous about.
    """
    match = _CITATIONS_RE.search(answer)
    if not match:
        return []
    raw = match.group(1).strip()
    cleaned = (c.strip("[]").strip() for c in re.split(r"[,\s]+", raw))
    return [c for c in cleaned if c]


class FindingParseError(ValueError):
    """The generation carried no recognisable OBSERVATIONS or CITATIONS block."""


def parse_finding(generation: str, *, domain: AnalystDomain) -> DomainFinding:
    """Parse a hypothesis-blind generation into a `DomainFinding`.

    "Parseable" means an OBSERVATIONS or CITATIONS block was found at all --
    deliberately laxer than `parse_verdict`, which raises without a stance. A
    missing DISPOSITION is not fatal here: the observations are still grounded
    evidence worth keeping, and `inconclusive` states the gap honestly rather
    than discarding a good read over a missing label. A missing *stance* has no
    such fallback, because `supports`/`refutes` cannot be defaulted without
    inventing a position.
    """
    reasoning, raw_answer = split_reasoning(generation)
    answer = _strip_md(raw_answer)

    observations_match = _FINDING_OBSERVATIONS_RE.search(answer)
    observations = []
    if observations_match:
        for line in observations_match.group(1).splitlines():
            line = line.strip().lstrip("-*").strip()
            if line:
                observations.append(line)

    citations = _parse_citations(answer)
    if not observations and not citations:
        raise FindingParseError(
            f"no OBSERVATIONS or CITATIONS block found in {domain} analyst output"
        )

    confidence_match = _CONFIDENCE_RE.search(answer)
    confidence = float(confidence_match.group(1)) if confidence_match else 0.0
    confidence = max(0.0, min(1.0, confidence))

    rationale_match = _RATIONALE_RE.search(answer)
    rationale = rationale_match.group(1).strip() if rationale_match else ""

    disposition_match = _DISPOSITION_RE.search(answer)
    disposition = (
        _normalise_disposition(disposition_match.group(1)) if disposition_match else None
    )
    if disposition is None:
        logger.info(
            "domain=%s | no recognisable DISPOSITION in analyst output; recording "
            "'inconclusive' rather than assuming a reading",
            domain,
        )

    return DomainFinding(
        domain=domain,
        disposition=disposition or "inconclusive",
        observations=observations,
        citations=citations,
        confidence=confidence,
        rationale=rationale,
        reasoning_trace=reasoning,
    )
