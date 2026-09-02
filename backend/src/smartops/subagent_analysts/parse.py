"""Split the model's reasoning from its answer and parse the labelled block.

The model is prompted with a seeded `<think>` tag, so its `generation` is
`…reasoning… </think> …labelled block…`. `split_reasoning` separates the two.

Two parsers read what follows, one per arm, and they require different things:

- `parse_finding` (here) is the **production, hypothesis-blind** path. This tier
  translates its rows into plain English, so the block is
  `NARRATIVE / OBSERVATIONS / CITATIONS` and a reply missing the narrative
  raises `FindingParseError`.
- `parse_verdict` (`shown.py`) is the A/B harness's hypothesis-SHOWN arm. It
  still reads `VERDICT / CONFIDENCE / RATIONALE`, and raises
  `VerdictParseError` without a recognisable stance.

Either error becomes one bounded re-ask in `analyze._invoke_with_one_reask`.

Parsing is deliberately lenient about surrounding prose (an 8B model will not
always stop cleanly after the block) but strict about the field that carries the
answer. It is strict there *because* of the opposite mistake: this module used to
parse a `DISPOSITION:` and default it to `inconclusive`, so on the 2026-08-30
live run a domain that had read its rows correctly still crossed the wire
carrying a verdict no model had formed. The disposition is gone from this tier
altogether -- deciding happens in the Analyst Agent, past the
`HypothesisFindings` boundary -- and nothing that replaced it gets a default.

Several regexes below are now read only by `shown.py`. Each says so on itself;
they are live code for the arm that measures whether the blind design was right.
"""

from __future__ import annotations

import re

from contracts import (
    AnalystDomain,
    DomainFinding,
)

_THINK_CLOSE = "</think>"

# `CONFIDENCE` and its value can be separated by markdown emphasis the 8B model
# adds (`**CONFIDENCE:** 0.7`), so allow non-digit noise between them -- but
# `[^\n\d]` rather than `\D`, so that noise cannot cross a newline. `\D*` used
# to walk straight past a valueless `CONFIDENCE: unclear` into the next digit
# anywhere later in the text, including inside a citation like
# `auth_events#1`, manufacturing confidence=1.0 from a reply that gave none.
_CONFIDENCE_RE = re.compile(r"CONFIDENCE[^\n\d]*([0-9]*\.?[0-9]+)", re.IGNORECASE)
"""**Shown-arm only, and deliberately kept.**

`parse_finding` stopped reading a confidence on 2026-08-31 -- a translator does
not rate its own certainty -- but `shown.py:290` imports this name directly to
parse its own `CONFIDENCE:` field, and `shown.py` keeps `Stance`,
`AnalystVerdict` and `confidence` on purpose. Deleting this as dead code breaks
that import and with it `blind_compare`, the harness whose measurements are the
evidence the blind design rests on."""

# Every label the prompts emit: `_VERDICT_FOOTER` (`shown.py`) for a
# hypothesis-shown verdict, `_NARRATIVE_ANSWER_BLOCK` (`prompts.py`) for a blind
# finding. Closed on purpose: the terminator used to be a generic uppercase run,
# `[A-Z][A-Z ]+:`, which under IGNORECASE matches any ordinary prose line ending
# in a colon -- so a rationale reading "Note the following: ..." was cut at "Note
# the following", and an un-bulleted observation line containing a colon ended
# the OBSERVATIONS capture and took every later observation with it. Enumerating
# the labels is what makes a colon in prose just a colon. Closed also means it
# must be kept in step: a label added to a footer and not added here silently
# stops terminating -- nothing raises, the preceding capture simply runs on
# through it and swallows the next block.
#
# `NARRATIVE` is here because the blind footer emits it. Without it, the
# OBSERVATIONS capture of a reply whose narrative follows its observations would
# absorb the whole narrative, and no test would fail loudly; see
# `test_analyst_parse.TestTheNarrativeLabelTerminates`.
#
# `DISPOSITION` is here even though NO prompt asks for it any more, and that is
# a decision rather than an oversight. This set is defensive -- it says which
# words end a field, not which words are wanted. An 8B model that habitually
# emits a `DISPOSITION:` line, or a stored generation replayed from before
# 2026-08-31, still has to have that line *end* the narrative rather than be
# absorbed into it; keeping the label costs nothing (nothing reads a disposition
# now, so it cannot resurrect a verdict) and dropping it would reintroduce the
# silent-truncation failure this comment exists to warn about.
_LABEL = r"(?:VERDICT|DISPOSITION|CONFIDENCE|NARRATIVE|RATIONALE|OBSERVATIONS|CITATIONS)"

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
_NARRATIVE_RE = re.compile(
    rf"NARRATIVE\s*:\s*(.+?)(?:\n{_LABEL_PREFIX}{_LABEL}\s*:|\Z)", re.IGNORECASE | re.DOTALL
)
_RATIONALE_RE = re.compile(
    rf"RATIONALE\s*:\s*(.+?)(?:\n{_LABEL_PREFIX}{_LABEL}\s*:|\Z)", re.IGNORECASE | re.DOTALL
)
"""**Shown-arm only, and deliberately kept under this name.**

The blind arm renamed its prose field `rationale` -> `narrative` on 2026-08-31
and reads `_NARRATIVE_RE` above; this one was NOT renamed to follow it, because
`shown.py:294` imports `_RATIONALE_RE` by name to parse the `RATIONALE:` its own
`_VERDICT_FOOTER` still asks for. Two regexes rather than one shared one is the
honest shape: the two arms now ask the model for two different fields."""

_CITATIONS_RE = re.compile(r"CITATIONS\s*:\s*(.+)", re.IGNORECASE)
# `parse_finding`'s own OBSERVATIONS pattern, module-level like every other
# pattern here rather than recompiled on every call. Deliberately not
# `_OBSERVATIONS_RE`: that one assumes OBSERVATIONS immediately precedes
# CITATIONS, but a hypothesis-blind finding's OBSERVATIONS may come before or
# after NARRATIVE, so this stops at any subsequent label instead -- any
# subsequent *known* label, per `_LABEL`.
_FINDING_OBSERVATIONS_RE = re.compile(
    rf"OBSERVATIONS\s*:\s*(.+?)(?:\n{_LABEL_PREFIX}{_LABEL}\s*:|\Z)", re.IGNORECASE | re.DOTALL
)

# The one hole `_LABEL` cannot close by itself. Every terminator above is
# anchored to a NEWLINE, so a label that is the very first thing after
# `NARRATIVE:` -- i.e. an empty narrative, `NARRATIVE:\nOBSERVATIONS: ...` --
# is not terminated but captured: the `\s*` after the colon gives the newline
# back and the label line itself becomes the narrative. Checking the captured
# text against this turns that into the `FindingParseError` an empty narrative
# should have been all along.
_LABEL_AT_START_RE = re.compile(rf"{_LABEL_PREFIX}{_LABEL}\s*:", re.IGNORECASE)


def _strip_md(text: str) -> str:
    """Remove markdown emphasis the model wraps the answer block in.

    The 8B model sometimes emits `**NARRATIVE:**`, `**CONFIDENCE:** 0.7`, etc.
    Stripping `*` and backticks before field extraction makes the labelled
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


def _parse_citations(answer: str) -> list[str]:
    """The header ids on the trailing `CITATIONS:` line.

    Split on commas *or* whitespace. Commas alone -- which is what the prompt
    asks for and what this used to assume -- turned `CITATIONS: auth_events#1
    auth_events#2` into the single token `auth_events#1 auth_events#2`, which
    matches no id in `valid_citation_ids()`. So a correctly grounded finding
    lost every citation and `_finalize_finding` stripped its observations and
    marked it ungrounded: the model's only mistake was punctuation, and the
    penalty was its whole read of the evidence. A separator no id can contain is
    safe to be generous about.
    """
    match = _CITATIONS_RE.search(answer)
    if not match:
        return []
    raw = match.group(1).strip()
    cleaned = (c.strip("[]").strip() for c in re.split(r"[,\s]+", raw))
    return [c for c in cleaned if c]


class FindingParseError(ValueError):
    """The generation carried no NARRATIVE, or no OBSERVATIONS and no CITATIONS."""


def parse_finding(generation: str, *, domain: AnalystDomain) -> DomainFinding:
    """Parse a hypothesis-blind generation into a `DomainFinding`.

    Two things must be present, and neither is defaulted when it is not:

    - **NARRATIVE**, because it is now the product. This tier's whole job is to
      turn rows into plain English; a reply without the translation is not a lax
      finding, it is an empty one. Defaulting it to `""` would be the 2026-08-30
      defect one field over -- that run defaulted an absent `DISPOSITION` to
      `inconclusive` and put a verdict no model had formed onto the wire, and a
      silent `""` would put a silence no model had produced there instead.
    - **OBSERVATIONS or CITATIONS**, either one. Still an OR, and still laxer
      than `parse_verdict`, which raises without a stance: a reply that gave
      grounded observations but no trailing `CITATIONS:` line has read its rows,
      and `analyze._finalize_finding` recovers the ids from the observations'
      inline `[header_id]`s anyway.

    Raising is not discarding. `analyze._invoke_with_one_reask` turns a
    `FindingParseError` into one bounded re-ask whose last instruction is the
    required block itself, and only a second failure ends the domain empty.
    """
    reasoning, raw_answer = split_reasoning(generation)
    answer = _strip_md(raw_answer)

    narrative_match = _NARRATIVE_RE.search(answer)
    narrative = narrative_match.group(1).strip() if narrative_match else ""
    # `_LABEL_AT_START_RE`: see its own comment. An empty `NARRATIVE:` line
    # followed by the next label captures that label instead of nothing.
    if not narrative or _LABEL_AT_START_RE.match(narrative):
        raise FindingParseError(f"no NARRATIVE block found in {domain} analyst output")

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

    return DomainFinding(
        domain=domain,
        narrative=narrative,
        observations=observations,
        citations=citations,
        reasoning_trace=reasoning,
    )
