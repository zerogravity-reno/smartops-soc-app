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

import re

from contracts import AnalystDomain, AnalystVerdict, DomainFinding, Stance

_THINK_CLOSE = "</think>"

_STANCE_RE = re.compile(r"VERDICT\s*:\s*(.+)", re.IGNORECASE)
# `CONFIDENCE` and its value can be separated by markdown emphasis the 8B model
# adds (`**CONFIDENCE:** 0.7`), so allow non-digit noise between them -- but
# `[^\n\d]` rather than `\D`, so that noise cannot cross a newline. `\D*` used
# to walk straight past a valueless `CONFIDENCE: unclear` into the next digit
# anywhere later in the text, including inside a citation like
# `auth_events#1`, manufacturing confidence=1.0 from a reply that gave none.
_CONFIDENCE_RE = re.compile(r"CONFIDENCE[^\n\d]*([0-9]*\.?[0-9]+)", re.IGNORECASE)
# A field stops at the next LABEL line, which the model may bold/emphasise
# (`\n**OBSERVATIONS:**`). Allow leading emphasis/space before the label word.
_RATIONALE_RE = re.compile(
    r"RATIONALE\s*:\s*(.+?)(?:\n[*_`\s]*[A-Z][A-Z ]+:|\Z)", re.IGNORECASE | re.DOTALL
)
_CITATIONS_RE = re.compile(r"CITATIONS\s*:\s*(.+)", re.IGNORECASE)
_OBSERVATIONS_RE = re.compile(
    r"OBSERVATIONS\s*:\s*(.+?)(?:\n[*_`\s]*CITATIONS\s*:|\Z)", re.IGNORECASE | re.DOTALL
)
# `parse_finding`'s own OBSERVATIONS pattern, module-level like every other
# pattern here rather than recompiled on every call. Deliberately not
# `_OBSERVATIONS_RE`: that one assumes OBSERVATIONS immediately precedes
# CITATIONS, but a hypothesis-blind finding's OBSERVATIONS may come before
# CONFIDENCE/RATIONALE, so this stops at any subsequent label instead.
_FINDING_OBSERVATIONS_RE = re.compile(
    r"OBSERVATIONS\s*:\s*(.+?)(?:\n[*_`\s]*[A-Z][A-Z ]+\s*:|\Z)", re.IGNORECASE | re.DOTALL
)


def _strip_md(text: str) -> str:
    """Remove markdown emphasis the model wraps the verdict block in.

    The 8B model sometimes emits `**VERDICT:** supports`, `**CONFIDENCE:** 0.7`,
    etc. Stripping `*` and backticks before field extraction makes the labelled
    parse tolerant of that. Underscores are deliberately kept -- header ids like
    `auth_events#1` and `dns_resolutions#1` depend on them.
    """
    return text.replace("*", "").replace("`", "")


class VerdictParseError(ValueError):
    """The generation carried no recognisable verdict block."""


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


_STANCE_KEYWORDS: tuple[tuple[str, Stance], ...] = (
    ("inconclusive", "inconclusive"),
    ("insufficient", "inconclusive"),
    ("unclear", "inconclusive"),
    ("refut", "refutes"),
    ("support", "supports"),
)


def _normalise_stance(raw: str) -> Stance | None:
    text = raw.strip().lower()
    # The model is prompted to lead the VERDICT line with the stance word
    # itself, so check the leading word first, before falling back to a
    # substring scan over the whole line. Substring-only used to misclassify a
    # verbose line where the *other* stance word appears in passing --
    # `VERDICT: refutes, there is no support for the hypothesis` scanned
    # "support" first and registered as `supports`.
    leading = re.split(r"[\s,.;:\-]+", text, maxsplit=1)[0] if text else ""
    for needle, stance in _STANCE_KEYWORDS:
        if needle in leading:
            return stance
    for needle, stance in _STANCE_KEYWORDS:
        if needle in text:
            return stance
    return None


def _parse_observations(answer: str) -> list[str]:
    match = _OBSERVATIONS_RE.search(answer)
    if not match:
        return []
    observations = []
    for line in match.group(1).splitlines():
        line = line.strip().lstrip("-*").strip()
        if line:
            observations.append(line)
    return observations


def _parse_citations(answer: str) -> list[str]:
    match = _CITATIONS_RE.search(answer)
    if not match:
        return []
    raw = match.group(1).strip()
    cleaned = (c.strip().strip("[]").strip() for c in raw.split(","))
    return [c for c in cleaned if c]


def parse_verdict(
    generation: str, *, domain: AnalystDomain
) -> AnalystVerdict:
    """Parse a full generation (reasoning + answer) into an `AnalystVerdict`.

    Raises `VerdictParseError` if no stance can be recovered.
    """
    reasoning, raw_answer = split_reasoning(generation)
    # Field extraction runs on a markdown-stripped copy so `**VERDICT:**`-style
    # emphasis does not break the labelled parse; `reasoning` is kept verbatim.
    answer = _strip_md(raw_answer)

    stance_match = _STANCE_RE.search(answer)
    stance = _normalise_stance(stance_match.group(1)) if stance_match else None
    if stance is None:
        raise VerdictParseError(
            f"no VERDICT stance found in {domain} analyst output"
        )

    confidence_match = _CONFIDENCE_RE.search(answer)
    confidence = float(confidence_match.group(1)) if confidence_match else 0.0
    confidence = max(0.0, min(1.0, confidence))

    rationale_match = _RATIONALE_RE.search(answer)
    rationale = rationale_match.group(1).strip() if rationale_match else ""

    return AnalystVerdict(
        domain=domain,
        stance=stance,
        confidence=confidence,
        rationale=rationale,
        key_observations=_parse_observations(answer),
        citations=_parse_citations(answer),
        reasoning_trace=reasoning,
    )


class FindingParseError(ValueError):
    """The generation carried no recognisable OBSERVATIONS or CITATIONS block."""


def parse_finding(generation: str, *, domain: AnalystDomain) -> DomainFinding:
    """Parse a hypothesis-blind generation into a `DomainFinding`.

    Unlike `parse_verdict`, there is no stance to recover here: "parseable"
    means an OBSERVATIONS or CITATIONS block was found at all. Reuses the same
    generic label regexes as `parse_verdict`; only the stance-specific
    `_STANCE_RE`/`_normalise_stance` are skipped, because there is no stance at
    this layer.
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

    return DomainFinding(
        domain=domain,
        observations=observations,
        citations=citations,
        confidence=confidence,
        rationale=rationale,
        reasoning_trace=reasoning,
    )
