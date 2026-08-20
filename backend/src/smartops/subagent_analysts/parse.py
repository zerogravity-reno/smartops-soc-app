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

from contracts import AnalystDomain, AnalystVerdict, Stance

_THINK_CLOSE = "</think>"

_STANCE_RE = re.compile(r"VERDICT\s*:\s*(.+)", re.IGNORECASE)
# `CONFIDENCE` and its value can be separated by markdown emphasis the 8B model
# adds (`**CONFIDENCE:** 0.7`), so allow non-digit noise between them.
_CONFIDENCE_RE = re.compile(r"CONFIDENCE\D*([0-9]*\.?[0-9]+)", re.IGNORECASE)
# A field stops at the next LABEL line, which the model may bold/emphasise
# (`\n**OBSERVATIONS:**`). Allow leading emphasis/space before the label word.
_RATIONALE_RE = re.compile(
    r"RATIONALE\s*:\s*(.+?)(?:\n[*_`\s]*[A-Z][A-Z ]+:|\Z)", re.IGNORECASE | re.DOTALL
)
_CITATIONS_RE = re.compile(r"CITATIONS\s*:\s*(.+)", re.IGNORECASE)
_OBSERVATIONS_RE = re.compile(
    r"OBSERVATIONS\s*:\s*(.+?)(?:\n[*_`\s]*CITATIONS\s*:|\Z)", re.IGNORECASE | re.DOTALL
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


def _normalise_stance(raw: str) -> Stance | None:
    text = raw.strip().lower()
    if "support" in text:
        return "supports"
    if "refut" in text:
        return "refutes"
    if "inconclusive" in text or "insufficient" in text or "unclear" in text:
        return "inconclusive"
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
