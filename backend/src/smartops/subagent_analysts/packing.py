"""Fit a domain's evidence into the model's context budget.

The reasoning model has a 32k window shared by the system prompt, the hypothesis,
the evidence, and the generated reasoning. Evidence is the elastic part, so this
module renders a `DomainSlice` to text under a token budget, shrinking the per-set
row cap (20 -> 10 -> ... -> header-only) until it fits rather than truncating one
block mid-way. What was withheld is always visible in the rendered headers and is
logged -- no silent caps.

Ordering puts the highest-signal evidence first so it survives any shrink:
VirusTotal reputation, then SIEM categories, then untagged sets.
"""

from __future__ import annotations

import logging

from .formatting import format_result_set, format_vt_verdicts
from .routing import DomainSlice

logger = logging.getLogger(__name__)

# Rough chars-per-token for Llama-family tokenizers; only used to keep the prompt
# from overrunning the window, and the model reports the true count back so this
# never has to be exact.
_CHARS_PER_TOKEN = 4

# Progressively tighter row caps. 0 renders header + a "(N rows not shown)" line,
# i.e. counts only -- the coarsest summary that still reports the set exists.
_ROW_CAP_LADDER = (20, 10, 5, 3, 1, 0)


def estimate_tokens(text: str) -> int:
    return len(text) // _CHARS_PER_TOKEN


def _render(slice_: DomainSlice, row_cap: int) -> str:
    blocks: list[str] = []
    if slice_.vt_verdicts:
        blocks.append(format_vt_verdicts(slice_.vt_verdicts, index=1))
    for i, (category, result_set) in enumerate(slice_.siem_sets, start=1):
        blocks.append(format_result_set(category, result_set, index=i, row_cap=row_cap))
    for i, result_set in enumerate(slice_.untagged_sets, start=1):
        blocks.append(
            format_result_set("uncategorised", result_set, index=i, row_cap=row_cap)
        )
    return "\n\n".join(blocks)


def valid_citation_ids(slice_: DomainSlice) -> set[str]:
    """The header ids emitted for this slice, i.e. the only citations that resolve.

    Mirrors `_render`'s block order/numbering exactly, so a model citation is valid
    iff it is in this set. Used by the anti-hallucination gate in `analyze`.
    """
    ids: set[str] = set()
    if slice_.vt_verdicts:
        ids.add("reputation#1")
    for i, (category, _rs) in enumerate(slice_.siem_sets, start=1):
        ids.add(f"{category}#{i}")
    for i, _rs in enumerate(slice_.untagged_sets, start=1):
        ids.add(f"uncategorised#{i}")
    return ids


def pack_evidence(
    slice_: DomainSlice, *, token_budget: int = 20_000
) -> tuple[str, set[str], bool]:
    """Render a slice's evidence under `token_budget`.

    Returns `(evidence_text, valid_citation_ids, was_truncated)`. Tries each row cap
    in the ladder until the rendered text fits; if even header-only overflows, the
    header-only text is returned anyway (a slice that large is a signal in itself)
    with `was_truncated=True`. `valid_citation_ids` is the set a verdict's citations
    are checked against.
    """
    ids = valid_citation_ids(slice_)
    if not slice_.has_evidence():
        return "(no evidence was retrieved for this domain)", ids, False

    for row_cap in _ROW_CAP_LADDER:
        text = _render(slice_, row_cap)
        if estimate_tokens(text) <= token_budget:
            truncated = row_cap != _ROW_CAP_LADDER[0]
            if truncated:
                logger.warning(
                    "domain=%s | evidence over budget, rendered at row_cap=%d",
                    slice_.domain,
                    row_cap,
                )
            return text, ids, truncated

    logger.warning(
        "domain=%s | evidence exceeds budget even at header-only; sending headers",
        slice_.domain,
    )
    return _render(slice_, 0), ids, True
