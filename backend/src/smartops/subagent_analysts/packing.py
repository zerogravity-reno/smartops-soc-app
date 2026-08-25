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
from dataclasses import dataclass

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


@dataclass(frozen=True)
class Block:
    """One rendered evidence block, with the header id the analyst may cite it by."""

    header_id: str
    evidence_ids: list[str]
    row_count: int
    text: str


def blocks(slice_: DomainSlice, *, row_cap: int = _ROW_CAP_LADDER[0]) -> list[Block]:
    """Every block this slice renders, in the order the analyst sees them.

    **The single place block order and numbering are defined.** `_render`,
    `valid_citation_ids` and `exhibits_for` are all thin readings of this list
    rather than three functions each mirroring the same enumeration --
    `valid_citation_ids` used to warn that a second parallel implementation
    "would rot the first time one changed", and the way to honour that as a
    third consumer arrives is to remove the mirroring, not to add to it.

    Ordering puts the highest-signal evidence first so it survives any shrink:
    VirusTotal reputation, then SIEM categories, then untagged sets.
    """
    out: list[Block] = []
    if slice_.vt_verdicts:
        out.append(
            Block(
                header_id="reputation#1",
                # A list because one `reputation#1` header covers every VT
                # verdict in the slice -- see `HypothesisFindings` open question C.
                evidence_ids=[v.evidence_id for v in slice_.vt_verdicts if v.evidence_id],
                row_count=len(slice_.vt_verdicts),
                text=format_vt_verdicts(slice_.vt_verdicts, index=1),
            )
        )
    for i, (category, result_set) in enumerate(slice_.siem_sets, start=1):
        out.append(
            Block(
                header_id=f"{category}#{i}",
                evidence_ids=[result_set.evidence_id] if result_set.evidence_id else [],
                row_count=result_set.row_count,
                text=format_result_set(category, result_set, index=i, row_cap=row_cap),
            )
        )
    for i, result_set in enumerate(slice_.untagged_sets, start=1):
        out.append(
            Block(
                header_id=f"uncategorised#{i}",
                evidence_ids=[result_set.evidence_id] if result_set.evidence_id else [],
                row_count=result_set.row_count,
                text=format_result_set("uncategorised", result_set, index=i, row_cap=row_cap),
            )
        )
    return out


def _render(slice_: DomainSlice, row_cap: int) -> str:
    return "\n\n".join(b.text for b in blocks(slice_, row_cap=row_cap))


def exhibits_for(
    slice_: DomainSlice, citations: list[str], *, row_cap: int = 8
) -> list[Block]:
    """Only the blocks a finding actually cited, for handing to the Analyst Agent.

    The reduction is the point: on `cli-20260825T100434` each domain was routed
    32-35 blocks and cited one, so this is ~2% of `pack_evidence`'s output. That
    is what makes it possible to show the Analyst Agent the real rows rather than
    ids it would have to resolve against an evidence store it may not have.

    `row_cap` is tighter than the analyst's own default (8 vs 20) because the
    consumer needs enough rows to check a judgement, not enough to redo it --
    and `format_result_set` appends "(N more rows not shown)", so what was
    withheld stays visible.
    """
    wanted = set(citations)
    return [b for b in blocks(slice_, row_cap=row_cap) if b.header_id in wanted]


def valid_citation_ids(slice_: DomainSlice) -> dict[str, list[str]]:
    """Each emitted header id mapped to the `Evidence.id`s behind it.

    A model citation is valid iff it is a key here. Returns the MAP rather than a
    bare set; callers that want only validity use the keys, which is what a
    membership test on a dict already does.

    Now a reading of `blocks()` rather than its own enumeration -- it used to
    re-implement `_render`'s order and numbering and warn in this docstring that
    a second copy "would rot the first time one changed". `exhibits_for` was
    about to be the third, so the enumeration moved into one function instead.

    A list per id because one `reputation#1` header covers every VT verdict in
    the slice. An entry is `[]` when the source predates `ResultSet.evidence_id`.
    """
    return {b.header_id: b.evidence_ids for b in blocks(slice_)}


def pack_evidence(
    slice_: DomainSlice, *, token_budget: int = 20_000
) -> tuple[str, dict[str, list[str]], bool]:
    """Render a slice's evidence under `token_budget`.

    Returns `(evidence_text, valid_citation_ids, was_truncated)`. Tries each row cap
    in the ladder until the rendered text fits; if even header-only overflows, the
    header-only text is returned anyway (a slice that large is a signal in itself)
    with `was_truncated=True`. `valid_citation_ids` is the header-id-to-evidence
    map a verdict's citations are checked against -- membership of its keys is
    the validity test, and the values are what a kept citation resolves to.
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
