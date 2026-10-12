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
from datetime import UTC, datetime
from typing import get_args

from contracts import AnalystDomain, Entity, Scope

from .formatting import format_result_set, format_vt_verdicts, summarise_rows
from .model import DEFAULT_MAX_GEN_LEN
from .prompts import build_facts_user_turn, facts_system_prompt
from .routing import DomainSlice

logger = logging.getLogger(__name__)

# Rough chars-per-token for Llama-family tokenizers, used to pick a row cap that
# keeps the prompt inside the window.
#
# It is an ESTIMATE, and it must run PESSIMISTIC (fewer chars per token, i.e. more
# estimated tokens for the same text) rather than optimistic -- a slice that packs
# slightly less than it could costs some evidence, while one that overflows the
# window costs the entire analyst call. This used to be 4, a fair average for
# prose, on the reasoning that evidence rows are hex digests, base64 command
# lines, GUIDs and timestamps, which BPE splits closer to "2-2.5 chars per
# token". That reasoning was directionally right and the number was still wrong
# by a lot. A live Splunk run on 2026-08-30 measured it against what the model
# actually counted (see docs/sessions/handover_2026-08-30_splunk-back-answer-
# sheet-and-siem-trace.md):
#
#   domain=network  | packed to fit ~20000 tokens but the model counted 31850
#   domain=endpoint | packed to fit ~20000 tokens but the model counted 22709
#
# network was 59% low -- implying an actual ratio of roughly 20000*4/31850 ≈ 2.5
# chars/token on that slice -- and endpoint 14% low (ratio ≈3.5). 2.5 is the
# worse (denser) of the two measured SIEM-evidence ratios, so it is what this
# constant uses: one conservative value applied everywhere, calibrated to the
# densest real evidence seen rather than an average across domains. It was
# derived from SIEM evidence specifically (identifier- and punctuation-heavy
# rows); a domain whose evidence tokenizes more like prose is simply packed with
# some margin to spare, which is the deliberately safe direction to be wrong in.
#
# This used to claim the inexactness was safe "because the model reports the true
# count back". That claim is false: the model does report it, on every call, and
# `_invoke_with_one_reask` does compare the two -- but the comparison fires AFTER
# the tokens are already spent. On the network run above it left just 918 tokens
# of the 32,768 window -- under 3% -- for the system prompt and the answer
# combined, and the first reply came back with no parseable block. A comparison
# that only warns after the call cannot be the safety net; getting the estimate
# itself right (this constant) and deriving the budget from real reserves
# (`_PACK_TOKEN_BUDGET` below) is.
_CHARS_PER_TOKEN = 2.5

# Progressively tighter row caps. 0 renders header + a "(N rows not shown)" line,
# i.e. counts only -- the coarsest summary that still reports the set exists.
#
# The FIRST rung is a ceiling, not a starting guess: `pack_evidence` walks down
# only when the rendered text overflows `token_budget`, so rung 0 is what every
# slice that fits gets. It was 20, and 20 was never reached by budget pressure --
# measured on `cli-20260823T112627`, the three slices rendered at 1,019 / 1,334 /
# 2,625 tokens against a 20,000 budget (the pre-recalibration figure -- see
# `_CHARS_PER_TOKEN` and `_PACK_TOKEN_BUDGET` below for the current one),
# i.e. 5-13% of it. What the cap was doing
# instead was hiding rows: 52 of a 72-row auth_events set from identity, and 110
# rows from endpoint including 80 of a single 100-row processes set. And because
# the ladder never stepped BELOW 20, `pack_evidence` returned `truncated=False`
# throughout -- so the loss was not merely unflagged, it was actively reported as
# "nothing was dropped".
#
# 200 because it clears the largest real set seen (100 rows) with room over, and
# because rendering every row of all three slices costs 2,317 / 1,491 / 7,180
# tokens -- the worst still under half the budget. The ladder is unchanged below
# the top: a genuinely huge slice shrinks exactly as before, so the budget decides
# what fits rather than a number chosen ahead of the data.
_ROW_CAP_LADDER = (200, 20, 10, 5, 3, 1, 0)


def estimate_tokens(text: str) -> int:
    # `int(...)` rather than relying on `//`'s own return type: `_CHARS_PER_TOKEN`
    # is a float (2.5), and float floor-division already returns a float
    # (`5 // 2.5 == 2.0`) -- silently widening this function's return type had it
    # stayed `len(text) // _CHARS_PER_TOKEN`.
    return int(len(text) // _CHARS_PER_TOKEN)


# ---------------------------------------------------------------------------
# The packing budget, derived from the model's context window rather than left
# as a bare number with no stated relationship to it -- which is how a budget of
# 20,000 sat next to a 32,768-token window with nobody having checked that the
# other things sharing that window (the system prompt, the generation) still
# fit once it was spent. Four named reserves, each with its own reason; a
# future reader (or `TestTheDerivedBudgetLeavesRoom` in
# `test_analyst_prompts.py`) can see why the budget is what it is, and changing
# `max_gen_len` or growing a system prompt visibly moves it.
# ---------------------------------------------------------------------------

_CONTEXT_WINDOW = 32_768
"""Foundation-Sec-8B-Reasoning's context window (see `model.py`'s own module
docstring for the model identity). Every reserve below is carved out of this."""

_GENERATION_RESERVE = DEFAULT_MAX_GEN_LEN
"""Tokens the model may spend on its reply. Imported rather than restated so this
budget visibly shrinks if `model.DEFAULT_MAX_GEN_LEN` (the module CONSTANT) ever
grows -- the two used to be reserved independently, with nothing that would
notice if one changed and the other did not.

**This is computed once, at import, and does not see a per-call override.**
`model.analyst_model_from_env` reads `SMARTOPS_ANALYST_MAX_GEN_LEN` at RUNTIME
and used to hand it straight to `AnalystModel`, so an operator setting it above
`DEFAULT_MAX_GEN_LEN` (e.g. 8192) silently overflowed this reserve -- and the
32,768-token window behind it -- by exactly the difference, with nothing here
able to notice a value that only exists later. `_clamped_max_gen_len` in
`model.py` is what actually enforces the invariant this constant's name implies:
it refuses (with a warning) any env value above `DEFAULT_MAX_GEN_LEN`, which is
the value this reserve was computed from."""

_SYSTEM_PROMPT_RESERVE = max(
    estimate_tokens(facts_system_prompt(domain)) for domain in get_args(AnalystDomain)
)
"""The largest rendered system prompt across the three domains, measured with
`estimate_tokens` rather than hardcoded -- prose tokenizes closer to the old
4-chars/token average than evidence does, so measuring it with the SAME
(conservative) estimator this module uses for evidence over-reserves rather than
under-reserves, which is the direction to be wrong in. `max()` over all three
because one shared budget is applied to every domain; the reader who grows one
domain's body sees this move without having to know which domain was largest."""

# Sized like real indicators, not short placeholders -- a SHA-256 hash and a
# full callback URL, not "sample-file_hash".
_SCAFFOLD_SAMPLE_VALUES: dict[str, str] = {
    "host": "WORKSTATION-042",
    "user": "svc-account-domain-admin",
    "ip": "203.0.113.255",
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "domain": "malicious-c2-infrastructure.example.com",
    "url": "https://malicious-c2-infrastructure.example.com/api/v2/beacon/checkin?token=deadbeef",
    "process": "powershell.exe",
    "file_name": "OneDriveStandaloneUpdater.exe",
    "command_line": "powershell.exe -NoProfile -EncodedCommand JABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQA=",
}

_SCAFFOLD_LONGEST_KIND, _SCAFFOLD_LONGEST_VALUE = max(
    _SCAFFOLD_SAMPLE_VALUES.items(), key=lambda item: len(item[1])
)
"""The single longest sample value across every `EntityKind` (currently `url`),
and the kind it belongs to.

**Every scaffold entity uses this one value, not a cycle through all seven
kinds.** A 20-entity scope built by cycling `EntityKind` puts each long value
(the SHA-256 hash, the full URL) in only ~3 of the 20 slots, with the rest
filled by short ones (`host`, `user`, `ip`) -- so the measurement below was an
AVERAGE-case scope, not a worst-case one. Measured reality for a 20-entity
scope of the longest value alone is 833 tokens against the 474 the cycled
version produced: the old reserve was exhausted at ~10 entities of the longest
kind, and the whole `_SAFETY_MARGIN` consumed by ~25 -- at which point
`_PACK_TOKEN_BUDGET` goes negative against the window. Bounding the WORST case
(every entity is the longest value) rather than a plausible-looking average is
what `_USER_TURN_SCAFFOLD_RESERVE` needs to actually be a bound."""

_SCAFFOLD_SAMPLE_SCOPE = Scope(
    entities=[
        Entity(kind=_SCAFFOLD_LONGEST_KIND, value=_SCAFFOLD_LONGEST_VALUE) for _ in range(20)
    ],
    time_window=(datetime(2000, 1, 1, tzinfo=UTC), datetime(2000, 1, 2, tzinfo=UTC)),
)
"""A synthetic scope used only to measure `build_facts_user_turn`'s fixed
overhead below -- never handed to a real analyst call.

**20 entities, not 1.** The first cut of this reserve measured a single-entity
scope (106 tokens) and derived a budget that landed EXACTLY on the 32,768-token
ceiling for `network` (the domain whose system prompt sizes
`_SYSTEM_PROMPT_RESERVE`) -- and was already 4 tokens short of what a real
1-entity scope costs once you count what `_render_scope` actually emits. That
is the identical failure mode this whole task exists to fix, just smaller and
harder to spot: a derivation that is *exact* on paper is exact only until the
next measurement finds it wrong by a few tokens, and this reserve is cheap
enough that there is no reason to cut it that close.

`Scope.entities` has no maximum (`contracts.subtask.Scope`), so no fixed count
is a guarantee -- 20 is a judgement about realistic investigation scopes, not a
hard bound. The largest scope in this repo's saved-run corpus
(`blind_compare.CASES`) names 5; 20 is 4x that, which comfortably covers a
hypothesis naming every entity kind several times over while still costing a
small, named amount (`_USER_TURN_SCAFFOLD_RESERVE` below) rather than an
unbounded one."""

_USER_TURN_SCAFFOLD_RESERVE = estimate_tokens(
    build_facts_user_turn(_SCAFFOLD_SAMPLE_SCOPE, "")
)
"""What `build_facts_user_turn` adds around the evidence text itself: the
`<scope>`/`<evidence>` fencing, one rendered line per scope entity, and the
trailing instruction line. Measured against `_SCAFFOLD_SAMPLE_SCOPE`'s 20
entities of the single LONGEST sample value (833 tokens), not an average across
`EntityKind` (474 tokens for the same 20 entities cycled through all seven
kinds) -- see that constant's own docstring for why the cycled version was not
actually a bound. The cost of that correctness, against a budget in the tens of
thousands, is ~1.4% (`_PACK_TOKEN_BUDGET` drops by 359 tokens) -- cheap enough
that there is no reason to keep the version that was wrong."""

_SAFETY_MARGIN = 500
"""A deliberate, named cushion on top of the three measured reserves, so the
budget does not land exactly on the window ceiling for whichever domain has the
largest system prompt -- which it did, silently, before this constant existed
(see `_SCAFFOLD_SAMPLE_SCOPE`'s docstring for the exact failure). Every reserve
above is itself a measurement -- of a rendered string, of a synthetic scope, of
`DEFAULT_MAX_GEN_LEN` -- and a measurement can be off by a little without being
wrong in kind: a system prompt gains a sentence, a real scope is denser than the
sample, the 2.5 ratio meets evidence a bit worse than the network slice that
calibrated it. 500 tokens (under 2% of the evidence budget) is cheap insurance
against exactly that, and it is a NAME a reader can see and reason about rather
than incidental slack that happens to exist for two domains and not the third.
`TestTheDerivedBudgetLeavesRoom` in `test_analyst_prompts.py` asserts every
domain keeps at least this much headroom, not just the tightest one."""

_PACK_TOKEN_BUDGET = (
    _CONTEXT_WINDOW
    - _SYSTEM_PROMPT_RESERVE
    - _GENERATION_RESERVE
    - _USER_TURN_SCAFFOLD_RESERVE
    - _SAFETY_MARGIN
)
"""The evidence budget `pack_evidence` packs to by default: everything left in
the window once the system prompt, the generation, the user-turn scaffolding,
and the explicit safety margin have each taken their named share. Restated
nowhere else -- `analyze.py` imports this name rather than hosting its own
copy, which is what let the two silently diverge before (`analyze.
_PACK_TOKEN_BUDGET` and this module's own default were two literals that
happened to both say 20,000)."""

# The way back has a budget too. The Analyst Agent is the same model with the same
# window, and every synthesis call re-reads the last FULL_ROUNDS rounds in full and
# the older ones as `run_trace.compact_round` records (`webapp/main.py`, W8).
_ANALYST_PROMPT_RESERVE = 4_300
"""Webapp system prompt + investigation plan, in tokens. Measured on 072fd610:
the round-2 synthesis call was 8,195 prompt tokens, of which the 6.3k-char system
prompt and the 10.4k-char plan were ~4.2k. 89674d75's were ~2.3k; plans vary."""

_ANALYST_ROUNDS = 2
"""Rounds synthesis reads in full: `webapp/main.py` FULL_ROUNDS."""

_COMPACT_ROUNDS_RESERVE = 4_000
"""Tokens for the compacted older rounds: 0.9-1.8 kB each (b3aa0dd2), so about 10."""

_HANDOFF_CHARS_PER_TOKEN = 3.5
"""The payload JSON, not raw rows (`_CHARS_PER_TOKEN`). Measured 3.76 on 89674d75:
round 3's synthesis prompt grew 4,789 tokens for round 3's 17,985 characters."""

_ANALYST_GENERATION_RESERVE = 8_192
"""The Analyst's own `max_gen_len` (`webapp/services/llm_service.DEFAULT_MAX_GEN_LEN`),
not the sub-analysts' `_GENERATION_RESERVE`: at 4,096 its synthesis thinking ran
out before the JSON on 78cd60ec (T15). `tests/test_verdict_gate.py` holds the two equal."""

HANDOFF_CHAR_BUDGET = int(
    (_CONTEXT_WINDOW - _ANALYST_GENERATION_RESERVE - _ANALYST_PROMPT_RESERVE
     - _SAFETY_MARGIN - _COMPACT_ROUNDS_RESERVE)
    // _ANALYST_ROUNDS
    * _HANDOFF_CHARS_PER_TOKEN
)
"""Characters one round's whole payload batch may take, split across its tasks by
the caller. 27,608: on 89674d75 the old 16,480 (a third share at 2.5 chars/token)
sent 0 observations in every round while synthesis peaked at 13.5k of 24.5k tokens (B14)."""


@dataclass(frozen=True)
class Block:
    """One rendered evidence block, with the header id the analyst may cite it by.

    `query` is carried alongside `text` rather than inside it: it is kept OUT of
    what the blind analyst reads (see `formatting.format_result_set`) and put
    back for the Analyst Agent via `contracts.Exhibit.query`. Empty for the
    `reputation#1` block, which is a lookup rather than a search.

    `summary` is the computed account of every row in the set, which is the same
    block `text` ends with, carried on its own because it crosses to the Analyst
    Agent while `text` does not (B1). `None` for an empty set and for `reputation#1`.
    """

    header_id: str
    evidence_ids: list[str]
    row_count: int
    text: str
    query: str = ""
    summary: str | None = None


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

    **Numbering is per category, not per slice.** One counter over `siem_sets`
    numbered by position instead, so the network slice of
    `cli-20260825T100434` emitted `connections#1..#9` and then
    `dns_resolutions#10..` -- with no `dns_resolutions#1`, which is the exact
    worked example `prompts._NARRATIVE_FOOTER` hands the model. A model citing it
    failed `valid_citation_ids`, lost the observation to
    `_resolve_observation_citations`, and -- as `_finalize_finding` behaved at the
    time -- had its disposition downgraded to `inconclusive`. That read as a
    cautious analyst rather than as a bug, which is what let it survive.

    The downgrade half of that account is history: since 2026-08-31 there is no
    disposition to downgrade and `_finalize_finding` marks the narrative instead.
    The NUMBERING half is not history, and is why this note stays -- a per-slice
    counter would still emit ids the model cannot cite.
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
    seen_per_category: dict[str, int] = {}
    for category, result_set in slice_.siem_sets:
        i = seen_per_category[category] = seen_per_category.get(category, 0) + 1
        out.append(
            Block(
                header_id=f"{category}#{i}",
                evidence_ids=[result_set.evidence_id] if result_set.evidence_id else [],
                row_count=result_set.row_count,
                text=format_result_set(category, result_set, index=i, row_cap=row_cap),
                query=result_set.query,
                summary=summarise_rows(category, result_set.rows, header_id=f"{category}#{i}"),
            )
        )
    for i, result_set in enumerate(slice_.untagged_sets, start=1):
        out.append(
            Block(
                header_id=f"uncategorised#{i}",
                evidence_ids=[result_set.evidence_id] if result_set.evidence_id else [],
                row_count=result_set.row_count,
                text=format_result_set("uncategorised", result_set, index=i, row_cap=row_cap),
                query=result_set.query,
                summary=summarise_rows("uncategorised", result_set.rows, header_id=f"uncategorised#{i}"),
            )
        )
    return out


def _render(slice_: DomainSlice, row_cap: int) -> str:
    return "\n\n".join(b.text for b in blocks(slice_, row_cap=row_cap))


def exhibits_for(
    slice_: DomainSlice, citations: list[str], *, row_cap: int | None = None
) -> list[Block]:
    """Only the blocks a finding actually cited, for handing to the Analyst Agent.

    The reduction is the point: on `cli-20260825T100434` each domain was routed
    32-35 blocks and cited one, so this is ~2% of `pack_evidence`'s output. That
    is what makes it possible to show the Analyst Agent the real rows rather than
    ids it would have to resolve against an evidence store it may not have.

    **`row_cap=None` means "whatever the analyst's own pack settled on"**, which
    is the only value for which `Exhibit.rows` is what its contract says it is:
    "the same projected text the domain analyst read". It used to default to a
    fixed 8 while the analyst read at whatever the ladder chose (20 down to 0),
    so an exhibit could show rows the analyst never saw -- and the consumer
    checking a judgement was checking it against evidence that did not inform
    it. Derived here rather than threaded in by the caller so no caller can get
    it wrong; pass an explicit cap only to render a deliberately different view.

    A consequence, and the honest one: where the pack DID shrink, the exhibit
    carries as little as a bare header. That is what the analyst read, so it is
    what the judgement rests on; `Block.row_count` and `Block.evidence_ids` are
    how a consumer holding the store gets the rest.
    """
    if row_cap is None:
        row_cap = fitted_row_cap(slice_)
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
    slice_: DomainSlice, *, token_budget: int = _PACK_TOKEN_BUDGET
) -> tuple[str, dict[str, list[str]], bool, int]:
    """Render a slice's evidence under `token_budget`.

    Returns `(evidence_text, valid_citation_ids, was_truncated, row_cap)`. Tries
    each row cap in the ladder until the rendered text fits; if even header-only
    overflows, the header-only text is returned anyway (a slice that large is a
    signal in itself) with `was_truncated=True`. `valid_citation_ids` is the
    header-id-to-evidence map a verdict's citations are checked against --
    membership of its keys is the validity test, and the values are what a kept
    citation resolves to.

    `row_cap` is the rung this call settled on, reported so a caller can log or
    assert on it. Note that `exhibits_for` does NOT take it from here: it calls
    `fitted_row_cap` and derives the rung again, deliberately, so that no caller
    can thread the wrong value through and make `Exhibit.rows` something other
    than what the analyst read (`exhibits_for`'s own docstring has the reasoning).
    This return value used to be documented the other way round -- as the thing
    `exhibits_for` consumes -- which described a design that had been replaced.
    No caller reads it today.
    """
    ids = valid_citation_ids(slice_)
    if not slice_.has_evidence():
        return "(no evidence was retrieved for this domain)", ids, False, _ROW_CAP_LADDER[0]

    text, row_cap = _fit(slice_, token_budget)
    if row_cap == 0:
        logger.warning(
            "domain=%s | evidence exceeds budget even at header-only; sending headers",
            slice_.domain,
        )
    elif row_cap != _ROW_CAP_LADDER[0]:
        logger.warning(
            "domain=%s | evidence over budget, rendered at row_cap=%d", slice_.domain, row_cap
        )
    return text, ids, row_cap != _ROW_CAP_LADDER[0], row_cap


def _fit(slice_: DomainSlice, token_budget: int) -> tuple[str, int]:
    """The first rung of `_ROW_CAP_LADDER` that fits, else header-only (row cap 0).

    Silent, so `fitted_row_cap` can re-measure without repeating
    `pack_evidence`'s warning (B41: 7 copies for one domain on 2a71757f).
    """
    for row_cap in _ROW_CAP_LADDER:
        text = _render(slice_, row_cap)
        if estimate_tokens(text) <= token_budget:
            return text, row_cap
    return _render(slice_, 0), 0


def fitted_row_cap(slice_: DomainSlice, *, token_budget: int = _PACK_TOKEN_BUDGET) -> int:
    """The row cap `pack_evidence` settles on for this slice.

    Shares `_fit` with `pack_evidence` rather than walking `_ROW_CAP_LADDER` again,
    for the same reason `valid_citation_ids` is a reading of `blocks()`: a second
    copy of the ladder would rot the first time one changed. It re-renders to
    measure, which is string formatting over at most a few dozen blocks against a
    call that is about to spend a model inference -- not a cost worth a cache.
    """
    if not slice_.has_evidence():
        return _ROW_CAP_LADDER[0]
    return _fit(slice_, token_budget)[1]
