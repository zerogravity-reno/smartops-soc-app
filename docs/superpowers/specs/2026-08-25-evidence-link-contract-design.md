# The evidence-link contract: what joins a hypothesis to the rows a verdict rests on

**Status:** three questions open, pending decision. Nothing here is settled.
**Date:** 2026-08-25
**Branch:** `task-broker-agent`, HEAD `d8406d1`

## Context

`docs/architecture.md:35` states the design invariant of the whole engine:

> conclusions must be grounded in evidence the system actually retrieved, and
> neither a model's rows nor its citations are taken on trust.

Enforcing that at runtime is one thing; being able to *prove* it afterwards from a
stored artifact is another. The second is what the id chain is for, and it now exists
end to end. But it was never designed as a whole. It accreted in three pieces, each
closing a specific gap the 2026-08-24 Findings Pipeline / Evidence Store audit found
by execution:

| Commit | What it added |
| :--- | :--- |
| `893f587` | `ResultSet.evidence_id`, `VtVerdict.evidence_id`, `AnalystVerdict.citation_evidence` |
| `4ccc54b` | `HypothesisAssessment.task_id` — the join key back to `report.json` |
| *(uncommitted)* | `evidence_id()` used on the enricher path; `Evidence.raw` reshaped to `{tool, query, result}` |

Each was correct in isolation. Nobody has written down what the assembled chain
guarantees, and two of its properties look more like consequences of how it was built
than like decisions someone made. This document records the chain, then puts three
questions.

It deliberately decides none of them. No id-shape code should land until they are
settled.

## The chain as built

```
AnalystTask.hypothesis_id ─┐   (analyst_task.py:35-36)
AnalystTask.task_id ───────┤
                           ▼
broker.py:767   mission.task_id = "{task_id}:{family}:{toolUseId}"
                                       │        │        │
                                  hypothesis  domain   dispatch
                           ▼
subtask.py:56   Evidence.id = evidence_id(mission.task_id, index)
                            = "{task_id}:{family}:{toolUseId}:{index}"
                           ▼
ResultSet.evidence_id  ──┐        VtVerdict.evidence_id  ──┐
                         ▼                                 ▼
packing.py:63   valid_citation_ids() → {header id: [Evidence.id, ...]}
                           ▼
                  "auth_events#1", "reputation#1"
                           ▼        ← the only id the analyst ever sees
AnalystVerdict.citation_evidence = {"auth_events#1": ["<Evidence.id>", ...]}
                           ▼
HypothesisAssessment.task_id ──→ BrokerReport.task_id
```

### What already holds, and is worth stating

Four properties are genuinely good and currently undocumented, which means the next
person to touch this has no way to know they are load-bearing:

1. **Every hop is minted by code. The model authors no id at any point.** This is the
   same rule `contracts.Evidence` and `_EvidenceCollector` exist to enforce —
   "assembled by code rather than authored by the model" — extended to the identifiers
   themselves. A model can cite an id; it can never create one.
2. **`toolUseId` is the broker-dispatch join.** It is the one component of
   `mission.task_id` that distinguishes two dispatches of the same family for the same
   hypothesis. Without it, a re-dispatch would overwrite the first dispatch's evidence
   ids.
3. **`citation_evidence` freezes the resolution at finalisation.** The grounding gate
   really does drop fabricated citations, but before `893f587` that decision was not
   recorded, so tracing a stored verdict to its rows meant recomputing the routing and
   hoping it came out the same. Now the mapping is in the artifact.
4. **One formula, one place.** `evidence_id()` (`subtask.py:56`) is the single
   definition; the two former inline copies in `_EvidenceCollector.evidence` and
   `smartops.broker` are being replaced by calls to it. Three consumers must agree
   exactly or a `ResultSet.evidence_id` points at nothing.

## Question A — positional, or content-addressed?

**As built:** `toolUseId` is Strands-generated per invocation, and `index` is the
`enumerate` position over `collector.calls`. Run the same case twice against identical
data and every id differs.

**The case that per-run uniqueness is correct.** Evidence fetched twice *is* two
observations. The underlying data may have changed between them, and the second fetch
has its own timestamp, its own cost, its own place in the ledger. Giving both the same
id asserts they are the same thing, which is a stronger claim than the system is
entitled to make. Under this reading "have we already fetched this?" is a question for
the replay layer, matching on tool + query, and the id is doing its job correctly by
being unique.

**The case for content-addressing** — `evidence_id(task_id, sha256(tool, query,
payload)[:12])`:

- Ids become reproducible, so an artifact can be verified against a re-run.
- `ReplayToolset` becomes an exact lookup instead of fuzzy matching on tool + query.
  This matters more than it sounds: the entire `_query_of` / `file_hash` class of
  replay bug exists *because* the id cannot do this job. `_query_of` had to learn to
  fall back to the longest plain string precisely so that VT records would carry
  something for a fuzzy matcher to match on, and `_extract_query_from_kwargs` still
  misses `file_hash`, so hash replays return a different hash's verdict.
- Deduplication becomes free rather than a feature someone has to build.

**The positional weakness, stated plainly.** `ResultSet.evidence_id`'s own docstring
argues that a header id is unsafe *because* `connections#23` names a position in a
recomputed routing — "if the routing order ever changes every stored citation silently
re-targets different evidence." `Evidence.id`'s trailing `:{index}` has the same
shape one layer down: it names the Nth call in a list the collector built. What holds
that list stable today is the answer-tool skip, and this is exactly why that fix had
to filter the one shared list rather than each consumer separately
(`subagents/__init__.py:294-316`) — filtering in `evidence()` but not in
`projection.project_*` would have slid every id onto the wrong payload while leaving
each one well-formed. That is a narrow escape, not a guarantee.

**What either answer costs.** The 22 saved reports that already fail to load
(`load_run_artifacts` raises `union_tag_not_found`; gap 2 of the 2026-08-24 handover)
are joined by these ids. Changing the id shape compounds a migration that is already
outstanding. If the answer is content-addressing, doing it *with* that migration is
cheaper than doing it after.

**Recommendation:** content-address the last hop, keep `task_id:family:toolUseId` as
the prefix. It preserves per-dispatch distinctness — two dispatches still produce
different ids because `toolUseId` differs — while making the payload-level id
reproducible and exact. But this is the question that most deserves a decision rather
than a default, because it is the one that is expensive to reverse.

**Open.**

## Question B — a citation can be valid and resolve to nothing

`valid_citation_ids()` (`packing.py:63-76`) returns `[]` for any source that predates
`ResultSet.evidence_id`:

```python
ids[f"{category}#{i}"] = (
    [result_set.evidence_id] if result_set.evidence_id else []
)
```

The grounding gate tests **key membership** — `_finalize` and `_finalize_finding` keep
a citation iff `c in valid_ids`. So a citation to a legacy source is *valid* and
*resolves to nothing*: it passes the gate, survives into the stored verdict, and lands
in `citation_evidence` as an empty list.

This is deliberate and defensible — the alternative is that every artifact written
before `893f587` becomes ungroundable, and the field is optional precisely so those
still load. But it means two different claims wear the same badge in the artifact:

- "the gate accepted this citation" — always true of a kept citation;
- "this citation can be traced to the rows it rests on" — true only when the list is
  non-empty.

Nothing in `assessment.json` distinguishes them. An auditor reading a stored verdict
cannot tell a fully-grounded citation from one that merely cleared a membership test,
without opening the evidence store and checking each list.

**Question:** should an empty resolution be visible — a count on
`HypothesisAssessment`, a per-verdict flag, a status enum on the citation — or is
silence correct because the legacy case will age out on its own?

**Recommendation:** a single derived counter (unresolved citations / total citations)
on `HypothesisAssessment`, computed at finalisation. Cheap, needs no new field on the
citation itself, and makes the distinction visible without asserting that an
unresolved citation is an error.

**Open.**

## Question C — `reputation#1` is many-to-one

`valid_citation_ids` maps the single `reputation#1` header to **every** VT verdict in
the slice:

```python
if slice_.vt_verdicts:
    ids["reputation#1"] = [v.evidence_id for v in slice_.vt_verdicts if v.evidence_id]
```

and `format_vt_verdicts` (`formatting.py:290-309`) renders all of them under that one
header. So an analyst citing `reputation#1` cites the entire VT set, and
`citation_evidence` faithfully records every VT `Evidence.id` — not the one verdict the
claim actually rests on. The field's own docstring already concedes this: "A list per
citation because one `reputation#1` header covers every VT verdict in a slice."

For SIEM the chain is one-to-one: `auth_events#1` names one `ResultSet` names one
`Evidence`. For VT it is one-to-many, and the precision is lost at the header, below
which nothing downstream can recover it. A verdict that says "the hash is malicious per
`reputation#1`" is grounded in a block that may also contain four clean indicators.

Note also that `format_vt_verdicts` **sorts** by `malicious + suspicious` descending,
so the rendered order is not `slice_.vt_verdicts` order. Any per-verdict scheme based
on rendered position (`reputation#1.3`) would have to mint ids from the sorted list, or
the number the analyst reads would point at a different verdict than the one the code
resolves.

**Question:** is per-verdict citation worth it? Options are one header per indicator
(`reputation#1`, `reputation#2`, …), or a sub-index within the block
(`reputation#1.3`). Both cost header count in the analyst's context window, which
`pack_evidence`'s token budget is already managing.

**Recommendation:** one header per indicator, minted from the sorted order. It matches
the SIEM shape exactly — one header, one evidence id — so `valid_citation_ids` stops
needing a special case, and the `list[str]` value type becomes uniformly single-element.
Indicator counts per slice are small; this is unlikely to strain the budget.

**Open.**

## Decision needed

| # | Question | Recommendation | Reversible? |
| :--- | :--- | :--- | :--- |
| A | Positional or content-addressed `Evidence.id` | Content-address the last hop, keep the dispatch prefix | Expensive — artifacts are joined by these ids |
| B | Make an unresolved-but-valid citation visible | Derived counter on `HypothesisAssessment` | Cheap |
| C | Per-verdict VT citation | One header per indicator, sorted order | Cheap, but changes what the analyst sees |

A is the one that matters. B and C can follow it or be dropped without cost.
