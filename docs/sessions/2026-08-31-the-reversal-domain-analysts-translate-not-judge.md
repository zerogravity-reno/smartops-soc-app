---
date: 2026-08-31
title: "REVERSAL: the three domain analysts translate evidence, they do not judge it"
---

# The Reversal — Domain Analysts Translate, Not Judge

**Branch `prompt-contract` at `a79a2c3`, 862 tests passing**, tree clean, 0 stale doc anchors.
Code work is complete. This session documents the architectural reversal explicitly.

## What reversed

The 2026-08-23 hypothesis-blind design gave the three domain analysts (identity/network/endpoint)
a deliberate, *reduced* mandate: they read evidence and reported only `Disposition` (benign /
suspicious / malicious / inconclusive), explicitly *not* `Stance` (supports / refutes), on the
reasoning that "blind does not mean silent — the analyst still judges." The division of labor was:
analysts judge evidence; the Analyst Agent (separate component) judges the hypothesis.

**That line moved, and significantly.** Mohammed's 2026-08-30/31 architectural call: the tier
judges nothing. It translates — converts ~170 rows per domain into plain-English prose that
names the hosts, accounts, addresses, processes and times involved, groups like rows, gives
counts and time ranges, and says what happened. It produces a `narrative` plus `observations`
(one distinct thing each row shows) and `citations` (which rows prove it). **The Analyst Agent
decides verdicts: did these rows mean the host was compromised, the connection was malicious,
the account was abused?**

This reversal dissolves four specific things the old design asked the tier to do:

1. **The `Disposition` field** on `DomainFinding` / `DomainJudgement`. Deleted.
2. **The `confidence` field.** Deleted. No verdict means no referent.
3. **"Identify every security-relevant finding"** in the prompts — a relevance filter. Deleted.
4. **"WHAT TO LOOK FOR"** (beaconing, DNS tunneling, brute force, etc.) — a detection checklist.
   Deleted. Telling a translator which patterns matter is asking it to assess them.

The defect that made this reversal urgent: an old template had two forms: the first-ask for
initial findings, and a re-ask to fill missing blocks. The re-ask accidentally omitted the
`DISPOSITION:` label, so a model obeying the form could only ever land `inconclusive` — it
defaulted to that when the field was missing. Fixing that required stopping asking for a
disposition at all, because a field with no meaning has nothing to ask for.

## What replaces it

The tier compresses ~170 rows per domain into prose that fits the consumer's context budget,
every claim is citation-checked by the grounding gate, and three domains run concurrently.

- **Compression:** a live network slice on 2026-08-30 was 46 `dns_resolutions` + 124
  `connections` rows. Those cannot be recounted line-by-line inside a 3,072-token budget. The old
  prompt resolved that by *selecting* ("report every security-relevant pattern") — a relevance
  judgement, the thing we just stopped. The replacement is aggregation: "Group like rows and
  describe the group. Give counts, distinct values, time ranges and the shape of any repetition.
  Host ABUNGST-L opened 124 connections to 12 distinct destinations between 03:14 and 04:02; 46
  of them went to 45.77.53.176 at roughly 60-second intervals" accounts for every row without
  picking a winner.

- **Citation integrity:** the grounding gate checks that every claim rests on valid citations —
  ids that code actually emitted when rendering evidence. A claim with zero valid citations is
  flagged.

- **Concurrency:** the three analysts run in parallel via `asyncio.gather(asyncio.to_thread)`,
  so wall-clock cost is one analyst instead of three. Wall-clock cost is the billing metric
  (Bedrock's Custom Model Unit charges per minute, not per token).

**If that stops being true, the tier is a pass-through.** If compression degrades to selecting,
citation checking fails, or the Analyst Agent absorbs the concurrency anyway (e.g., by calling
them sequentially on its side), then this tier no longer buys anything, and its existence is a
pure compliance layer.

## What is now load-bearing

- **`RetrievalSummary`** is now the **only signal** separating "we looked and found nothing" from
  "we did not look." When a domain gets no evidence, the analysts return an empty narrative and no
  observations — they never make a model call, so there is nothing distinguishing the two cases
  from the fact of an empty message. That field (which carries what the fetch tier looked for, and
  what it turned up per category) is what tells the consumer which case it was. It existed for
  precisely this reason; this change makes it essential rather than supplementary.

  **Live evidence (2026-08-31 run with Splunk unreachable):** a run produced empty narratives for
  identity and endpoint while `RetrievalSummary` recorded `completed: false, rows_retrieved: 0`
  for all three SIEM steps. That distinction worked in practice — an empty narrative means "we
  did not look", proved by the retrieval summary. Without `RetrievalSummary`, the consumer could
  not tell it apart from actual negative evidence ("we looked and found nothing").

- **The evidence fence integrity.** The previous design accepted the grounding gate's citation
  checking as sufficient guard against injection. This design makes that mechanism critical —
  without it, a narrative could claim things the evidence never showed. The sanitisation that
  prevents fence injection (`&`, `<`, `>` escaped; whitespace collapsed) becomes the
  fail-safe, not an implementation detail.

## How `HypothesisFindings` changed

**Old shape (v1.0):**
```
DomainJudgement:
  domain, disposition, confidence, rationale,
  observations, citations, exhibits
```

**New shape (v2.0):**
```
DomainJudgement:
  domain, narrative, observations, citations, exhibits
```

Dropped: `disposition`, `confidence`. Renamed: `rationale` → `narrative` (explicitly a translation,
not a reading of what the evidence means).

Per-domain spare token margins (the headroom left over after packing evidence): changed because
the system prompt shrank when the judging blocks were deleted. Network is pinned at exactly
`_SAFETY_MARGIN` by construction; when the reserve decreased, the pack budget grew for everyone,
but identity and endpoint did not shrink equally, so their margins *changed* asymmetrically.
- Identity: 577 → 601 (+24)
- Network: 500 → 500 (±0, pinned)
- Endpoint: 590 → 575 (−15)

The mechanism: `_PACK_TOKEN_BUDGET` is derived from the 32,768-token context window minus named
reserves. One of those reserves is `_SYSTEM_PROMPT_RESERVE`, the max spare bytes across all three
domain system prompts, measured at import. When a prompt shrank, that max shrunk, the pack budget
grew, and the margin allocation rebalanced. Endpoint did not shrink as much as the overall reserve,
so it lost margin to growth elsewhere.

## What the schema version meant

**v1** carried the design in which the tier judges and the Analyst Agent filters its verdict by
hypothesis. This was never deployed; the hypothesis-blind design changed the premise on day one,
but the v1 schema sat on disk as if it matched the code.

**v2** reflects the translator design: the tier produces prose, not a verdict. v1 is kept on disk
for replay of old runs; v2 is the current wire. The published schema file is enforced by a
test assertion: `hypothesis-findings.v2.schema.json` must match the models in `contracts/reasoning.py`,
or a consumer reading it gets wrong guidance authoritatively, which is worse than publishing none.

## What the answer key now means

`bench.py:EXPECTED_CITATIONS` (was `EXPECTED_DISPOSITIONS`) maps BOTSv3 cases to the evidence
categories the narrative *must cite* to have seen the row proving the documented fact.

- `botsv3_coinhive` → network must cite `dns_resolutions` (to have seen the coinhive.com query)
- `botsv3_c2_beacon` → network must cite `connections` (to have seen the beacon interval)
- `botsv3_hdoor_tool` → endpoint must cite `reputation` OR `processes` (to have seen the hash or the execution)

This metric gets *stronger* under pure translation: a translator instructed to "account for
every set" should cite every set it was shown. Citation coverage becomes a fair test of whether
it did its job rather than a proxy for a verdict.

Only 3 of 11 cases are labelled; the rest remain unscored until the decision record can cite
what BOTSv3 documents about them.

## What stays the same

- **Grounding gate:** code validates citations; invented ids are dropped.
- **Cross-domain guardrails:** the prompts still forbid inferring across domains (identity does
  not infer network behavior, network does not assert our host acted on a reputation verdict).
- **Empty-slice short-circuit:** a domain with no evidence makes no model call, so there is no
  wasted token or false confidence.
- **Bounded re-ask:** one unparseable reply earns one more attempt; both are billed.
- **`shown.py` on disk:** the hypothesis-shown arm is not deleted because it is how we measured
  whether blindness worked — `blind_compare` runs both and compares. It still uses the old
  design (it has a verdict) and still exports `AnalystVerdict` with `Stance`. That is
  deliberate; the A/B harness is the evidence the blindness rests on.

## Process note

This reversal was in the decision record 2026-08-23, but as a design that the code never
implemented. The code landed on 2026-08-30 (discovering it was wrong via a production run), and the
architectural reversal was spoken by Mohammed the same day. This session documents what was built,
not what the prior record said would be built — and that is Jasper's job.

No architectural question raised here is open. The four decisions made (R2–R6 in the preflight
rulings) settled every decision-point the handover listed. The next edge case that surfaces will
likely require a decision, but this reversal is architecturally clean: the tier judges nothing, the
Analyst Agent decides verdicts, the contract is narrower and clearer for it.
