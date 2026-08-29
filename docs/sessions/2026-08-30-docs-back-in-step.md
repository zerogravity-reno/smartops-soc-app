---
date: 2026-08-30
title: The docs describe the code again, and 6.9MB left the tracked tree
---

Closes the item `handover_2026-08-29_verdict-reproducibility-and-schema.md` opened as
**"Do this first"**. Two commits, `3bc33a6` and `46ad14f`. 782 tests passing, 82
anchors verified, 0 stale.

## architecture.md was describing deleted code

Its §7 documented `combine()` rolling three verdicts into a `HypothesisAssessment` as
the live endpoint. `f49cb8a` deleted that path the day before. Both diagrams
terminated there, and the data-flow walkthrough ended on an overall stance the
pipeline no longer produces.

Corrected end to end. The substantive changes, beyond renaming:

- **§7 is now the Analyst Agent boundary.** What crosses (`DomainJudgement` +
  `Exhibit`), what is dropped and why — `reasoning_trace` is "persisted for audit,
  never re-fed", and putting a model's chain of thought into a contract handed to
  another model is exactly re-feeding it — and that **the absence of a combiner is
  the contract**, not a gap.
- **New §8, "Trace chain: `evidence_id` → `hypothesis_id`."** The chain was only
  documented in a companion page, never in the overview, despite being what makes a
  verdict auditable. Shows the three-file join and names all four minting sites that
  must agree.
- **§5 records why the wire format is labelled text, not JSON.** This model has no
  structured-output or tool-calling support, so there is no constrained decoding to
  lean on — and labelled text degrades gracefully where JSON fails atomically.
- **§12 gained three limits that were real and unwritten:** no answer key, the
  grounding gate's claim-vs-row blind spot, and no OTEL spans on the analyst path.

## The anchor checker earned its keep

`docs/check_anchors.py` found **23 stale `file:line` anchors**, every one caused by
the previous day's refactor shifting lines in `analyze.py`, `packing.py` and
`main.py`. Nobody would have found these by reading.

Repointed **symbol-aware** — each symbol's true line resolved by parsing the source
AST — rather than by replacing numbers, because the same figures appear in unrelated
table cells nearby.

`combine()`'s two anchors could not be repointed: the function is gone. Its open item
§10.6 ("no confidence floor") is therefore **closed by deletion**, and now says so.
The defect cannot recur in a repository that contains no combiner.

## Decluttering: order mattered

`docs/blind-vs-shown-*.{json,md}` were untracked and look identical in kind to the
disposable dumps beside them. **They are evidence** — quoted in
`handover_2026-08-25_blind-vs-shown-remeasured.md:109,122`. A blanket `docs/*.json`
ignore would have orphaned a handover's own numbers. They were tracked *first*, and
the ignore patterns written narrowly around them.

Then: `graphify-out/` (12MB) ignored; ~6.9MB of diagram PNGs untracked in favour of
the 11–13KB SVGs of the same diagrams already beside them (both stay on disk — the
confluence pages document PNG as the paste deliverable); four orphaned
benchmark/report artifacts untracked. **Tracked `docs/` went 8.8M → 1.9M.**

`git rm --cached` does not shrink `.git` — those bytes remain in history. Reclaiming
them needs `git filter-repo`, which rewrites history and needs team coordination.
Deliberately not done.

Three superseded documents moved to `docs/archive/` with a manifest
(`agent_architecture.md`, `broker_agent_architecture.md`, `agy-skddles-handover.md` —
the last of which describes `broker_flat.py`, verified absent from source). Archived
rather than deleted: a superseded document still explains why a decision was made,
and that is the part git history reads poorly.

## Still open

Unchanged from yesterday's handover, which remains the fuller list:

- **No answer key** — the highest-leverage next work. Verdicts are consistent; nothing
  shows them correct.
- **Cold-start determinism unproven.** 8 warm draws identical, 1 cold draw differed.
  Needs a deliberate >5-minute idle wait to reproduce.
- **`SMARTOPS_ANALYST_CMU_COUNT` unset**, so the cost line prints "cost unknown".
- **The eval harness is not built.** `blind_compare.ArmStats` still lacks disposition
  agreement and confidence spread.
- **Correction to yesterday's note:** the four probe scripts in `scratchpad/` are on
  disk but **untracked** — `scratchpad/` has never been committed. They survive a
  session, not a clone. Committing them is part of the eval-harness work.
