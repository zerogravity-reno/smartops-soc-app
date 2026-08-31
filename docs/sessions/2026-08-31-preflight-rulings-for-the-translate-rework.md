---
date: 2026-08-31
title: Preflight rulings for the translate rework, and one defect in its own handover
---

Supplement to
`docs/sessions/handover_2026-08-31_subanalysts-translate-not-judge.md`. Read that
first — it is the spec. This file carries only what was decided after it was written,
during the conflict scan that precedes execution. **No code has been written yet.**

## Branch

`prompt-contract`, forked from `task-broker-agent` at **8969785** — Mohammed's call,
to keep the blast radius of a contract-breaking change off the integration branch.
`8969785` is also the MERGE_BASE for the eventual whole-branch review. Baseline
**856 tests passing**.

## The handover's task split does not survive a conflict scan

**R1 — the plan's six tasks become four. T1 + T3 + T4 must be ONE task.**

Removing a required contract field, its only producer, and its three readers is one
atomic breaking change:

- T1 deletes `disposition`/`confidence` from `DomainFinding`/`DomainJudgement`
- T3 (`parse_finding`) is the **only** thing that produces them
- T4 (`main.py:452`, `telemetry.py:217`, `blind_compare.py:824`) are the **only**
  things that read them

Landed as three tasks, the first two each commit a red suite, and each task review
can only see a fragment of a change whose entire point is that the field is gone
everywhere. Execution order:

| | Was | Scope |
|---|---|---|
| **A** | plan T2 | the prompt rewrite |
| **B** | plan T1+T3+T4 | the shape change, atomic |
| **C** | plan T5 | the answer key, rescoped |
| **D** | plan T6 | docs |

The prompt goes **first** so no commit exists in which the prompt asks for a field
the parser has stopped reading. Task B is large (~13 files) and must commit in three
readable stages — contracts, then producers, then consumers — with its final commit
green.

## R7 — the handover is wrong about the packing margin test

The handover says `test_analyst_prompts.py:394-420` pins the per-domain margins
(identity 577 / network 500 / endpoint 590) and **"will fail. That failure is
correct."**

It will not fail. That test asserts `spare >= _SAFETY_MARGIN` — an **inequality**.
`_PACK_TOKEN_BUDGET` is derived from the system-prompt reserve measured at import, so
deleting the judging blocks makes the prompt *shorter*, spare *larger*, and the
assertion *easier* to satisfy. Task A must not touch it, and must not "fix" a
passing test to match a plan sentence.

The 577/500/590 figures live in **docs**, not tests, and are task D's to re-measure.

## The five open decisions, now settled

**R2 — keep `DomainJudgement`'s name** (resolving D-E *against* the handover's own
recommendation to rename it `DomainNarrative`). Mohammed's instruction when opening
this branch was to "mitigate changing too much from the source code"; the rename
touches the contracts export, `analyze.py`, `main.py`, the published schema and every
test naming the type — pure churn against that constraint. The docstring carries the
correction instead. *Cost:* a wire type named "Judgement" that carries none. A
recorded naming smell; v3 is the cheap moment to fix it.

**R3 — D-A: an all-citations-fabricated narrative keeps its narrative.** Append the
existing `[downgraded: no cited evidence resolved]` note and let `observations: []` /
`citations: []` / `exhibits: []` tell the consumer. The narrative is the audit record
of what the model claimed; blanking it destroys the only evidence of a fabrication.

**R4 — D-B: keep the `Disposition` type in contracts**, docstring rewritten as the
vocabulary the Analyst Agent decides in.

**R5 — D-C: `ArmSample.confidence: float | None`**; confidence columns in
`blind_compare` become shown-arm-only.

**R6 — D-D: telemetry replaces the two span attributes with counts** —
`analyst.observation_count`, `analyst.citation_count`, `analyst.narrative_chars`.

## R8 — one declared cross-task file overlap

Renaming `prompts._FINDING_*` to `_NARRATIVE_*` breaks `analyze.py:73`'s import.
**That one import line belongs to task A**; the rest of `analyze.py` is task B's.
`analyze._FINDING_REASK` keeps its own name until task B owns the file. Without this,
task A lands a red suite.

## Conflict scan, for the record

Checked every pair of tasks sharing a file or an interface, and every task against
itself. Beyond R1, R7 and R8 above: T1→T5 is clean (the `Disposition` type survives
per R4); T3→T4 is a chain with no contradiction; T1–T5→T6 is ordering only
(`check_anchors.py` runs after T6). Task-internal checks were consistent in every
case — T1's schema-v2 item already rewrites the `.v1` assertion it would otherwise
break, and T3's `_apply_grounding` item parameterises the shared function rather than
stripping the arm `shown.py` still needs.
