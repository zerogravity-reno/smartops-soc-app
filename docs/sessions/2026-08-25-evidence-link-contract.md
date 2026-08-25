---
date: 2026-08-25
title: The evidence-link contract recorded end to end; three questions on its id shape left open
---

# The evidence-link contract

## Why this exists

The chain that joins a hypothesis to the rows a verdict rests on now runs end to
end, but it was never designed as a whole. It accreted in three pieces across the
2026-08-24 audit's remediation — `893f587` (`ResultSet.evidence_id`,
`VtVerdict.evidence_id`, `AnalystVerdict.citation_evidence`), `4ccc54b`
(`HypothesisAssessment.task_id`), and the enricher-side `evidence_id()` work — each
correct in isolation, none of them written down as a contract.

Full analysis, including the tradeoffs behind the three open questions, is in
`docs/superpowers/specs/2026-08-25-evidence-link-contract-design.md`.

## The chain

```
AnalystTask.hypothesis_id / task_id        (analyst_task.py:35-36)
  → mission.task_id = "{task_id}:{family}:{toolUseId}"     (broker.py:767)
  → Evidence.id = evidence_id(mission.task_id, index)      (subtask.py:56)
  → ResultSet.evidence_id / VtVerdict.evidence_id
  → valid_citation_ids() → header id, e.g. "auth_events#1" (packing.py:63)
  → AnalystVerdict.citation_evidence = {header id: [Evidence.id, ...]}
  → HypothesisAssessment.task_id → BrokerReport.task_id
```

## Settled, and load-bearing

These four properties hold today and should not be changed without a reason
recorded here:

1. **No model authors an id, at any hop.** The same rule `contracts.Evidence` and
   `_EvidenceCollector` enforce for evidence itself — assembled by code, not
   authored by the model — extends to the identifiers. A model may cite an id; it
   can never create one.
2. **`toolUseId` is the broker-dispatch join.** It is the only component that
   separates two dispatches of the same family for the same hypothesis. Remove it
   and a re-dispatch overwrites the first dispatch's evidence ids.
3. **`citation_evidence` freezes the resolution at finalisation.** The grounding
   gate drops fabricated citations at runtime; before `893f587` that decision was
   not recorded, so tracing a stored verdict to its rows meant recomputing the
   routing and trusting it came out identical.
4. **`evidence_id()` is the single formula.** Three consumers must agree exactly or
   a stored `ResultSet.evidence_id` points at nothing.

## Open, pending decision

| # | Question | Reversible? |
| :--- | :--- | :--- |
| A | `Evidence.id`'s last hop is positional (`enumerate` over `collector.calls`) and the whole id is unique per run. Keep per-run uniqueness, or content-address the payload so ids are reproducible and replay becomes an exact lookup? | Expensive — stored artifacts are joined by these ids, and the 22 unloadable reports make it a compounding migration |
| B | `valid_citation_ids()` returns `[]` for sources predating `ResultSet.evidence_id`, and the gate tests key membership — so a citation can be **valid and resolve to nothing**, indistinguishably, in the stored artifact. Surface it, or let the legacy case age out? | Cheap |
| C | `reputation#1` maps to *every* VT verdict in a slice, so a VT citation is one-to-many where SIEM is one-to-one. Per-verdict citation, or accept the precision loss? | Cheap |

**No id-shape code lands until A is answered.** The four bug fixes taken this
session are all independent of it.
