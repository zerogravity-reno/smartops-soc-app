---
date: 2026-08-24
title: Artifact & contract integrity plan executed end to end; all three Evidence Store closure blockers cleared
---

# Handover — 2026-08-24: Artifact & Contract Integrity

Continues `handover_2026-08-24_findings-pipeline-evidence-store-audit.md`.
Branch `task-broker-agent`, HEAD `893f587` (started at `f9bc706`).
`uv run pytest` from the repo root: **645 passed, 0 failed**.

## Pick this up here

1. **The artifact-contract plan is finished.** All four tasks executed and
   committed. Nothing in it is outstanding.
2. **The next thing is a measurement, not a build:** re-run the hypothesis-blind
   vs hypothesis-shown comparison offline against `.smartops/runs/`. See
   *The hypothesis-blind investigation* below for why this is the next step and
   why it is now cheap.
3. **The Asana cards can close.** All three blockers named in the previous
   handover are gone. Details in *Closure blockers, all cleared*.

## What landed

Seven commits. Five are the plan; two are not.

| Commit | What |
| :--- | :--- |
| `430df12` | Task 1a — `EdrAssessment`/`NdrAssessment` in the union, `classification` retyped, `scope` on `BrokerReport` |
| `90b80a2` | Task 1b — `BrokerOutcome.run_dir` carried out, passed into `_persist_assessment` |
| `6f69835` | *(not in the plan)* three session handovers, two plans, the spec, and the `compile_docs.py` output |
| `1e893ea` | Task 2 — callable discriminator; untagged legacy payloads resolve by shape |
| `46feabd` | *(not in the plan)* the Aggregator ownership question, parked for the team |
| `4ccc54b` | Task 3 — `HypothesisAssessment.task_id` required, `run_id` stamped at persist time |
| `893f587` | Task 4 — `evidence_id` back-references, citation-to-evidence map frozen on the verdict |

**The headline number:** `loadable 24  failing 0` against `.smartops/runs/`, up
from `loadable 2  failing 22`. Re-verified after Tasks 3 and 4, not just after
Task 2.

## Closure blockers, all cleared

The previous handover named three reasons not to close the cards. Each is now
resolved, and each was verified by execution rather than by reading the diff:

| Blocker | State |
| :--- | :--- |
| Findings 4–7 uncommitted | Committed in `430df12` + `90b80a2` |
| 22 of 24 saved reports fail to load | All 24 load, and load *correctly* — see below |
| Artifact-linking unstarted | `ResultSet.evidence_id`, `VtVerdict.evidence_id`, `HypothesisAssessment.task_id`/`run_id`, `AnalystVerdict.citation_evidence` all landed |

On the second: "it loaded" is not "it loaded correctly", and a quiet load into
the wrong subclass would look identical. Checked against the raw JSON — 120
payloads resolved to the subclass their keys imply, **zero mis-resolutions**,
with all 7,598 SIEM rows and 22 VT verdicts intact.

Worth recording from that survey: **every payload on disk is untagged** (62
findings, 58 assessments, zero tagged). The two reports that loaded before did
so only because all their results had `findings: null`. The string discriminator
had never successfully read a single real payload — the shape fallback is not a
legacy edge case here, it is the only path the corpus takes.

On the third: the chain was walked end to end offline, no model involved —
projector and collector mint the same id for the same call, `route()` +
`pack_evidence()` yield `{'auth_events#1': ['cli-1:siem:s0:0']}`, `_finalize`
freezes it onto the verdict, and that id resolves back to the raw tool payload
`{'user': 'bostoll'}`.

## Defects found while executing, that the plan did not contain

The plan was written by reading. Executing it found five things:

1. **A latent `NameError` in the work Task 1 said to commit unedited.**
   `BrokerReport.classification` and `.cost` had been given a `default_factory`,
   flipping two *required* fields to optional with placeholder values — the same
   silent degradation findings 4–7 exist to remove. Worse, the `classification`
   lambda closed over `TaskClassification`, imported only under `TYPE_CHECKING`
   to break the `analyst_task` ↔ `subtask` import cycle, so constructing a
   `BrokerReport` without one raised `NameError` rather than a clean
   `ValidationError`. Both defaults removed; both fields required again.
2. **`_resolve_observation_citations` did `cited & valid_ids`** — a `TypeError`
   once `valid_ids` became a mapping. It postdates the plan (added by `f9bc706`
   earlier the same day). Now intersects `.keys()`.
3. **`test_projection.py` needed all 21 projector call sites updated.** The plan
   listed neither the file nor the calls.
4. **A test that kept passing after it stopped testing its own claim.**
   `test_hypothesis_id_is_required` asserts `ValidationError` on an empty
   `hypothesis_id`; once `task_id` became required it raised for the *missing
   task_id* instead. Restored.
5. **`project_vt`'s `VtVerdict(**v)` duplicate-keyword landmine.** The plan
   flagged it and left it documented. Removed instead: the payload is spread
   *over* the default (`VtVerdict(**{"evidence_id": eid, **v})`), so a payload
   carrying its own `evidence_id` wins and the collision cannot occur. Tests
   cover both directions.

Two extras approved during Task 1 went in unproven and are worth knowing about:
the `from __future__ import annotations` removal in `contracts/analyst_task.py`
and `BrokerReport.model_rebuild()` in `contracts/__init__.py`. Each was removed
in turn and the suite passed both times; with `model_rebuild()` deleted pydantic
still resolved the forward ref unaided. Harmless insurance, not load-bearing.

## The hypothesis-blind investigation

Asked mid-session: why are the analyst subagents not running hypothesis-blind?
All four grep-verifiable claims hold — `gather_finding()` has zero production
callers, `analyze()` hardcodes `run_one`, no switch exists, and there is no
Aggregator. **It is dark code on purpose**, and the Tier 1 plan says so in its
own Architecture line: *"purely additive, not wired into `analyze()` yet. The
Aggregator that consumes this new path is a later cycle."* Landing Tier 1 dark
was the mechanism that made it un-regressable.

**There is no switch because a switch would have nowhere to route the output.**
`run_one` returns an `AnalystVerdict` carrying a stance; `gather_finding`
returns a deliberately stance-free `DomainFinding`. The entire point is that an
analyst who cannot see the hypothesis must not decide SUPPORTS/REFUTES, so the
stance has to come from somewhere else. The spec's answer is `aggregate.py`,
whose structured output *is* the `HypothesisAssessment`, deleting `combine()`.
"Wire it in" and "write the Aggregator" are the same task.

**What changed: the queue that was blocking Tier 2 has cleared.** The 2026-08-23
handover ranked it #6 behind five prerequisites. Four have landed — `8512f28`
(EventCode/Logon_Type), `a56b1df` (`_CONFIDENCE_RE`), `b18bf09` (env leak),
`e98b3a7` (budget over-refund). Only #5 is open: analyst spend never enters
`Budget` — confirmed, there is no `Budget` reference anywhere in
`subagent_analysts/`, and that was explicitly flagged as Mohamed's decision.

**But Tier 2's empirical case is currently unproven, and that is the real next
step.** The anchoring-bias demo that justified the whole redesign — blind
analyst reads `auth_events#6` as "password spraying", hypothesis-shown reads it
as "legitimate local logins" — was traced to `_format_auth_event` dropping
`EventCode`/`Logon_Type`. The 2026-08-23 handover's own verdict: *"a code bug,
not proof either analyst reasoned better."* That projector is fixed twice over
now (`8512f28`, `9576a8f`) and **nobody has re-run the comparison**.

It is cheap now in a way it was not before: `1e893ea` made all 24 saved runs
loadable, so the comparison runs offline against real evidence with zero fetch
spend. Do that before anyone commits effort to Tier 2 in either direction.

The ownership question — the Aggregator would delete `combine()`, which belongs
to Mariam's Analyst Agent epic — is parked in `docs/open-questions-for-team.md`
(`46feabd`), deliberately undecided.

## Deliberate trades made this session

- **The 9 existing `assessment.json` files no longer validate** (confirmed:
  loadable 0, failing 9). `HypothesisAssessment.task_id` is required, which
  contradicts the additive-defaults rule its sibling fields follow. Taken
  knowingly: the path is write-only — nothing in the tree ever reads one back —
  and an assessment that cannot name its report is not auditable.
- **`DomainFinding` gains no `citation_evidence`**, per the plan: the Aggregator
  that would consume it does not exist. Note the consequence — the blind path
  has been kept in sync with every hardening pass so far (both `_finalize` and
  `_finalize_finding` call `_resolve_observation_citations`), and this is the
  first deliberate divergence. Each further pass widens it while Tier 1 sits
  dark.

## What to do next, in order

1. **Re-run blind vs shown offline** against `.smartops/runs/`. It settles
   whether Tier 2's premise survives the projector fix, and costs no live spend.
2. **Close the Asana cards** — "Findings Pipeline", "Evidence Store", parent
   "Data Connector", under the SubAgents epic. All three blockers are cleared.
3. **Raise the parked Aggregator ownership question** with Mariam.
4. **Recompile the decision record** after any further session file lands:
   `uv run python docs/compile_docs.py`. Never hand-edit `PROJECT_DOCS.md`.

## Landmines

- **Never stage `backend/src/smartops/bench.py`.** Still `M`, still 20 lines of
  deliberate out-of-scope work. Verified untouched after every commit this
  session.
- **Never delete or rewrite anything under `.smartops/runs/`.** They are the
  fixture the entire audit rests on, and now the fixture for the blind-vs-shown
  re-test too.
- `project_siem` and `_EvidenceCollector.evidence()` must keep enumerating the
  same list — index *i* in one is index *i* in the other, and that alignment is
  the whole basis of `evidence_id`. If they drift, every id points at the wrong
  payload while still looking well-formed. Now pinned by
  `TestEvidenceBackReference::test_the_projector_and_the_collector_mint_the_same_ids`.

## Still open — the previous review's Important tier

Untouched this session, no plan covers them:

- `_parse_citations` splits on commas only, so `CITATIONS: a#1 a#2` yields zero
  valid ids and downgrades a correctly-grounded verdict to `inconclusive`.
- Citation numbering is global rather than per-category, emitting
  `connections#2` with no `connections#1`. Task 4 preserved this deliberately —
  `valid_citation_ids` must mirror `_render` exactly — so fixing it means
  changing both together.
- `combine()` can return a decisive stance at ~0.00 confidence with no floor
  back to `inconclusive`.
- `_EvidenceCollector` records the structured-output call (`SiemAnswer`,
  `VtAnswer`) as `Evidence`, so the store holds model-authored content and a
  citation can point at the model quoting itself.
- `replay.py` cannot read VT evidence from the current enricher path — every VT
  record replays as `None`, silently.

Minor, noticed in passing: `backend/tests/test_projection.py` has `import json`
on line 1, *above* the module docstring, which demotes the docstring to a no-op
string expression. Pre-existing, and `json` appears unused. Left alone.

## Process note

Every defect in the *Defects found while executing* section above was invisible
to the plan's author, who had read the same code carefully. The pattern from the
previous handover held exactly: **for this codebase, running it is the only
review that finds these.** Two of the five were caught only because a
verification step was run that the plan did not ask for — the `NameError` came
from testing whether a `default_factory` actually executes, and the correctness
of the legacy load came from diffing loaded objects against their raw JSON
rather than trusting that no exception meant success.
