---
date: 2026-08-24
title: Findings Pipeline / Evidence Store audited by execution; 7 findings fixed, 3 gaps block closure
---

# Handover — 2026-08-24: Findings Pipeline & Evidence Store

Single continuation document for this work. Branch `task-broker-agent`, HEAD
`f9bc706` (started the session at `072beb8`). `uv run pytest` from the repo
root: **637 passed, 0 failed**.

## Pick this up here

1. Read `docs/superpowers/plans/2026-08-24-artifact-contract-integrity.md`.
2. Execute its **Task 1 on its own** — it commits work that is currently only in
   the working tree, which is the largest standing risk in the repo.
3. Then Tasks 2–4, then the Asana cards can close. Details in
   *What to do next* below.

Do **not** close the Asana cards yet. The session opened by asking whether to
tick "Findings Pipeline", "Evidence Store" and their parent "Data Connector",
and the answer is still no, on the three counts in *Gaps blocking closure*.

## What this session established

Every prior claim that these two subsystems worked had been made by **reading**
the code. Executing them against the 22 real BOTS v3 runs saved under
`.smartops/runs/` found three critical defects that no test caught and no
inspection-based review had found — including one where the analyst was shown
entirely blank rows while the grounding gate still accepted citations to them.

**The lesson worth carrying forward:** for this codebase, "the tests pass" and
"I read the code" are not evidence that a data-handling path works. The saved
run artifacts are the fixture that tells the truth, and they should be the
default way any evidence-path change is validated.

## The seven findings

All seven confirmed by execution. **1–3 are committed; 4–7 are green but
uncommitted.**

| # · Component | Status | Root cause & resolution | Files |
| :--- | :--- | :--- | :--- |
| **1 · Row projectors rendered blank** <br> *(Findings Pipeline)* | **committed `9576a8f`** | Candidate lists used CIM names (`process_name`) while real BOTS v3 rows carry Windows/Stream spellings (`New_Process_Name`, `Creator_Process_Name`, `Account_Name`, `Process_Command_Line`, `cmd_line`, `query{}`) and aggregates (`count`). Measured: 1,648 of 1,887 `processes` rows lost data; ~97% rendered effectively blank. **Critical, not cosmetic** — the header still said `rows=N` and the id stayed in `valid_citation_ids()`, so a fabricated claim citing `processes#1` passed the grounding gate. Added the real spellings, `_count_suffix()`, both byte directions, and a fallback to `_format_generic` when a projector recognises nothing. | `subagent_analysts/formatting.py` <br> `tests/test_analyst_formatting.py` |
| **2 · Evidence fence forgeable** <br> *(Findings Pipeline)* | **committed `9b0ab08`** | Log values could contain newlines and `</evidence>`, closing the fence, placing an instruction outside it, and forging a second block **under a header id already in `valid_citation_ids()`** — so a verdict resting on forged rows cited a resolvable id and passed the gate. Added `_sanitise()` (collapse whitespace, then `guards.escape_untrusted`) in `_first`, `_format_generic`, and the result-set header. | `subagent_analysts/formatting.py` <br> `tests/test_analyst_formatting.py` <br> `tests/test_analyst_prompts.py` |
| **3 · Inline citations unvalidated** <br> *(Findings Pipeline)* | **committed `f9bc706`** | `_finalize` filtered only the trailing `CITATIONS:` line, so `[header_id]` citations inside observations went unchecked — a verdict returned `supports`/0.95 citing `auth_events#7` (nonexistent) and `processes#3` (wrong domain), both reaching the operator and `assessment.json`. Added `_resolve_observation_citations()`: drop observations resting solely on unresolvable ids, strip invented ids from mixed ones, union valid inline ids into the verdict's citations — which also fixes the converse, where a verdict citing correctly inline was downgraded for omitting the `CITATIONS:` line. | `subagent_analysts/analyze.py` <br> `tests/test_analyst_analyze.py` |
| **4 · edr/ndr broken at construction** <br> *(Evidence Store)* | **⚠ UNCOMMITTED** | `DomainSpec.assessment_model` defaulted to bare `Assessment` (no `tool_family`) for edr/ndr, so `SubtaskResult.from_answer()` raised `ValidationError` the moment either subagent returned — surfacing as a generic "subagent failed". A regression introduced by `4461652`; every test passed because nothing covered that path. Added `EdrAssessment`/`NdrAssessment` to the union and to `DomainSpec`. | `contracts/findings.py` <br> `contracts/subtask.py` <br> `smartops/domains.py` <br> `tests/test_domains.py` |
| **5 · `classification` degraded to `dict`** <br> *(Evidence Store)* | **⚠ UNCOMMITTED** | Typed `Any`, so `load_run_artifacts()` returned a plain dict and `main.py:394/397/403` plus `bench.py:580-582` raised `AttributeError`. The same silent degradation the `tool_family` discriminator existed to eliminate, missed on the sibling field. The round-trip test passed only because it exercised `route()`, which never touches `classification`. Retyped to `TaskClassification`. | `contracts/subtask.py` <br> `tests/test_broker.py` |
| **6 · `scope` never persisted** <br> *(Evidence Store)* | **⚠ UNCOMMITTED** | `BrokerReport` carried no `scope`, but `route()` and `analyze()` both require one — a reloaded report structurally could not drive the pipeline the reload path exists to feed. The test masked it by supplying `make_scope()` from its own fixture. Added `scope`, populated at construction. | `contracts/subtask.py` <br> `smartops/broker.py` <br> `tests/test_broker.py` |
| **7 · Assessments filed into the wrong run** <br> *(Evidence Store)* | **⚠ UNCOMMITTED** | `latest.txt` is written at save time but its stamp comes from `report.created_at`, so overlapping runs of one case disagree about which directory is newest. `_persist_assessment()` resolved through that stale pointer and filed run B's assessment into run A's folder — confirmed by execution, and undetectable afterwards because `assessment.json` carries no join key. `BrokerOutcome.run_dir` is now carried out and passed in. | `smartops/broker.py` <br> `smartops/main.py` <br> `tests/test_broker.py` |

## Verification evidence

Each re-confirmed by running it, not by reading the diff:

| Check | Result |
| :--- | :--- |
| `from_answer()` across all four families | siem/edr/vt/ndr all construct; `EdrAssessment`/`NdrAssessment` resolve |
| save → `load_run_artifacts()` round trip | `classification` returns `TaskClassification`; `.tool_families` works |
| `BrokerReport.scope` | present, survives reload, `route(reloaded, reloaded.scope)` → `RoutedEvidence` |
| `BrokerOutcome.run_dir` | present, and `main.py:672` passes it into `_persist_assessment` |
| `uv run pytest` | **637 passed, 0 failed, 6 warnings** |

## Gaps blocking closure

Verified this session; none are in the findings table.

1. **Findings 4–7 are uncommitted.** `broker.py`, `main.py`, `domains.py`,
   `contracts/*` and their tests are modified in the working tree.
2. **22 of the 24 saved reports fail to load.** They predate the `tool_family`
   discriminator, so `load_run_artifacts()` raises `union_tag_not_found`. An
   evidence store that cannot read what it wrote is the hardest thing to defend
   when closing "Evidence Store".
3. **The artifact-linking work is unstarted.** No `ResultSet.evidence_id`, no
   `HypothesisAssessment.task_id`, no `AnalystVerdict.citation_evidence`. A
   stored citation is still a *position* — `connections#23` means "the 23rd
   connections set in this slice" — so it silently re-targets if routing order
   ever changes, and `assessment.json` is joined to `report.json` by nothing but
   its directory path. All nine assessments on disk carry the same hardcoded
   `hypothesis_id: "cli-hypothesis"`.

## Plans

| Plan | State |
| :--- | :--- |
| `docs/superpowers/specs/2026-08-24-analyst-grounding-integrity-design.md` <br> `docs/superpowers/plans/2026-08-24-analyst-grounding-integrity.md` | **complete** — both tasks committed (findings 2 and 3) |
| `docs/superpowers/plans/2026-08-24-artifact-contract-integrity.md` | **written, not started** — 4 tasks, ends at 642 tests |

## What to do next, in order

1. **Task 1 of the artifact-contract plan, alone.** Commits findings 4–7. Costs
   nothing but a diff review and removes the biggest risk in the tree.
2. **Task 2**, then confirm `loadable 24  failing 0` against `.smartops/runs/`.
   That single fact is what moves "Evidence Store" from indefensible to
   closeable. The approach — a callable pydantic `Discriminator` resolving
   untagged legacy payloads by shape — was spiked against pydantic 2.13.4 and
   confirmed working before the plan was written.
3. **Tasks 3 and 4** — the assessment join key, then citations that resolve to
   evidence.
4. **Then close the Asana cards**: "Findings Pipeline", "Evidence Store", parent
   "Data Connector", under the SubAgents epic.
5. **Recompile the decision record**: run `docs/compile_docs.py` so this file
   reaches `PROJECT_DOCS.md`. Never hand-edit `PROJECT_DOCS.md`.

## Unscheduled — the review's Important tier

Found and confirmed, no plan covers them:

- `_parse_citations` splits on commas only, so `CITATIONS: a#1 a#2` yields zero
  valid ids and downgrades a correctly-grounded verdict to `inconclusive`.
- Citation numbering is global rather than per-category, emitting
  `connections#2` with no `connections#1` — hostile to a model the prompts hand
  `connections#1` as the worked example.
- `combine()` can return a decisive stance at ~0.00 confidence with no floor
  back to `inconclusive`.
- `_EvidenceCollector` records the structured-output call (`SiemAnswer`,
  `VtAnswer`) as `Evidence`, so the store holds model-authored content and a
  citation can point at the model quoting itself.
- `replay.py` cannot read VT evidence from the current enricher path — every VT
  record replays as `None`, silently.

## Landmines

- **Never stage `backend/src/smartops/bench.py`.** It carries 20 lines of
  deliberate, pre-existing, out-of-scope work that predates all of this.
- **Never delete or rewrite anything under `.smartops/runs/`.** Those are real
  run artifacts and they are the fixture the whole audit rests on.
- Task 4 Step 5 of the plan says to pass `evidence_id=` into every
  `VtVerdict(...)` in `project_vt`. One of the three is `VtVerdict(**v)`, so if
  a payload dict ever carried `evidence_id` that is a duplicate-keyword error.
  It cannot happen with today's VT payloads; it will fail loudly if it ever does.

## Standing architectural threads

Raised and deliberately left open, not decided:

- **Multi-hypothesis investigations.** Direction set, not designed: the Broker
  *should* see the hypotheses (plural — competing benign/malicious
  explanations), each gets its own end-to-end run, parallel where possible, and
  the domain analysts still never see any hypothesis. This does not contradict
  the recorded decision — `contracts/reasoning.py` excluded hypothesis prose
  *"until a consumer needed them"*, and the Broker is now that consumer. The
  selection-bias risk it introduces is mitigated by the plural itself: fetching
  to *discriminate between* competing explanations forces broader retrieval than
  confirming one.
- **`hypothesis_id` is a dead constant** — `main.py:558` hardcodes
  `"cli-hypothesis"` on every CLI run. Any hypothesis store starts here.
- **`combine()` is pre-built Analyst Agent territory.** It already implements a
  thin version of the Aggregator that the Analyst Agent epic (Mariam's, unbuilt)
  claims as its own responsibility. Worth flagging so it is absorbed or replaced
  deliberately rather than rebuilt blind.
