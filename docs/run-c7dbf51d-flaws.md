# Run c7dbf51d: broker flaws (2026-10-07, uncommitted close-of-10-06 fixes)

**Alert.** Queue row 0: a RunOnce autostart, `msedge_cleanup_{56EB18F8-…}`, PID 220, user SYSTEM, event at 18:41:51Z.
**Run.** One broker round with 5 tasks, all fetched and none failed.
**Real broker spend.** $2.36: the budget went from 50.00M to 47,641,119 micro-USD.
**Files.** `.smartops/runs/c7dbf51d*`.

## Close-of-10-06 checklist
| Check | Result |
|---|---|
| Rail spend equals the log's `spend by task` | **No.** See F1. |
| Command block reaches synthesis | **No.** It is built (T4, T5 `findings.json`) but cut from the payload. See F2. |
| Registry and file rows categorised | **Yes.** `registry_events` and `file_events` are populated in T1–T5. |
| Narratives carry no figures | **No.** See F4. |
| Payload within its character budget | **No.** 28,564 against 20,745. See F2. |
| VT where the hash is in scope | Not tested. A Sysmon 13 alert has no hash, so no task had `file_hash`. See F6. |

## Flaws
1. **F1: the W1 fix undercounts spend** (`broker.py:1411`).
   - `spend_by_task().get(task.task_id)` returns only the broker's own planning entry.
   - Subagent missions are keyed `<task_id>:siem:tooluse_…`, so they are missed.
   - For T1 the report carries 43,735; the true figure is 607,858.
   - Reports sum to $0.20 against the real $2.36.
   - `main._task_spend` already sums by prefix and is the correct version. The unit test passed because its spend is keyed on the bare task id.
2. **F2: every summary is cut, and the payload exceeds its budget** (`contracts/reasoning.py` `pack_for_analyst`).
   - Narratives plus observations alone are about 25.9k characters against `HANDOFF_CHAR_BUDGET` of 20,745.
   - `remaining` therefore clamps to 0, and all 15 domains send only "… N set summaries omitted".
   - "The first summary is the last cut" does not hold once the fixed part overflows. Nothing caps or reports the overflow.
3. **F3: T1's observations are a degeneration loop.**
   - One 2,758-character observation repeats ", , , , , , had no matching events." until it is cut off.
   - Nothing detects or flags the loop. On its own it takes about 13% of the budget.
4. **F4: narratives still contain figures and times.** The prompt-only fix did not hold.
   - T1: "six instances … between 18:42:05Z and 18:42:09Z".
   - T2: "14 events", "zero rows".
   - T3: "eight times each".
   - T4: "28169".
   - **T5 contradicts itself.** It says Mariam ran setup.exe "four times", then "1 under Mariam". It also says "18 / 11 / 2 / 1 events" while the names footer says 16 / 10 / 2.
   - `_drop_unsupported_figures` gates observations only, never the narrative.
5. **F5: identical result sets are counted more than once.**
   - Retries such as `summariesonly=t`/`=f` and `index=a OR b` vs `index=a` return byte-identical rows, and each becomes its own set.
   - T3's file rows appear 3 times (59 rows each). The classification therefore reports "178 file events" for 60 distinct rows.
   - Totals by task: T2 12 sets, 8 distinct. T3 29 sets, 22 distinct. T4 13 sets, 11 distinct. T5 12 sets, 11 distinct.
6. **F6: a VT step is planned with no observable to look up** (T2).
   - The broker planned `vt_hash_reputation` alongside the SIEM step that would find the hash.
   - Steps cannot hand an observable to a later step, so the VT step was rejected: "scope has ['host','user']". The spend on it was wasted.
7. **F7: the status contradicts itself** (T1 `process_and_parent_lookup`).
   - The subagent result is `no_data`, but it carries 74 rows, and retrieval lists the step as `complete`.
   - The 74 rows are fallback scans, not PID 220.
8. **F8: the empty-set citations are noise.**
   - T1 cites 26 zero-row sets and T2 cites 4 `file_events` sets as "contained no rows".
   - The code logs a warning and keeps them. That is by design, but in volume they crowd out real observations.
9. **F9: smaller issues.**
   - The log header says "15 analyst calls"; 10 were made, because empty domains are skipped.
   - The T1 siem agent probed 6 other indexes (`botsv3`, `win`, `main`, `osquery`, `security_log`, `unix`), which cost $0.45 of T1's $0.61.

## Out of broker scope (webapp side, noted only)
- **T1's window starts at the event (18:41:51) and runs 60s.** The writing process (setup.exe) started earlier, so "what was the parent" cannot be answered inside that window.
- **T4's window is 48h ending in the future** (Oct 7 18:41Z), though the task asked for "last 24 hours".
- **The import maps the registry path into `process.process_name`.** `process_guid` is present but never reaches scope.
- **One broker round: the verdict gate passed on references it never checked** (`run_trace.verdict_gate`).
  - Synthesis scored H2 90 and H3 60. The gap is 30, so the score test passed and the loop stopped correctly.
  - The evidence test only checks that `evidence_refs` holds a string not starting with `ALERT:`. The refs were `T1:registry_events#2`, `T2:registry_value_data` and `T3:user`. None is the `<task_id>:<domain>` the prompt asks for.
  - `T2:registry_value_data` is the planner's own entity: the setup.exe path, which `to_task_file` dropped from T2's scope.
  - The reasoning says T2 "verified the executable as a known Edge installer". No hash was ever retrieved, and the VT step was rejected (F6).

## Status (2026-10-07, uncommitted)
F1–F5 are fixed. Plan: `~/.claude/plans/witty-bouncing-toucan.md`.
- **F1:** `Budget.spend_for_task` replaces `main._task_spend`.
- **F3:** a `length` stop is re-asked.
- **F5:** `route()` routes identical rows once.
- **F2:** the command lines are a narrative footer, and observations give way when narratives fill the budget.
- **F4:** narrative sentences with a figure or time found in no block are dropped.

**Offline re-projection of this run:**
- command footers are in T4 and T5 endpoint;
- T5's "11 under SYSTEM" sentence is dropped;
- the batch is 21,180 characters against 20,745. The packer measures per payload; the overflow is the batch wrapper's nesting, as its `ponytail:` note says.

F3 needs a live run to confirm.
