# Handover: broker fixes from run 148b0e69 (2026-10-06 close)

**Start here in a new session.** This replaces `docs/handover-2026-10-06-night.md`. That one is still the reference for run 148b0e69 and its flaws (`docs/run-148b0e69-flaws.md`).

## Current state
- **Branch:** `smartops-loop-fix`.
  - Pushed: `786a32f`.
  - Local, unpushed: `ea99a6b` and `0b80ba7`, the console commits.
- **This session's fixes are uncommitted:** 22 files, +314 −120.
- **Tests:** `uv run pytest -q engine/contracts engine/tests tests` gives **1181 passed** (it was 1176).
- **No new live baseline yet.**
  - The live run was started on :8013, but Claude Code stopped both the server and the Playwright driver because the machine ran low on memory. The run was still building context, so nothing reached the broker and no run folder was written.
  - Queue row 0 is now a **different alert**: a RunOnce registry autostart (`msedge_cleanup_{…}`, T1547.001, user SYSTEM, event 18:41:51Z). It is no longer the encoded-PowerShell alert behind 148b0e69.

## Decisions taken this session (Mohammed)
- **OpenCTI:** ignored for now; it works on a teammate's setup.
- **File events:** include everything Splunk can fetch: file writes, PowerShell script blocks and registry.
- **The model calculates nothing; code does.** Saved to memory as `no-model-arithmetic`.
  - A Strands calculator tool does not fit. It ships in `strands-agents-tools`, which is not installed, and the sub-analysts are single-shot calls that cannot call tools.
- **VT:** the alert hash goes into every task's scope, and the Broker (an LLM) decides whether to use VT.

## What changed (each item maps to the 148b0e69 flaw it fixes)
1. **W1, spend** (`broker.py`, `_run_broker_task`).
   - `total_spend_micro_usd` is now this task's own spend (`budget.spend_by_task()[task_id]`). Before, it was the batch's running total.
   - The console's sum is then correct with no UI change.
   - Test: `test_each_report_carries_its_own_spend_not_the_batchs`.
2. **Broker 1, command lines** (`tools/native/decoder.py` `commands_in`, `subagent_analysts/analyze.py` `_as_judgement`).
   - Interpreter and LOLBin command lines from the rows, rarest first. Capped at 8 lines of up to 400 characters each.
   - Lines already covered by the encoded-command block are skipped. The command line is also read from `_raw` Sysmon XML (T4's case).
   - It is sent as the **first summary**, not a narrative footer, so the payload budget can trim it. The first summary is the last one cut.
3. **Broker 3, duplicate observations.** Removed in `_finalize_finding`.
4. **Broker 4, new categories.**
   - `file_events` covers Endpoint.Filesystem, Sysmon 11/23/26 and `TargetFilename`.
   - `registry_events` covers Endpoint.Registry, Sysmon 12/13/14 and `TargetObject`.
   - `script_blocks` covers 4104 and `ScriptBlockText`.
   - All three route to endpoint and each has its own formatter.
   - Contract: `CimCategory` and `SiemFindings`. The `hypothesis-findings.v2` schema was regenerated; the change is additive.
   - `_CIM_BUCKETS`, `SiemFindings.total_rows` and `bench` now derive their lists from `CimCategory` instead of keeping copies.
5. **Broker 2, narratives inventing figures** (`subagent_analysts/prompts.py`).
   - The prompts asked for counts and times, so the model did arithmetic (T3's 4 + 8 = 11). Narratives now carry no numbers or times.
   - Observations may only copy a figure printed in a header or computed summary; `_drop_unsupported_figures` already enforces this.
   - Worked examples and closing instructions no longer contain count or time slots.
   - **Correction to the flaws doc:** T5's narrative was not cut off. The model wrote "(6 events." without closing the bracket, and the text continues after it. No truncation flag was added.
6. **Broker 7, payload.** The command block now sits in the trimmable summaries.
   - Deleted the unreachable copy of `pack_for_analyst` that followed `return` in `HypothesisFindings.for_analyst`.
   - Not re-measured live yet.
7. **Broker 6 + W2, task scope** (`webapp/services/run_trace.py`).
   - Every task gets the alert's host and SHA256, parsed from Sysmon's `MD5=…,SHA256=…`, when it lacks them.
   - An all-digit `process` becomes the new `process_id` `EntityKind`. The siem prompt explains decimal `ProcessId` vs hex `New_Process_ID`. The `task-input.v1` schema was regenerated; the change is additive.

**Offline check**, re-projecting 148b0e69's saved evidence with the new code:
- The download line now reaches T1, T2, T4 and T5.
- The `Test-Connection` sweep reaches T2, T4 and T5.
- T3's three Sysmon 11 rows land in `file_events` instead of `uncategorised`.

The script is `$CLAUDE_JOB_DIR/tmp/offline_check.py` (scratch, not kept).

**Analyst write-up:** A1–A6 were added as section 6 of `docs/analyst-handoff-2026-10-06.md`, and that doc's entity list now includes `process_id`.

## Next
1. **Run the live baseline** once memory allows:
   - `uv run uvicorn webapp.main:app --host 127.0.0.1 --port 8013`
   - `uv run --with playwright python live.py <outdir>`. The driver clicks queue row 0; to compare with 148b0e69, pick the encoded-PowerShell alert instead.
   - Record the flaws in `docs/run-<id>-flaws.md`.
2. **Check on that run:**
   - the rail's spend equals the log's `spend by task` total;
   - the command block reaches synthesis;
   - registry and file rows are categorised;
   - narratives carry no figures;
   - the payload stays within its character budget;
   - VT steps appear where the hash is in scope.
3. **Watch:** blocked `index=*` queries. With the host now always in scope, T3-style counts should drop.
