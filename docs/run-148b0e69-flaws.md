# Run 148b0e69: flaws (live baseline on `smartops-loop-fix`, 2026-10-06)

This is the first live investigation on `smartops-loop-fix` (commit `0b80ba7`). It was driven through the real console:
- the alert was queue row 0, "Malicious PowerShell Process - Encoded Command", on `ar-f6eddb5b-df6`, user Mariam;
- the Splunk ES notable was created at 16:04:17 +03:00, and the event itself happened at 11:50:44Z.

The run took 1128s in total:

| Stage | Duration |
|---|---|
| Context | 381s (all 20 OpenCTI lookups timed out) |
| Plan | about 145s |
| Broker | about 590s |
| Synthesis | about 10s |

**Result.** The verdict was BENIGN at 95%, with scores H1 25, H2 35 and H3 90. The gate passed it, and there was one broker round. The handshake held: 5 sent, 5 fetched, 5 returned.

**Real broker spend.** It was **$2.87** (the budget went from $50.00 to $47.13). The console showed $7.65, which is wrong; see flaw W1.

**Trace.** `docs/trace_148b0e69.html` (standalone; open it in a browser).

## Fixed and confirmed on this run
- **Event time.** Every task window is anchored at 11:50:44Z, the event's time, not the notable's time. On run 600721d3 the windows were 74 minutes late.
- **T1 finds the alert's own process.** It now returns the alert's own `powershell.exe` starts at 11:50:44 and 11:50:45, with the `$env:username` decode. On 600721d3 it found only the forwarder's `splunk-powershell.exe`.
- **Alert facts.** The import carries the command line, parent process, SHA256 and integrity level into the context.

## Broker (our scope)
1. **The download and the ping sweep never reach synthesis.**
   - What the rows hold: T1 (4 rows), T2 (12), T4 (2) and T5 (10) all contain `Invoke-WebRequest -Uri http://192.168.40.211/update/win-agent-2.4.1.bin -OutFile %TEMP%\svcupdate.dat`. They also contain the `Test-Connection` sweep of 10.0.10.1, 192.168.40.211 and 192.168.40.212.
   - What the narratives say: no narrative names the download. T2 says only "network reachability tests".
   - **Fix:** a code-written block of distinct command lines (script interpreters and LOLBins, rarest first, capped), next to `ENCODED_FOOTER` in `subagent_analysts/analyze.py`.
2. **Narratives contradict their rows (the narrative itself is never gated).**
   - **T1, times:** it states 11:50:44–45 and also "(These rows carry no time)".
   - **T1, counts:** "6 process starts … Four had the parent powershell.exe … Another two … OneDrive.exe", while the code line says the decoded command has parent OneDrive.exe=3 and powershell.exe=3.
   - **T3:** "11 process starts … Eight from OneDrive.exe, two from powershell.exe, one missing; four encoded, eight standard". 4 + 8 is 12, not 11.
   - **T2 network:** times stated alongside "These rows carry no time".
   - **T5 endpoint:** the narrative is cut off mid-sentence ("conhost.exe occurred 3 times … (6 events.").
3. **T1's observations repeat.** Eight identical lines read "Process powershell.exe started with encoded command on host AR-F6EDDB5B-DF6 …". Nothing dedupes observations.
4. **File writes land in "uncategorised", and synthesis missed them.**
   - T3 reports "wrote 2 temporary script files to C:\Users\Mariam\AppData\Local\Temp\4\" from uncategorised rows.
   - Sysmon 11 rows (`TargetFilename`) are present in T2 and T4.
   - There is no file-events category, and synthesis says "no file writes … were observed".
5. **Scope and `index=*` blocks wasted turns.** T3 had 26 blocked queries and was the most expensive task at $1.31; T5 had 16. Most were `index=*`, or `tstats` with no scope term.
6. **VT.**
   - T2's VT step was rejected because the scope held only `process`.
   - T4's VT did run, but on the SHA256 of `powershell.exe` itself: clean, 71 harmless. That result says nothing about the command, yet synthesis used it as "the encoded command hash has no malware detections" (see A2).
7. **The payload is over budget:** 20,913 characters against the 20,745 budget.

## Webapp (our scope)
- **W1. The spend total is wrong.**
  - `spend_micro_usd` on each broker run is the batch's running total (T5's 2,874,110 equals the whole batch), not that task's cost.
  - The console rail adds them up, so it showed $7.65 instead of $2.87.
  - The same bug put 600721d3 at "$5.47". The "T5 cost $2.23" line in `handover-2026-10-06-late.md` was a running total too.
  - The per-task spend is in the log's `spend by task` line: T1 $0.12, T2 $0.49, T3 $1.31, T4 $0.18, T5 $0.77.
  - **Fix:** take the per-task figures in `run_trace.broker_runs`, or difference the running totals.
- **W2. The PID was sent as a process name.** T3's entity was `process=2900`; the plan put a PID in the process field.
  - The broker did search `ProcessId=2900` and `0xB54`, but those queries also used `index=*` and were blocked.
  - **Proposed:** a `process_id` kind would need an `EntityKind` addition. Ask first.

## Analyst (write up for the owner; do not edit `system_prompt.txt`, the `eval_header` or the synthesis schema)
- **A1. The synthesis contradicts the findings it was given.**
  - It says "No secondary indicators … like network connections, file writes".
  - But T3 reports file writes to `Temp\4\`, T5 reports 3 connections to 192.168.40.211:8888, and T2 reports the reachability tests.
  - It also cites "documented OneDrive sync behavior", which appears in no evidence.
  - The verdict needs review against the rows.
- **A2. T4's premise is wrong.** The task asks about "the encoded command hash", but `process_hash` is the hash of the `powershell.exe` image. A clean VirusTotal result for `powershell.exe` was then used as evidence about the command.
- **A3. T5 can't be answered from the SIEM.** "Did any users report unusual activity …": the broker fetched Mariam's logons and processes instead.
- **A4. Two windows run into the future:** T4 ends 2026-10-07 23:59Z and T5 ends 2026-10-07 17:00Z.
- **A5. `evidence_refs` are invented labels** (`T4:hash_1C84…_no_malware_detections_high_harmlessness_score`). They pass `verdict_gate`, which accepts any string not starting with `ALERT:` (`webapp/services/run_trace.py`).
- **A6. No follow-up tasks, so one round only.** This is unchanged since `330d1bc`.

## Console (live check)
The new console ran the whole live stream with no page errors. The stage lines, task board and verdict all filled in correctly. The only wrong number was spend (W1).

## Infrastructure
- **OpenCTI:** `.env` points at an address that times out. 20 lookups at 2×10s each made context building take 381s, a third of the run.
