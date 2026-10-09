# Tool Broker fixes: timesheet (2026-09-29 → 2026-10-09)

**What this measures.** Time spent in Claude Code sessions on this repo, read from the session transcripts' message timestamps (local time, +03:00). A session's *active* time sums the gaps between consecutive messages and leaves out any gap longer than a cutoff:
- **45-min cutoff (used for the totals):** counts waits on live runs and reviews, which often go 20–40 minutes without a message.
- **15-min cutoff (lower bound):** counts only continuous back-and-forth.

**What it doesn't measure:** time spent outside Claude Code (reading traces in a browser, Splunk, talking to teammates). Parallel sessions are counted separately, so overlapping hours add up. The Broker share of each session and the split across items are judged from that session's handover and commits; they're estimates, not timers.

## Totals

| | Hours |
|---|---|
| All sessions on this repo, 09-29 → 10-09 (45-min cutoff, UI worker session excluded) | 37.1 |
| Of which Broker and sub-analyst work | **≈ 25.7** |
| Lower bound for the Broker work (15-min cutoff) | ≈ 18 |

The rest went to the Analyst port and main integration, the webapp loop (T17, W8), the console UI, and the handovers themselves. The UI worker session (`4ca714f1`, 1.7 h) is left out.

## By item

Hours are the item's share of each session's Broker time (45-min cutoff). "Rework" means the item was fixed, then fixed again after a live run showed the first fix didn't hold.

| Item | What | Hours | Sessions | Commits | Live runs | Rework |
|---|---|---|---|---|---|---|
| W2, W3, W4 | Stale run fed to the Analyst; tasks as rejected kinds; hardcoded siem stub | 1.5 | 09-29/30, 09-30 eve | `58d39c3` | SOC3 (before), `cecd266a` | — |
| B4 + time pin | `+03:00` misread; `TimeWindowPin` so every siem call is time-bounded | 1.5 | 09-29/30, 09-30 eve | `58d39c3` | `cecd266a`, `072fd610` | — |
| B3 | Steps planned for families with no tool | 0.4 | 09-30 eve | `58d39c3` | `072fd610` | — |
| B7 | Unconnected families named to the models | 1.4 | 09-30 eve → 10-01, 10-01 eve | `959c6da` | `04a15495`, `a8118db9`, `check-T3` | — |
| B8 | `tstats` non-CIM fields and the dead-end guard | 1.9 | 09-29/30, 10-01, 10-01 eve | `959c6da` | `072fd610` repeats | ladder (09-30), then guard rework (10-01) |
| K1 | $5–12 per Broker loop: offload oversized results | 1.0 | 10-05 am | `0e82b4c` | `072fd610-L2-T3` | — |
| Guard fixes | Guards scanning the subagent's own answer; `--scripted` families; out-of-turns prompt | 0.2 | 10-05 am | `5e5120c`, `9dd2fea`, `17406df` | — | — |
| B1 | Parent path lost: projection, tstats sets, rarest values, siem prompt, summaries crossing, name lines | 3.1 | 10-05 am, 10-05 midday, 10-05 pm, 10-05 eve | `0964e3a`, `616b27c`, `b64c575`, `1cda901`, `e475a84`, `b50273c` | `check-B1`…`B1d`, `ded5cac1`, `e1461da6` | B1b and B1c prompt edits tried and reverted, then summaries (B1d) and name lines (B1c) |
| B9, B9a | Handoff size budget; one budget per batch | 1.1 | 10-05 pm, 10-05 eve | `e475a84`, `4d27092` | `ded5cac1`, `e1461da6` | per-task split → batch water-fill |
| O1, O3 | Context saved with the run; Broker log streamed to disk | 0.3 | 10-05 pm | `c85eb93` | `ded5cac1` | — |
| K2, O2, B5 | `none` provider; dispatch-to-step link; recovery logged | 0.3 | 10-05 eve | `b50273c`, `4d27092` | — | — |
| B10, B10b, B10c | Encoded PowerShell: tool → tag and decode on request → decode in the loop, capped | 2.4 | 10-05 eve, 10-05 late, 10-06 am, 10-06 midday | `76296eb`, `ce97080`, `8cb165b`, `c128cb3` | `67da804d`, `dbb0e75c`, `9322c93a`, `dce405e5` | **twice**: the step-id design missed live, then on-request decoding never ran |
| B11 | Notable/risk rows read as telemetry; judging words in narratives | 1.1 | 10-06 am, 10-06 midday | `a7286e7`, `fa4a43e` | `dce405e5` | — |
| Handoff kinds | `file_name`/`command_line` kinds; scope guard accepts a path's file name | 0.6 | 10-06 pm | `d89fd96`, `5c89fcb` | `30b729b6` (offline after it) | — |
| 148b0e69 fixes | Blocked `index=*` queries, spend, file events, alert hash in every task's scope | 1.3 | 10-06 eve, 10-06 close | `cced224` | `148b0e69`, `c7dbf51d` | spend fix missed subagent keys, redone 10-07 |
| c7dbf51d fixes (N1–N3) | Spend keys, payload budget, runaway replies, duplicate sets, narrative figures | 1.8 | 10-07 | `cced224` | `c7dbf51d`, `78cd60ec` | — |
| B12, B13, O4 | Cut-off-twice salvage; index probing; gate drops logged | 0.6 | 10-07 late → 10-08 | `1b29d75` line | `b3aa0dd2` | — |
| F6, F7, F8 + `process_guid` | Tools only when needed; lost answers are errors; empty searches named; Sysmon GUID per task | 1.5 | 10-08 → 10-09 | `95c2153` | `874ab334`, `9410e664`, `397542de`, `99e26b1e`, `5dc65b8c`, `25965109` | F8's footer became B14's biggest cause |
| 874ab334 trace | End-to-end handoff trace (9 traces, 12 folders, 0 observations sent) | 0.5 | 10-08 → 10-09 | (handover) | `874ab334` | — |
| B14 | Footers off the narrative into `facts`; priority trimming; `DomainRecord` rename | 0.35 | 10-09 | `78a2fdc` | offline re-pack of `874ab334` | budget still open |
| B15 | Endpoint cut-off diagnostics | 0.1 | 10-09 | `78a2fdc` | — | — |
| B16, B17, B18 | VT cache; PID split; VT skips private IPs | 0.2 | 10-09 | `78a2fdc` | — (baseline blocked by a Bedrock 403) | — |
| O5, O6 | One run folder and trace; task named in logs | 0.3 | 10-09 | `78a2fdc` | — | — |
| c90ca5f9 trace | Round-by-round review; task-drop bug; findings B19–B22, T21, T22, P1 | 1.0 | 10-09 pm | `89ff6d0` | `c90ca5f9` | — |
| B19, B21, B22 | Task windows widen before the window check; private-address facts; file-hash facts | 0.4 | 10-09 eve | `276f789` | — (baseline replay pending) | B22's premise was wrong (no hashes in the context); reworked as hashes from the rows |
| B23 | One UTC standard: `utc_row` for every row time, siem asks for stored times, run-time check | 0.7 | 10-09 pm, 10-09 eve | `276f789` | — (baseline replay pending) | — |
| Prompt review | Every live Broker-side prompt read as rendered; findings P-1…P-10 | 0.2 | 10-09 eve | (handover) | — | — |

## By session

| Session | Local time | Active h (45 / 15 min) | Broker share | Broker h | Handover | Main work |
|---|---|---|---|---|---|---|
| `33915f40` | 09-29 14:09 → 09-30 16:29 | 3.5 / 3.5 | ~50% | 1.75 | 09-30 | Analyst↔Broker reconnection; also Splunk MCP restore, lanes UI, secrets, tooling |
| `7a6edb58` | 09-30 16:35 → 10-01 19:45 | 5.8 / 3.3 | ~70% | 4.1 | 10-01 | time fixes and `58d39c3`; B7/B8 investigation and plan |
| `a6280621` | 10-01 19:48 → (idle) | 0.8 / 0.5 | 100% | 0.8 | — | B7/B8 implemented (`959c6da`) |
| `6c5cb03d` + `891792c0` | 10-05 10:17 → 11:35 (parallel) | 2.2 / 1.9 | 100% | 2.2 | 10-05 | K1, B1 first pass, guard fixes |
| `1cb498c3` | 10-05 11:46 → 13:20 | 1.6 / 1.3 | 100% | 1.6 | 10-05 pm | B1b–B1d checks |
| `71ac7673` + `07e08952` | 10-05 13:25 → 15:57 | 1.5 / 1.5 | ~85% | 1.3 | 10-05 eve | B9, O1/O3, `ded5cac1` |
| `65f1a4d0` | 10-05 15:57 → 18:24 | 1.6 / 1.6 | ~75% | 1.2 | 10-05 night | Analyst port (not Broker); B1c, B9a, B10, K2/O2/B5 |
| `b704853c` | 10-05 18:27 → 19:18 | 0.9 / 0.9 | ~70% | 0.6 | 10-05 late | B10b; T15/T16 write-up |
| `343e50d9` | 10-06 10:43 → 12:26 | 1.7 / 1.0 | ~90% | 1.5 | 10-06 | B10c, B11 |
| `158a62f2` | 10-06 12:31 → 14:27 | 1.1 / 0.7 | 100% | 1.1 | 10-06 pm | B10c cap, B11 |
| `a85147cb` | 10-06 14:27 → 16:27 | 2.0 / 1.3 | ~30% | 0.6 | 10-06 eve | console UI (not Broker); handoff kinds |
| `96f75768` | 10-06 16:28 → 21:44 | 3.3 / 2.0 | ~20% | 0.7 | 10-06 late, night | main `d53d869` integration, event time, console; `148b0e69` flaws |
| `43ca7a16` | 10-06 21:44 → 10-07 12:30 | 0.6 / 0.6 | 100% | 0.6 | 10-06 close | `148b0e69` fixes |
| `bc34ddbf` | 10-07 12:30 → 22:22 | 2.0 / 0.7 | ~90% | 1.8 | 10-07 | `c7dbf51d` fixes, `cced224` |
| `ce0d0e85` | 10-07 22:22 → 10-08 08:57 | 1.5 / 1.1 | ~40% | 0.6 | 10-08 | multi-round loop and W8 (not Broker); B12, B13, O4 |
| `ecb4bbce` | 10-08 08:57 → 10-09 10:45 | 3.1 / 2.2 | ~65% | 2.0 | 10-09 | F6–F8, `process_guid`, 5 live runs, `874ab334` trace; webapp windows/queue |
| `c522b714` | 10-09 10:45 → 15:47 | 2.9 / 1.6 | ~85% | 2.5 | 10-09 pm | B14–B18, O5, O6, issues report; `c90ca5f9` trace; time standard design |
| `2e19eb2d` | 10-09 15:47 → 19:34 | 0.7 / 0.4 | ~95% | 0.65 | 10-09 eve | B19, B21–B23; Analyst-owner list; prompt review |
| `3cede18f` | 10-09 19:34 → 19:45 | 0.1 / 0.1 | 100% | 0.1 | (this report) | commit `276f789`, this update |

## What stands out

- **B1 (the parent path) is the largest item at about 3 h**, including two prompt attempts that were reverted. The delivery side is done; the Analyst still doesn't read the path (T4, T13).
- **B10 (encoded PowerShell) needed about 2.4 h over three designs**, two of which failed live. Each redesign came from a live run, not a test.
- **Live verification is a large share of every item.** Most "Rework" entries trace to a run where the fix held in tests and not live, so a Broker fix isn't finished until a live run shows it.
- **10-09's Broker fixes are only partly verified live:** `c90ca5f9` ran after B14–B18 landed and surfaced B19–B22; B19–B23 wait on the baseline replay of that alert.
