# Tool Broker fixes: timesheet (2026-09-29 → 2026-10-11)

**What this measures.** Time spent in Claude Code sessions on this repo, read from the session transcripts' message timestamps (local time, +03:00). A session's *active* time sums the gaps between consecutive messages and leaves out any gap longer than a cutoff:
- **45-min cutoff (used for the totals):** counts waits on live runs and reviews, which often go 20–40 minutes without a message.
- **15-min cutoff (lower bound):** counts only continuous back-and-forth.

**What it doesn't measure:** time spent outside Claude Code (reading traces in a browser, Splunk, talking to teammates). Parallel sessions are counted separately, so overlapping hours add up. The Broker share of each session and the split across items are judged from that session's handover and commits; they're estimates, not timers.

## Totals

| | Hours |
|---|---|
| All sessions on this repo, 09-29 → 10-11 (45-min cutoff, UI worker session excluded) | 46.9 |
| Of which Broker and sub-analyst work | **≈ 32.8** |
| Lower bound for the Broker work (15-min cutoff) | ≈ 23.8 |

The rest went to the Analyst port and main integration, the webapp loop (T17, W8), the console UI, the 10-11 architecture audit and cleanups (AR1–AR11), G1/G2 coded on the Analyst side and reverted, and the handovers themselves. The UI worker session (`4ca714f1`, 1.7 h) is left out.

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
| P-1…P-8, P-10 | The prompt review's fixes, committed with PR #4 | 0.55 | 10-10 | `1f63130` | `89674d75` | P-10 didn't hold (B26) |
| B24, B27 | Reconnect a dead MCP session; end and time-box a stuck step; row and cell caps | 0.75 | 10-10 pm | `8d21f8b` | `89674d75` (before) | — |
| W10 | Don't re-send a follow-up already asked; end the run when nothing is new | 0.25 | 10-10 pm | `ee9958f` | replay of `89674d75` | — |
| B14 | Budget re-measured (3.76 chars/token, 2 full rounds, compact reserve): 16,480 → 27,608 | 0.4 | 10-11 | `69c7e7a` | replay of `89674d75` | second pass: 10-09's `facts` split didn't free enough |
| B15 | Cause: one paragraph per set under a fixed cap; narrative rule rewritten | 0.3 | 10-11 | `69c7e7a` | — | third pass, after 10-09's diagnostics |
| B26, B25 | Splunk check (`stats … by` drops rows, not `host=`); `fillnull` rule; status from rows; entity rule | 0.3 | 10-11 | `69c7e7a` | Splunk queries | the `host=` hypothesis was wrong |
| B20, K4 | "Can't answer" design; model-tiering plan; issues report | 0.3 | 10-11 | `9b340e8` | — | — |
| K4 | Anthropic provider with per-role tiers; A/B runs | 0.3 | 10-11 | `47ec269`, `1dcf67e` | `3bf5fce8`, `8807fafa` | — |
| B28–B33, B11, W11 | Rows by their own event code; estate `tstats` as discovery; gaps rule; refused-ref state; where hashes live; logon type names; one MCP client | 0.55 | 10-11 | `c7aa245`, `3be53b6`, `84c65b8`, `7babf3a`, `b7d458f`, `2c27cf6` | `8807fafa`, `3bf5fce8` replays; Splunk queries | — |
| B30 | Tokens and requests per role | 0.05 | 10-11 | `4661868` | `a818a3fd` | — |
| B34–B37, B31 | `a818a3fd` read; aggregate rows by event code, Sysmon network fields, output holds from measurement, coverage from rows, gaps filtered in code | 0.8 | 10-11 | `2ab6bb2`, `67718cd`, `6a8255b`, `0ce24c0`, `8902b52`, `868980f` (PR #6) | `a818a3fd`, re-projection | B34 is B28's second pass; B31's prompt rule failed live |
| B15 | Code lever: collapse repeated sentences, quote the loop in the re-ask, salvage the first reply | 0.3 | 10-11 | `9190ad4`, `2b4f9ef` (PR #6) | `e8d949af`, `942115f7` | fourth pass; endpoint still lost 6 times |
| G1–G3, B38 | Evidence-gate bugs and code-count rows registered from the two baselines; where the gates live (Analyst side); handover | 0.7 | 10-11 | (docs) | `e8d949af`, `942115f7` | — |
| Efficiency plan | Cost and latency per role, wasted calls, 14 ranked items (smartops-worker) | 0.5 | 10-11 late | `docs/efficiency-plan-2026-10-11.md` (untracked) | `e8d949af`, `942115f7` | — |
| Handoff timing | Analyst ↔ Broker handoff traced; serial fetch is ~70% of a round (942115f7 L3: 5m24s of 6m43s) | 0.15 | 10-11 late | — | `942115f7`, `e8d949af` | — |
| B15 | A/B of 5 prompt versions on the 6 lost endpoint slices (0/6 → 6/6); the example sentence was the loop seed, removed in every domain; sub-analyst Bedrock key diagnosed | 0.8 | 10-11 late | `18f7719` (PR #6) | replays of `e8d949af`/`942115f7` slices, all 3 domains through `gather_finding` | fifth pass; held offline, live check pending |

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
| `3cede18f` | 10-09 19:34 → 19:45 | 0.1 / 0.1 | 100% | 0.1 | (10-09 report) | commit `276f789`, the 10-09 update |
| `34fd06cb` | 10-10 13:21 → 15:06 | 0.9 / 0.9 | ~60% | 0.55 | 10-10 | PR #4; prompt fixes `1f63130`; committed the run-control UI (`5a6f88b`, not Broker) |
| `0ed73387` | 10-10 21:13 → 22:25 | 1.2 / 0.9 | ~85% | 1.0 | 10-10 pm | B24, B27, W10 from the `89674d75` findings |
| `53985608` | 10-11 09:19 → 10:46 | 1.45 / 0.96 | ~90% | 1.3 | 10-11 pm | push; B14, B15, B25, B26; B20 design; K4 plan |
| `cd672601` | 10-11 10:48 → 11:56 | 1.14 / 1.14 | ~80% | 0.9 | 10-11 eve | K4 A/B; B28–B33, W11; PR #5; T27 benign-lean write-up (Analyst side) |
| `d862cc12` | 10-11 10:22 → 14:42 (parallel) | 1.03 / 0.22 | 0% | 0 | — | architecture audit AR1–AR10 (not Broker) |
| `cf9a7026` | 10-11 11:58 → 14:41 | 1.81 / 1.42 | 100% | 1.8 | 10-11 close | `a818a3fd` read; B34–B37, B15 code lever, PR #6; `e8d949af`/`942115f7` read; gate bugs G1–G3 and where they live |
| `38648d29` | 10-11 14:42 → 15:49 (parallel) | 1.11 / 0.84 | ~45% | 0.5 | (this update) | efficiency plan; AR3/AR4/AR5/AR7/AR9 engine half and AR11 (not Broker) |
| `a1e6792c` | 10-11 14:42 → 15:50 | 1.12 / 1.12 | ~85% | 0.95 | 10-11 late | handoff timing; B15 A/B and `18f7719`; G1/G2 coded and reverted (Analyst side) |

## What stands out

- **B1 (the parent path) is the largest item at about 3 h**, including two prompt attempts that were reverted. The delivery side is done; the Analyst still doesn't read the path (T4, T13).
- **B10 (encoded PowerShell) needed about 2.4 h over three designs**, two of which failed live. Each redesign came from a live run, not a test.
- **Live verification is a large share of every item.** Most "Rework" entries trace to a run where the fix held in tests and not live, so a Broker fix isn't finished until a live run shows it.
- **B14 and B15 needed a measurement, not another rule.** Both had a fix in place (10-09) that didn't hold on `89674d75`. In both, the cause was a number nobody had checked against a run: the payload's characters per token, and output that grew with the number of sets under a fixed cap.
- **The `89674d75` trace itself isn't counted:** it isn't in any session on this repo.
- **B15 is the longest-running item: five passes** (diagnostics, a narrative rule, a "write each group once" rule, code, then the A/B). Each rule added text around the prompt's own example sentence, which was what the model copied. Replaying the lost slices against prompt versions found it in under an hour; removing the example took 0/6 to 6/6 offline. It waits on a live run.
- **On the 10-11 baselines the evidence gate, not the evidence, ended every round.** 5 of 6 rounds met the score rule and were refused on refs. Four of those were endpoint domains lost to B15, and one was a cited block the gate misread (G1).
- **10-09's Broker fixes are only partly verified live:** `c90ca5f9` ran after B14–B18 landed and surfaced B19–B22; B19–B23 wait on the baseline replay of that alert.
