# SmartOps Issues Report

**As of:** 2026-10-11 (through run `89674d75`, plus the 10-11 logic pass). **Code:** branch `smartops-loop-fix` (since 2026-10-06; the earlier line is `post-analyst-update-integration`, cut from `main` at `8b07441`, plus the hand port of the teammate's analyst branch `330d1bc`).

**Scope:** the whole pipeline: context pipeline, Analyst (plan and synthesis), Tool Broker and sub-analysts, webapp integration, cost, audit trail, security and architecture. Items that also appear in `docs/analyst-bug-report.md` keep their IDs there (A#, C#) and are cross-referenced here.

## Evidence base

Runs up to `b3aa0dd2` investigated the same Splunk ES notable: *Threat - Custom - Windows PowerShell Process Discovery*, host `ar-f6eddb5b-df6`, user `Administrator`, `_time 2026-09-27T15:04:02+03:00`. Run `cecd266a` is the exception: it investigated *Malicious PowerShell Process - Encoded Command* on the same host. The 2026-10-08 runs investigated newer notables on the same host (rule named per row).

| Run | Date | Outcome | Notes |
|---|---|---|---|
| SOC3 (saved UI page) | 2026-09-30 | FALSE POSITIVE 70%, 19 loops | Built before the integration fixes; the Broker handoff returned a stale run every loop |
| `cecd266a` | 2026-09-30 | FALSE POSITIVE 95%, 1 loop | Narrow task windows 3 h off (dropped `+03:00`) |
| `072fd610` | 2026-09-30 | TRUE POSITIVE 95%, 1 loop | First run after the time fixes |
| `04a15495` | 2026-10-01 | TRUE POSITIVE 90%, 2 loops | First evaluation leaned benign (30/90/90) |
| `a8118db9` | 2026-10-01 | TRUE POSITIVE 95%, 3 loops | First evaluation leaned benign (40/80/90) |
| `6fc4f590` | 2026-10-01 | no verdict | Stopped mid-Broker because the test machine ran out of memory; not a product fault |
| `9322c93a` | 2026-10-06 | TRUE POSITIVE 98%, 1 loop | B10b baseline: 32 encoded commands tagged, none decoded; verdict leaned on unread "obfuscated PowerShell". Trace `docs/trace-9322c93a.html` |
| `dce405e5` | 2026-10-06 | REQUIRES_INVESTIGATION 65%, 1 loop | B10c: decoded text in the handoff and read by synthesis; run ended with gaps but no follow-ups (T17). Trace `docs/trace-dce405e5.html` |
| `c7dbf51d` | 2026-10-07 | FALSE_POSITIVE 90%, 1 loop | RunOnce `msedge_cleanup_{…}` (T1547.001). The gate accepted `evidence_refs` that name no broker finding (`T2:registry_value_data`, `T3:user`) (T1). Flaws: `docs/run-c7dbf51d-flaws.md` |
| `78cd60ec` | 2026-10-07 | no verdict, 1 loop | Replay of `c7dbf51d`'s context. Synthesis was cut off at 4,096 output tokens while still thinking; the extracted JSON had no follow-ups, so the run ended (T15). Flaws: `docs/run-78cd60ec-flaws.md` |
| `71ef7d21` | 2026-10-07 | no verdict | First run after the loop fixes, replaying `c7dbf51d`'s context. Stopped during the first Broker fetch because the test machine ran out of memory (~1 GB of 16 GB free); not a product fault. To be re-run |
| `b3aa0dd2` | 2026-10-08 | REQUIRES_INVESTIGATION 60%, 3 loops (max) | Re-run of `71ef7d21` after the loop fixes. Loop 2 FP-leaning 60/90/80, gap under 20, so the model's own follow-ups went on. Loop 3 claimed FALSE_POSITIVE 88 on one invented ref; the gate refused it, and T1's question went back as `G1`. Loop 4 ended 20/80/80 at max loops. Broker $2.31 + $2.58 + $0.17 = $5.06 |
| `25965109` | 2026-10-08 | Failed | Stopped by a Ctrl+C on the server console (exit `0xC000013A`), shown in the UI as an ordinary failure. Endpoint cut off on T4 and T7 (B15); VT looked up one hash 7 times (B16) |
| `874ab334` | 2026-10-08 | no verdict, 2 rounds | *Custom - Windows PowerShell Ingress Tool Transfer*, user `Mariam`, event 2026-10-06T11:51:16Z. Round-3 synthesis spent all 8,192 output tokens on a 19,152-token prompt (T15). Payloads 23.8k/31.8k against 16.5k, 0 observations sent (B14). Traced end to end below (874ab334 deep-dive) |
| `9410e664` | 2026-10-08 | BENIGN 90, 1 round | *ESCU Encoded Command*. H3 90 / H2 70, refs held |
| `397542de` | 2026-10-08 | no verdict, 1 round | *ESCU Encoded Command*. Synthesis JSON did not parse (1,107 tokens, empty reasoning); the raw answer is not recorded (T15, T17) |
| `99e26b1e` | 2026-10-08 | no verdict, 1 round | *ESCU Encoded Command*. BENIGN 70 (needs 85); the reasoning itself says "Status: VERDICT_REACHED"; no follow-ups (T17) |
| `5dc65b8c` | 2026-10-08 | no verdict, 1 round | *Custom Process Discovery*. FP 95 vs BENIGN 88, lead 7 (needs 20); refs `T1:T1`, `T2:T2` (T1, T9, T17) |
| `c90ca5f9` | 2026-10-09 | no verdict, 2 rounds | First run on `78a2fdc`, replaying `874ab334`'s alert. 3 of 5 tasks dropped at handoff for zero-length windows (B19). Round 2 FALSE_POSITIVE 80 with status REQUIRES_INVESTIGATION (60/80/75); round 3 spent 8,192 tokens thinking on an 11.7k prompt and wrote nothing (T15). Broker $1.01 + $1.56. Observations crossed (11, 14), B18/O5/O6 held |
| `89674d75` | 2026-10-10 | no verdict, stopped in round 5 | First run on `1f63130` (prompt review), same alert as `874ab334`. Round 2 TRUE_POSITIVE 98/65/78 and round 3 95/60/45 both met the score rule and were refused on refs (T25). Round 4 re-ran round 3's tasks unchanged (W10) and came back 90/82/83 (T26). Round 5 lost the Splunk MCP session after FU1 and hung for 21 min until stopped (B24). Broker $4.02 + $2.70 + $3.47 + ≥$0.55 |
| `2a71757f` | 2026-10-11 | TRUE_POSITIVE 95/45/25, 1 round | Baseline on PR #6 + `18f7719` (B15), tier A, same alert as `874ab334`. First round today the gate accepted: 5 refs held, 4 of them endpoint. 0 `stop_reason=length`, 0 repeats, 0 re-asks; all 15 domain calls in 44 s. Broker 6m39s, $1.81. Of synthesis's four reasons only the download chain holds: the "encoded commands" decode to `$env:username`, "Atomic Red Team" is a module import of installed test tooling, and the "suspicious hash" is powershell.exe's own, read as svcupdate.dat's (B40). The gate checks refs, not reasoning (Analyst side: T21, T24) |

**Baseline checks on `89674d75`** (the list in `docs/handover-2026-10-10.md`):
- **Held:**
  - B19: T1–T3 were all sent.
  - B21: `192.168.40.211` arrived as a private-address fact, and round 2 called it private.
  - B22: OneDrive.exe's hash `DCC9F3B8…` is in rounds 3 and 4's `facts`. No task asked VirusTotal about it (T21).
  - P-8: vt was never dispatched.
  - P-1: sets read "20 of 100 rows shown".
  - B23: `tests/test_run_times_utc.py` passes, and no `+03:00` appears in any `tasks.json` or payload.
- **Not held:**
  - B14: 0 observations reached the Analyst in any round.
  - B15: the cut-off recurred twice.
  - P-10: a `no_data` status came back beside returned rows (B26).

Runs live in `.smartops/runs/<run_id>/`; from 2026-10-09 one folder per investigation (O5). The `072fd610` trace is at `tests/test-integration/trace-072fd610.html`.

**Severity:** **Critical** means it produces a wrong verdict, or a security exposure. **High** means it can produce a wrong verdict, or makes a verdict untrustworthy. **Medium** means cost, wasted work, or misleading output. **Low** means cosmetic or minor.

## Summary

| ID | Area | Issue | Severity | Status |
|---|---|---|---|---|
| T1 | Triage | Verdict accepted without meeting the stop rule (no code gate) | High | Fixed on `smartops-loop-fix`: refs checked against findings and steps |
| T2 | Triage | Scores unstable on the same input; first evaluation flips | High | Open (A2) |
| T3 | Triage | Planning framing decides the outcome when evidence is thin | High | Open |
| T4 | Triage | Parent process judged by name, not path; masquerade missed | High | Open (A5) |
| T5 | Triage | Masquerade attributed to the wrong processes | High | Open |
| T6 | Triage | Verdict built on other activity on the host, not this alert's evidence | High | Open |
| T7 | Triage | Alert text and hypothesis wording cited as evidence | High | Open (A4) |
| T8 | Triage | Reasoning from absence ("lack of benign indicators") | Medium | Open |
| T9 | Triage | Hypothesis scores aren't mutually consistent (FP 90 and Benign 90 together) | Medium | Open |
| T10 | Triage | Status and verdict vocabulary mixed | Medium | Open (A8) |
| T11 | Triage | Task entity kinds the Broker can't search; tasks dropped | Medium | Open (A6) |
| T12 | Triage | Wrong reference rule; contradictory alignment judgements | Medium | Open (A7, C5) |
| T13 | Triage | Analyst ignores the parent path even when the narrative spells it out | High | Open |
| T14 | Triage | Synthesis reads tasks that never ran and cites them as findings | High | Open |
| T15 | Triage | Synthesis can spend its output budget before writing the verdict JSON | High | Partly fixed (`4aac5a6`): a `length` stop now ends the run as a model failure and saves the whole generation; the runaway thinking itself is open |
| T16 | Triage | Unanswered follow-ups closed as "no gaps" | High | Open |
| T17 | Triage | REQUIRES_INVESTIGATION with gaps but no follow-up tasks ends the run | High | Worked around in code (gaps become follow-ups); recurred in 4 of 5 runs on 2026-10-08 when scores are close or low, or the JSON is unparsed; prompt and gate open |
| T18 | Triage | Task windows reach weeks back; follow-ups inherit the widest, so old activity is narrated beside the alert | High | Open (Analyst planning + loop follow-ups) |
| T19 | Triage | Synthesis misses a cross-reference between the alert and other rows it was given | High | Open (Analyst) |
| T20 | Triage | Tasks aren't linked to hypotheses, but the contract's names say they are | Medium | Open (owner decision) |
| T21 | Triage | A parent is judged by its name, not by what it ran | High | Open (Analyst) |
| T22 | Triage | Synthesis describes rounds and tasks that never ran | Medium | Open (Analyst) |
| T23 | Triage | The evaluation header never states the event time | Low | Open (Analyst) |
| T24 | Triage | Task questions and row counts cited as findings ("CrowdStrike telemetry", "execution of svcupdate.dat") | High | Open (Analyst) |
| T25 | Triage | Verdicts that meet the score rule are refused on one bad ref or a malformed ref format | High | Open (decision pending) |
| T26 | Triage | Synthesis reads gap tasks G1–G3 as hypotheses H1–H3 and copies scores from an evaluation that never ran | High | Open (Analyst + W8 compaction) |
| T27 | Triage | The first evaluation leans non-malicious: H2/H3 restate the telemetry, H1 claims what telemetry can't show | High | Open (Analyst planning + scoring) |
| P1 | Context | `event_time` is detection time, not activity time | High | Fixed 10-06 (`firstTime` with `_time`'s offset); five other times still reach planning (decision pending) |
| P2 | Context | Seed drops the command line and parent path | High | Open |
| P3 | Context | Hardcoded non-existent index `win_sysmon` | Medium | Open (C4) |
| P4 | Context | OpenCTI lookups use wrong types; unrelated intel added | Medium | Open |
| P5 | Context | ESCU matcher scores rule names only | Medium | Open (C5) |
| B1 | Broker | Observations drop the parent path, so it never reaches synthesis | High | Fixed (`e475a84`, narrative names on this branch); live re-run pending |
| B2 | Broker | Narrow task windows miss the activity | Medium | Open (follows P1) |
| B3 | Broker | Planned steps for families with no tool (`investigate_edr`) | Medium | Fixed in `58d39c3` |
| B4 | Broker | Sub-analyst misread a `+03:00` row as outside a `Z` window | High | Fixed in `58d39c3` |
| B5 | Broker | Subagent hit its output-token cap; recovery produced no answer | Medium | Not reproduced since; now logged |
| B6 | Broker | Follow-up tasks inherit every entity and the widest window | Medium | Open: needs the Analyst's follow-ups to name their task (B20) |
| B7 | Broker | Unconnected families (edr, ndr) named in what the models read; host questions steered off Splunk | Medium | Fixed on this branch |
| B8 | Broker | `tstats` unreliable: non-CIM fields return 0 rows; one filtered empty result killed a data model | Medium | Fixed on this branch |
| B9 | Broker | Handoff to the Analyst had no size limit; B1's summaries would overflow its window | High | Fixed (`e475a84`, batch water-fill on this branch); overran again on 874ab334 (B14) |
| B10 | Broker | Encoded PowerShell fetched but never decoded; a "decode" follow-up came back unanswered | High | Reworked (B10c: decoded in the loop that sees it; verified live `dce405e5`); decoded block capped at 8 lines, rarest parent first (`ENCODED_LINE_CAP`) |
| B11 | Broker | Sub-analyst narratives judge ("suspicious"), misread fields (paths as endpoints, events as destinations), and present ES notable/risk records as telemetry | Medium | Open; logon type now named by code (`broker-k4-ab-fixes`) |
| B12 | Broker | A sub-analyst cut off twice loses its whole domain | Medium | Fixed on `smartops-loop-fix` |
| B13 | Broker | The siem subagent probes indexes one by one | Medium | Fixed on `smartops-loop-fix` |
| B14 | Broker | Code footers inside narratives push every observation out; payload ships over budget | High | Fixed on `smartops-loop-fix`: budget re-measured, 16,480 → 27,608 characters; replayed on `89674d75`, 0 → 43/51, 59/59, 52/52 observations; live check pending |
| B15 | Broker | Endpoint sub-analyst cut off on both calls; the raw answer is lost | Medium | Fixed (`18f7719`): the example sentence was the loop seed, removed in every domain. Held live on `2a71757f` (0 cut-offs, 15/15 domains) |
| B16 | Broker | VirusTotal re-queries the same indicator in every task; tasks run one after another | Medium | Cache fixed on `smartops-loop-fix`; parallel tasks deferred |
| B17 | Broker | `process=powershell.exe (PID 12345)` sent as one value | Low | Fixed on `smartops-loop-fix` |
| B18 | Broker | VirusTotal queried for a private IP, and the result read as clean | High | Fixed on `smartops-loop-fix` |
| B19 | Handoff | Lookup tasks with a zero-length or no window are dropped | High | Fixed on `smartops-loop-fix`; held on `89674d75` |
| B20 | Broker | Follow-ups repeat the round's searches; questions no source can answer are fetched anyway | Medium | "Can't answer" fixed on `broker-a818-fixes` (`plan_fetch` `unanswerable`, `01877a9`); held live on `451334ad` and `ea38cb13`; scoping is Analyst-side |
| B21 | Broker | A private address isn't stated as one; the Analyst called it external | Medium | Fixed on `smartops-loop-fix`; held on `89674d75` |
| B22 | Broker | The parent process's hash never reaches the Analyst, so no task asks VT about the parent | Medium | Fixed on `smartops-loop-fix` (hashes in `facts`); live check pending |
| B23 | Broker | Row times reach the sub-analysts in several zones and formats | Medium | Fixed on `smartops-loop-fix`; held on `89674d75` |
| B24 | Broker | The Splunk MCP session dies mid-round, nothing restarts it, and the round hangs | High | Fixed on `smartops-loop-fix`; live check pending |
| B25 | Broker | The Broker writes the task's IP as the host's address | Medium | Fixed on `smartops-loop-fix` (rule in the user turn); live check pending |
| B26 | Broker | siem tasks disagree on whether svcupdate.dat is in the data; `no_data` beside returned rows | Medium | Fixed on `smartops-loop-fix`: the cause is `stats … by` dropping rows missing a by-field, not `host=` (checked in Splunk); status from the rows |
| B27 | Broker | A siem step pulls every script block on the host (6.9 MB of evidence in one step) | Medium | Fixed on `smartops-loop-fix`; live check pending |
| B28 | Broker | Rows filed in the wrong category: a mixed-event-code call filed whole, the lab's FortiGate rows uncategorised; steps read 0 rows | High | Fixed on `broker-k4-ab-fixes`; re-projected on `8807fafa` |
| B29 | Broker | The required index-discovery `tstats` is filed as evidence ("2105 events with no timestamp") | Medium | Fixed on `broker-k4-ab-fixes` |
| B30 | Broker | Tokens, cache reads and requests per role aren't recorded | Low | Fixed on `broker-k4-ab-fixes` |
| B31 | Broker | siem reports `gaps: vt` on every task with nothing vt could look up | Low | Prompt fixed on `broker-k4-ab-fixes`; live check pending |
| B32 | Handoff | A refused ref says "step … is ok" for an incomplete step | Low | Fixed on `broker-k4-ab-fixes` |
| B33 | Broker | Hash questions unanswered: siem never searched Sysmon 15/29, and file_events held non-file rows the narrative called file writes | High | Fixed on `broker-k4-ab-fixes` (siem hint, 15/29 as file events, `event_code=`); svcupdate.dat's hash is not in the lab's data |
| B34 | Broker | Aggregate rows skip the per-row event-code split | High | Fixed on `broker-a818-fixes` |
| B35 | Broker | Sysmon network fields weren't read | High | Fixed on `broker-a818-fixes` |
| B36 | Broker | One task's output-token holds refused its own third step | High | Fixed on `broker-a818-fixes` |
| B37 | Broker | `covered` was the subagent's own claim | Medium | Fixed on `broker-a818-fixes` |
| B38 | Broker | Pure code-count rows are narrated as events | Medium | Fixed on `broker-a818-fixes` (`20c83b9`): a call of only EventCode counts is discovery |
| B39 | Broker | A step's status is its last dispatch's, not its rows': `no_data` beside 5 rows | Medium | Fixed on `broker-a818-fixes`: status follows cumulative rows (`e8b0ffb`); held live on `451334ad` |
| B40 | Broker | A `-` placeholder counts as a value, so a hash's file reads "(file not named)" and synthesis pinned powershell.exe's hash on svcupdate.dat | High | Fixed on `broker-a818-fixes`: `_first` skips `-` (`d259509`); held live on `451334ad` |
| B41 | Broker | The packer's over-budget warning repeats on every re-measure (7× for one domain) | Low | Fixed on `broker-a818-fixes`: `fitted_row_cap` measures silently |
| W1 | Webapp | Two different plans per investigation; the UI shows the one not executed | High | Open |
| W2 | Webapp | Stale run fed to the Analyst; exit code ignored | Critical | Fixed in `58d39c3` |
| W3 | Webapp | Tasks passed as `--entity` kinds the engine rejects | High | Fixed in `58d39c3` |
| W4 | Webapp | Hardcoded siem stub ran outside every guard | High | Fixed in `58d39c3` |
| W5 | Webapp | Demo alert pre-filled in the form | Medium | Fixed in `58d39c3` |
| W6 | Webapp | Model and log text inserted into `innerHTML` unescaped | Medium | Fixed in `58d39c3` |
| W7 | Webapp | Planning prompts disagree (entity schema, window rule) | Medium | Open |
| W8 | Webapp | Long runs outgrow the window: every round is re-sent, nothing compacts them | High | Fixed on `smartops-loop-fix` (option a); live run pending |
| W9 | Webapp | The browser falls back to the notable time when the event time didn't resolve | Medium | Open (frontend, smartops-worker) |
| W10 | Webapp | Gap statements become tasks verbatim, so a round can repeat the last one exactly | Medium | Repeat filter on `smartops-loop-fix`; gap wording open (Analyst) |
| W11 | Webapp | The webapp opened its own Splunk MCP client beside the backend's | Medium | Fixed on `broker-k4-ab-fixes`: `smartops.tools.registry.call_tool` |
| K1 | Cost | About $5–12 per Broker loop; long results re-sent every turn | Medium | Fixed (`0e82b4c`) |
| K2 | Cost | Blank `SMARTOPS_LLM_PROVIDER` does not stop Broker model calls | Medium | Fixed on this branch (`none`) |
| K3 | Cost | SOC3 ran 19 loops on empty input | Medium | Fixed (W2, T1 gate); `max_loops` raised to 15 on 2026-10-08, see W8 |
| K4 | Cost | One model for every Broker call: the planner, each fetch subagent and each recovery call | Medium | Fixed: Anthropic API provider, per-role tiers A/B, per-request pricing; A/B runs 2026-10-11 (`3bf5fce8`, `8807fafa`); tier A in use on `451334ad` ($1.33 Broker) and `ea38cb13` (Mohammed closed it 2026-10-12) |
| O1 | Audit | Context contract not saved with the run | Medium | Fixed (`c85eb93`) |
| O2 | Audit | Dispatch-to-step link not recorded | Low | Fixed on this branch |
| O3 | Audit | Broker log written only at the end of a loop | Low | Fixed (`c85eb93`) |
| O4 | Audit | Sub-analyst gate drops never reached the run's Broker log | Low | Fixed on `smartops-loop-fix` |
| O5 | Audit | One investigation is 9 traces in 12 folders | Medium | Fixed on `smartops-loop-fix` (one folder, one trace id); Analyst calls have no spans |
| O6 | Audit | Warnings don't name the task; the packer's overflow warning isn't logged | Low | Fixed on `smartops-loop-fix` |
| S1 | Security | Live credentials in git history | Critical | Removed from tree; rotated (Mohammed, 2026-10-12); `33ccf52` (C1–C2) keys: confirm they were in that rotation |
| S2 | Security | Splunk Web scraper replaced the official MCP | High | Fixed (C3) |
| AR1 | Architecture | Six webapp routes and their job store have no caller in the UI | Low | Fixed (AR11, `5fd9757`): the six routes and their job store deleted |
| AR2 | Architecture | The webapp has its own Foundation-Sec-8B client beside the engine's `AnalystModel` | Medium | Fixed (AR11, `b64307b`): the Analyst uses the engine's `AnalystModel`; `llm_service` deleted. Read timeout 600 s kept (`af01d36`) |
| AR3 | Architecture | A global boto3 monkeypatch in `main.py` duplicates `AnalystModel`'s scoped bearer auth | Medium | Open: `FS8B_MODEL_ARN` gone, but the patch still reads `FS8B_API_KEY` and the in-process Analyst relies on it; delete once `SMARTOPS_ANALYST_API_KEY` holds the working key |
| AR4 | Architecture | Four engine symbols only tests use | Low | Fixed on `broker-a818-fixes`: three deleted; `output_tokens_remaining` is live (`subagents/__init__.py:673`), kept |
| AR5 | Architecture | The runs-root lookup is written out 7 times | Low | Fixed: `run_trace.py` is gone; the Analyst and telemetry use `broker.runs_root()` |
| AR6 | Architecture | `extract_json` scans braces by hand | Low | Open |
| AR7 | Architecture | `bench._pinned_skills` only delegates | Low | Fixed on `broker-a818-fixes` |
| AR8 | Architecture | Two launchers on different ports; one re-parses `.env` | Low | Fixed (AR11): `start_server.bat` deleted; `start.ps1` runs `smartops.main:app` on :8013, `.env` loaded once by the server |
| AR9 | Architecture | `mcp` and `botocore` declared by the root package, imported by neither | Low | Fixed on `broker-a818-fixes`: moved to the engine, which imports both directly |
| AR10 | Architecture | There is no frontend: the only UI is the vanilla stopgap in `webapp/static`, and `frontend/` is empty | Medium | Fixed: React + TS frontend in `frontend/` (smartops-worker); `webapp/static` deleted with AR11 |
| AR11 | Architecture | The codebase's file structure: `webapp/` mixes the frontend, the main Analyst, the context pipeline, the Broker handoff and the API server; one model has two configurations; dev tools sit inside the engine package | High | Fixed (`12c34e3`..`4ff806c`, merged 2026-10-12): `analyst.py`, `broker.py`, `context.py`, `main.py` (CLI + API); `webapp/` gone; Broker round in process; Python pinned to 3.13. Live on `79c024e8`; round 2 warm-up still unexercised |

## Triage logic (Analyst plan and synthesis)

**T1. Verdict accepted without meeting the stop rule.** *High. Partly fixed (`330d1bc`, A1).*
- **Evidence:** SOC3 stopped at FALSE_POSITIVE with H2 80 / H3 75. That fails the prompt's own rule (top ≥ 85 and leads by ≥ 20). The SOC2 run stopped at H1 35.
- **Cause:** the loop ends on the model's self-reported `status` (`webapp/main.py:580`), and no code checks `hypothesis_scores`.
- **Fix:** compute the stop decision in code from the scores. Treat `status` as advisory.
- **Done (`330d1bc`):** `run_trace.verdict_gate` sets `status` in code: top ≥ 85, a lead of ≥ 20, and at least one non-`ALERT:` entry in `evidence_refs`, which the evaluation schema now asks for. The trace keeps the model's own status as `model_status`. Not yet measured on a live run.
- **Gap (replay on `ded5cac1`):** the gate only checks that an `evidence_refs` entry isn't `ALERT:`. Arm A cited invented refs (`T2:splunkd.exe`, `T5:host_alerts`) and still passed. The refs should be checked against the payload's `<task>:<domain>` keys.
- **Recurred live (`c7dbf51d`, 2026-10-07):** FALSE_POSITIVE 90 (H2 90 / H3 60) on `T1:registry_events#2`, `T2:registry_value_data` and `T3:user`. The last two are field names, not findings, and T2's VT step had been rejected. The gate passed it, the model sent `follow_up_tasks: []`, and the run stopped after one round.
- **Fixed (`smartops-loop-fix`):** `run_trace._ref_problem` checks every ref against every round's payload and Broker steps. A ref holds when its task ran (full id or `T1` tail), the part after `:` is a domain with observations or a block id cited in that task's findings, and none of the task's steps was rejected or left incomplete. One bad ref blocks the verdict. The reasons go into `refused_refs`, and the cited task's question goes into `evidence_gaps`, which T17's fallback turns into the next round's follow-ups. Replayed offline on `c7dbf51d`: REQUIRES_INVESTIGATION, and two follow-ups for round 3.
- **Verified live (`b3aa0dd2`, 2026-10-08):** loop 3 returned FALSE_POSITIVE with H2 88 / H1 35 and one ref, `b3aa0dd2-L2-T1:FU1`, which joins a round-2 task to a round-3 follow-up and names no finding. The gate refused it, so the run went on to loop 4 instead of stopping on it.
- **Still open (Analyst side): the model doesn't write refs in the asked format.** The evaluation header asks for `<task_id>:<domain>`, but `b3aa0dd2` loop 4 wrote `G1:process_id:220`, `T2:entity:host:ar-f6eddb5b-df6` and `FU2:user:NT AUTHORITY\SYSTEM`: entities, not findings. The gate only catches this when the scores are confident; the prompt has to fix the format.
- **Recurred (2026-10-08):** `874ab334` round 2 wrote `T3:process`, `T5:user` and `T6:process`; `5dc65b8c` wrote `T1:T1` and `T2:T2`. Both were below the score bars, so the gate never checked the refs.

**T2. Scores are unstable on the same input.** *High. Open (A2).*
- **Evidence:** `04a15495` loop 2 scored 30 / 90 / 90, then loop 3 scored 90 / 60 / 30. `a8118db9` went 40 / 80 / 90, then 75 / 65 / 68, then 95 / 65 / 30. SOC3 drifted 0/0/0 → 30/70/50 → 30/60/70 → 40/80/75 across loops that had *no new evidence*.
- **Impact:** a verdict can come down to which loop the run stops on. 2 of 3 true-positive runs passed through a confident benign state on the way.
- **Fix:** define a neutral baseline for "no evidence". Score only from cited observations, and require new evidence before a score can move.
- **Also (replay of `ded5cac1`, 2026-10-05):** the live synthesis message, rebuilt byte for byte (same prompt, same 8,751 prompt tokens) at temperature 0, matched the live reasoning for 721 characters and then diverged. The live call reached FALSE_POSITIVE 92; the reproduction scored 60 / 50 / 45 and wrote no verdict (T15). Temperature 0 doesn't make the model deterministic on Bedrock, so a single run can't attribute a verdict change to a code change. Trace: `docs/trace-ded5cac1-replay.html`.
- **Also (2026-10-05/06, same notable, three consecutive live runs):** `67da804d` BENIGN 95, `9322c93a` TRUE_POSITIVE 98, `dce405e5` REQUIRES_INVESTIGATION 65. Each was reached in one loop with high stated confidence.
- **How later rounds swing (`89674d75`, 10-11 review):** 98 / 65 / 78 → 95 / 60 / 45 → 90 / 82 / 83. The chain:
  1. Both TP evaluations met the score rule and were refused on refs (T25), so the loop went on.
  2. The follow-ups were gap statements sent as questions ("Lack of explicit threat intel hits for 192.168.40.211", "Uncorroborated attacker identity"), and round 4 re-sent round 3's tasks (W10). Nothing decisive came back.
  3. From round 4, `compact_round` shows round 2's scores but not round 3's. The reasoning tries to reconcile them ("We must use the latest round? Or the average?") and maps G1–G3 onto H1–H3 (T26).
  4. The thinking grows: 1,197 → 1,385 → 4,669 output tokens. In `c90ca5f9` and `874ab334` the round-3 synthesis hit 8,192 and returned no JSON (T15).

**T3. The plan's framing decides the outcome when evidence is thin.** *High. Open.*
- **Evidence:** given identical context, the same model framed the alert oppositely.
  - SOC3's plan said `splunkd.exe` is *"a trusted process"* and concluded *"the best fit is BENIGN"* before any retrieval.
  - `072fd610`'s plan kept the attack reading open (*"potential abuse of Splunk's capabilities"*).
- **Impact:** with no evidence (SOC3), synthesis repeated the plan's framing back as a verdict.
- **Fix:** the plan must not pre-judge. Ban verdict language in planning, and require each hypothesis to name the evidence that would confirm or refute it.

**T4. The parent process is judged by name, not path.** *High. Open (A5).*
- **Evidence:** the notable carries `parent_process: C:\Users\Administrator\Desktop\splunkd.exe`. The legitimate forwarder runs from `C:\Program Files\SplunkUniversalForwarder\bin\` as SYSTEM.
  - No run's plan or synthesis cited the path.
  - SOC3 concluded *"spawned by splunkd.exe, indicating an internal Splunk operation"*.
- **Fix:** have the prompt check the parent's image path, user and signature against the expected values for that binary name, and always plan a task that verifies them.

**T5. Masquerade attributed to the wrong processes.** *High. Open.*
- **Evidence:** `a8118db9` called the **legitimate** `splunk-powershell.exe` processes (running as SYSTEM under the real forwarder) *"an attempt to hide malicious activity by masquerading as legitimate Splunk processes"*, and ignored the actual masquerading binary.
- **Cause:** T4, plus B1. The decisive rows never reached synthesis, so the model guessed from the rows it did see.

**T6. The verdict rests on other activity on the host.** *High. Open.*
- **Evidence:**
  - `04a15495` justified true positive by *"HTTP requests"*.
  - `a8118db9` justified it by *"encoded commands fetching remote content"* and *"credential-based logon activities"*.
  - Both came from other activity on the same host, retrieved by multi-day task windows, not from this alert's Process Discovery events.
- **Also:** `04a15495` retrieved **no** row with the alert's masquerading parent (B1).
- **Impact:** the verdict is right about the host but not demonstrated for the alert. On a host with only this activity, the same reasoning has nothing to stand on.
- **Fix:** synthesis should separate evidence about the alerted activity from other host context, and base the verdict on the former.
- **Also (`ded5cac1` replay B):** TRUE_POSITIVE 90 rested partly on host-wide traffic, misread. It called `192.168.40.212:9997` a non-standard exfiltration port (9997 is Splunk's forwarder-to-indexer port, 20 of T3's 21 connections), said `192.168.40.211` was outside the internal subnet (it's RFC 1918), and cited 1,716 HTTPS connections over 26–28 Sep that nothing ties to the alert.

**T7. Alert text and hypothesis wording are cited as evidence.** *High. Open (A4).*
- **Evidence:** `072fd610`'s verdict says *"through splunkd.exe compromise"*. That's hypothesis H1's own wording; nothing shows the real Splunk was compromised. "CISA AA23-347A" in the verdict comes from the alert annotations.
- **Fix:** label the alert facts and the plan text as non-evidence in the synthesis prompt, and require every claim in the verdict to cite an observation id.

**T8. Reasoning from absence.** *Medium. Open.*
- **Evidence:** `072fd610`: *"lack of benign indicators… confirm the malicious nature"*. The prompt itself says absence of evidence isn't evidence of absence.
- **Recurred (`c90ca5f9` round 2):** the file-event searches for `svcupdate.dat` returned no rows (the lab most likely doesn't log `%TEMP%` file creation), and synthesis wrote "the file itself was *not found* in endpoint logs … This directly contradicts H1's claim of a malicious binary transfer".
- **Recurred, toward BENIGN (10-11 review):** `9410e664` "the absence of any malicious indicators" (BENIGN 90, VERDICT_REACHED); `99e26b1e` "no destructive actions or sensitive data exfiltration occurred" (BENIGN 70); `25965109` "Threat intelligence and C2 analysis yielded no malicious indicators" (BENIGN 90). The prompt's rule (`system_prompt.txt:50`) only forbids penalising a hypothesis for missing data; nothing stops the model from crediting the other side with it. See T27.

**T9. Hypothesis scores aren't mutually consistent.** *Medium. Open.*
- **Evidence:** `04a15495` loop 2 scored FALSE_POSITIVE 90 *and* BENIGN 90 at the same time, for mutually exclusive outcomes.
- **Recurred (`dce405e5`):** H1 70 / H2 50 / H3 80, with the reasoning calling T1's commands "clearly malicious" and BENIGN never argued for. BENIGN scored highest, yet the status was REQUIRES_INVESTIGATION, and none of the three numbers appears in the reasoning.
- **Fix:** define what a score means (a probability, or independent support) and enforce it.
- **Recurred (`5dc65b8c`, 2026-10-08):** FALSE_POSITIVE 95 and BENIGN 88, two "legitimate" hypotheses the model could not separate. The plan's hypotheses overlap, which is the Analyst's planning side.

**T10. Status and verdict vocabulary are mixed.** *Medium. Open (A8).*
- **Evidence:** `a8118db9` loop 2 emitted `status: REQUIRES_INVESTIGATION` with `verdict: BENIGN, confidence 90`. SOC3's reasoning debates whether `UNCERTAIN` and `REQUIRES_INVESTIGATION` are verdicts or statuses.
- **Recurred (`c90ca5f9` round 2):** `verdict: FALSE_POSITIVE 80` with `status: REQUIRES_INVESTIGATION`. The leading hypothesis was H2, a legitimate update, which is BENIGN, not FALSE_POSITIVE.

**T11. Task entity kinds the Broker can't search.** *Medium. Open (A6).*
- **Evidence:** `072fd610` dropped T5 (`service`) and T8 (`command`); `a8118db9` dropped T5. `dce405e5` dropped T5 (`network_connection`, value `null`: "did any network connections occur within 30 seconds").
- **Fix:** list only the allowed kinds in the planning prompt, and validate in code before the handoff. Today the check exists only at conversion time (`run_trace`).

**T12. Wrong reference rule, and contradictory alignment judgements.** *Medium. Open (A7, C5).*
- **Evidence:** a Process Discovery alert (T1057) was matched to *Malicious PowerShell Process - Encoded Command* (T1027). In SOC3, the section-5 plan judged the alignment ALIGNED and the loop-1 plan judged it NOT_ALIGNED.

**T13. The Analyst ignores the parent path even when the narrative spells it out.** *High. Open.*
- **Evidence:** in the `ded5cac1` replay (`docs/trace-ded5cac1-replay.html`), synthesis B's narratives carried the computed name lines from `b50273c` (`"splunkd.exe" in these rows is 2 files: C:\Users\Administrator\Desktop\splunkd.exe=26, C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe=20`; T4: `1 file: …Desktop\splunkd.exe=180`). Its reasoning never mentions `Desktop`. It names splunkd only through the hypotheses' wording. Synthesis A, without the lines, didn't either. Earlier, the summaries carried the same path (B1, `ded5cac1` live) and were ignored too.
- **Recurred (`9322c93a`, `dce405e5`):** both payloads carried the Desktop and Public parents in name lines and `enc#` lines (`dce405e5` T4: `enc#784267: 28 events, parent C:\Users\Administrator\Desktop\splunkd.exe=3, C:\Users\Public\splunkd.exe=11, …; decodes to: $env:username`). `9322c93a` reasoned "splunkd.exe (which is a forwarder) spawned PowerShell"; `dce405e5` reasoned that being launched by splunkd.exe "is a common pattern for Splunk". Neither names a path.
- **Cause:** not established. The delivery side is done (B1), so this is how the 8B Analyst reads its input. The plan frames splunkd by name: H2 and H3 name `splunkd.exe` as the legitimate source, and T2 asks whether it is *documented* to run these commands (T3, T4).
- **Fix (Analyst side):** to be decided. Candidates: have the plan name the entity by full value, a code-side check that compares a parent's path against the expected location for its name, or a synthesis step that must state each process's path before scoring. A prompt-only change should be measured with a replay first: it failed twice on the 8B sub-analysts (B1b, B1c).

**T14. Synthesis reads tasks that never ran, and cites them as findings.** *High. Open.*
- **Evidence:** on `ded5cac1`, T1 and T2 were dropped at handoff (zero-length windows, start equal to end), and only T3–T5 reached the Broker. The plan the Analyst reads still lists all five, with nothing marking T1 and T2 as not run.
  - The live FALSE_POSITIVE 92 rested on *"T2 … splunkd.exe is documented to run such commands (as seen in the narrative)"*: T3's line about the real forwarder, read as the answer to T2's question.
  - Replay A cited `T1:powershell.exe` and `T2:splunkd.exe` in `evidence_refs`, and the verdict gate accepted them (T1).
- **Recurred live (`e1461da6`):** 3 of 5 planned tasks were dropped again. T2 and T5 had zero-length windows, and T4 had entity kind `command` (T11).
- **Recurred (`dce405e5`):** T5 was dropped at handoff (T11); the reasoning opens with "We have five broker findings" when four ran.
- **Recurred (`c90ca5f9` round 2):** T1–T3 were dropped (B19), and synthesis still cited "Round 2 (T1): The full path of `svcupdate.dat` is unknown".
- **Fix:** `plan_slim` should carry only the tasks that were sent, or mark the dropped ones with their reason. The gate should accept only `evidence_refs` that match a `<task>:<domain>` in the payload. The planning prompt should also stop emitting zero-length windows (see T11 for the same "dropped at handoff" path).

**T15. Synthesis can spend its output budget before writing the verdict JSON.** *Medium. Open.*
- **Evidence:** the exact reproduction of the `ded5cac1` synthesis used all 4,096 output tokens (`stop_reason=length`): after scoring 60 / 50 / 45, it kept drafting follow-up tasks and never emitted the JSON. `extract_json` returned nothing, so the loop has no status, scores or follow-ups.
- **Fix:** keep the reasoning bounded (ask for the JSON first, or a shorter reasoning section), and treat a `length` stop as a failed call that is retried or reported, not as an empty evaluation.
- **Recurred live (`dbb0e75c` loop 2, 2026-10-05):** 4,096 of 4,096 output tokens, an empty reasoning field and only `{"status": "REQUIRES_INVESTIGATION"}`. The run ended there, with no verdict and no follow-ups.
- **Recurred live (`e1461da6` loop 2):** 4,072 of 4,096 output tokens, and the JSON came back with empty `hypothesis_scores`. The gate turned it into REQUIRES_INVESTIGATION, so the run continued to loop 3 rather than stopping on it.
- **Recurred live (`78cd60ec` loop 2, 2026-10-07): ended the run.** 4,096 of 4,096 output tokens and `stop_reason=length`. The thinking never closed `</think>`, so `call_llm` returned an empty reasoning and put the whole generation in `answer`. `extract_json` pulled out a fragment, `{"H1": 20, "H2": 90, "H3": 80, "status": "REQUIRES_INVESTIGATION"}`, with no `hypothesis_scores` key, no gaps and no follow-ups, and `webapp/main.py` stopped with "No actionable follow-up tasks". The run never reached round 3.
- **Changed (`smartops-loop-fix`):** `llm_service.DEFAULT_MAX_GEN_LEN` is 8,192, which leaves room in the model's 32k window. The Broker's handoff budget is now derived from the Analyst's own generation reserve (`packing._ANALYST_GENERATION_RESERVE`, held equal by a test), so each round's payload batch is 16,480 characters, down from 20,745; three re-sent rounds plus the plan still fit. This only buys headroom.
- **Live at 8,192 (`b3aa0dd2`):** the three synthesis calls used 1,162, 1,314 and 2,008 output tokens, with prompts of 7,406, 12,009 and 13,934 tokens. No cut-off. Neither the 4,096 cut-off nor this run proves the thinking is bounded; the headroom is what changed.
- **Still open (Analyst side):** a `length` stop is still parsed as if whole. `call_llm` and `extract_json` should treat it as a failed evaluation to retry or report, and the synthesis prompt should bound the thinking.
- **Recurred live at 8,192 (`874ab334` round 3, 2026-10-08): ended the run.** 8,192 of 8,192 output tokens on a 19,152-token prompt: rounds 2 and 3 in full (W8 keeps 2), about 55k characters. The answer was cut, `{}` was parsed, and with no gaps the run stopped. `397542de` returned JSON that did not parse after 1,107 tokens with empty reasoning; the raw answer is not recorded, so its cause can't be seen.
- **Recurred (`c90ca5f9` round 3, 2026-10-09): not input size.** 8,192 of 8,192 output tokens on an 11,723-token prompt, with empty reasoning: the thinking never closed and no answer was written. `874ab334` blamed a 19k prompt; this one was 11.7k, so the thinking itself runs away. The run ended after 2 of 15 rounds (T17).
- **Recurred (`8807fafa` round 3, 2026-10-11): ended the run.** 8,192 of 8,192 output tokens on a 19,194-token prompt (two full rounds), no JSON. Round 2 had met the score rule and was refused on refs (T25), so this was the round that should not have run.

**T16. Unanswered follow-ups are closed as "no gaps".** *High. Open.*
- **Evidence:** on `e1461da6`, loop 2 listed "Decoded PowerShell command functionality" as a gap and sent FU1 (decode) and FU2 (is `192.168.40.211` a legitimate update server). Neither was answered: nothing was decoded (B10), and the loop 3 reasoning itself says Round 3 "does not provide direct evidence" about `.211`. Loop 3 still returned `evidence_gaps: []` at TRUE_POSITIVE 98, and leaned on "encoded PowerShell". The command was `$env:username`.
- **Fix (Analyst side):** for each follow-up sent, synthesis must say whether it was answered, citing a finding. An unanswered follow-up stays in `evidence_gaps`, and the gate refuses VERDICT_REACHED, or caps confidence, while one is open.

**T17. REQUIRES_INVESTIGATION with gaps but no follow-up tasks ends the run.** *High. Open.*
- **Evidence:** `dce405e5` loop 2 returned REQUIRES_INVESTIGATION 65 with three `evidence_gaps` (what triggered the splunkd.exe processes, the parent-child relationships in T1, the `192.168.40.211` URI) and no `follow_up_tasks` key. Its reasoning says "we must include evidence_gaps and follow_up_tasks … So we will add these", then the JSON omits them. `webapp/main.py` found no actionable follow-ups and ended the run after 1 of 3 loops ("No actionable follow-up tasks"), with the gaps unexamined.
- **Likely contributor:** the evaluation header (`webapp/main.py`, "Required fields:") lists `hypothesis_scores`, `verdict`, `verdict_reasoning`, `evidence_refs` and `status`, but not `evidence_gaps` or `follow_up_tasks`. Those appear only in `system_prompt.txt`'s schema.
- **Fix (webapp/Analyst side):** list both fields as required when the status is REQUIRES_INVESTIGATION. When gaps arrive without follow-ups, either turn each gap into a follow-up question in code or treat it as a failed evaluation and retry, not as the end of the investigation.
- **Worked around (`smartops-loop-fix`):** `run_trace.follow_up_tasks` turns each `evidence_gap` into a follow-up (`G1`, `G2`, …) when synthesis sent none. It covers the gate's own refusals too (T1). The evaluation header still doesn't ask for the two fields; that stays with the Analyst owner.
- **Verified live (`b3aa0dd2`):** the gate's refusal in loop 3 left `follow_up_tasks: []` and one gap; `G1` (T1's parent-process question) became loop 4's task.
- **Recurred in 4 of 5 runs (2026-10-08), each ending with up to 15 loops left.** Three feeds: the evaluation header still doesn't ask for `evidence_gaps` or `follow_up_tasks`; `verdict_gate` adds a gap only when the score bars are met and a ref fails, so close scores (`5dc65b8c`, lead 7) and low ones (`99e26b1e`, BENIGN 70) add none; and an unparsed synthesis (`874ab334` round 3, `397542de`) becomes `{}`. Fix candidates (webapp/Analyst side, not started): ask for both fields when status is REQUIRES_INVESTIGATION; when scores are close, a gate gap naming the two leading hypotheses; re-run an unparsed synthesis once; record the raw answer and `stop_reason` in `investigation.jsonl`.

**T18. Task windows reach weeks back, and follow-ups inherit the widest.** *High. Open (Analyst planning and loop follow-ups).*
- **Evidence (`874ab334`):** the alert's event is 2026-10-06T11:51:16Z. The plan gave T6 "the last 30 days" (from 09-06), T5 a week, T2 and T4 five days, T1 24 hours. `to_task_file` only widens a window, so they went as planned. G1–G3 in round 3 each got T6's 30 days, because follow-ups take the widest window of the round (B6).
- **The Broker kept to the windows.** `guards.py` sets every Splunk call's `earliest_time`/`latest_time` to the task window, and the row times match: G1's rows run 09-07 → 10-06.
- **Impact:** rows from Sep 7–21 were narrated beside the Oct 6 alert ("Between September 21 and October 6, scripts consistently downloaded files from http://192.168.40.211"), with nothing marking them as two weeks before the alert. That's T6's pattern, now built into the windows.
- **Analyst bug, same run:** T3's planned window was 2026-10-05T11:45–12:15Z, a day early. The widening happened to cover the event.
- **Fix (owner to decide):** a planning rule for when a baseline window is warranted; follow-ups scoped to the task they follow up (B6); or a code line in each set's facts giving how many rows fall within the alert's ±1h.
- **Again on `89674d75`:** T3 asked for "the past 72 hours" with a window of 09-29 → 10-06 23:59Z, which is eight days. Every follow-up in rounds 3–5 inherited that window.

**T19. Synthesis misses a cross-reference between the alert and other rows it was given.** *High. Open (Analyst).*
- **Evidence (`874ab334`):** the alert's own row is PowerShell under `Mariam`, parent `C:\Users\Mariam\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, fetching `http://192.168.40.211/update/win-agent-2.4.1.bin` to `%TEMP%\svcupdate.dat`. The same server shows up in T6's rows on 2026-09-20/21: PowerShell under `Administrator`, parent `C:\Users\Public\splunkd.exe`, fetching `/api/v1/t1105-demo-artifact` to `caldera-demo-t1105.txt`.
- **Both reached the Analyst.** The round-2 payload names the Caldera artifact 3 times, in T6's command-line footer near the end of a 23.8k-character payload. Round 3's payload names it twice.
- **The round-2 reasoning uses neither.** It mentions Caldera, T1105 and the Public `splunkd.exe` parent 0 times. It describes a "Round 3" that hadn't run yet. It weighs "the internal IP's clean VirusTotal score (92)" against H1 (B18), and reads OneDrive.exe as "whitelisted", which is H2's own wording (T7). Round 3, which held more of it, was cut off before any JSON (T15).
- **Broker share:** the payload went over budget with the facts last (B14), and the VirusTotal line for a private address (B18). Linking the two activities is synthesis's job.

**T20. Tasks aren't linked to hypotheses, but the contract's names say they are.** *Medium. Open (owner decision).*
- **By design today:** the planning prompt (`webapp/prompts/system_prompt.txt`) says at line 16 "Tasks must be a holistic evidence-gathering set designed to explore ALL possibilities. Do NOT map tasks to specific hypotheses", and for synthesis at lines 25–26 "do NOT assign findings to specific hypotheses. Every observation informs every hypothesis."
- **In the data:** `874ab334`'s six planned tasks carry only `task_id`, `question`, `entity` and `time_window`. The engine's task file requires a unique `hypothesis_id`, so `run_trace.to_task_file` sets `hypothesis_id = task_id`. On the way back, `HypothesisFindings.hypothesis` and the payload's `hypothesis` field hold the task's question, not an H1–H3 description.
- **Impact:** the names imply a link the prompt forbids, and the model takes them at their word. `874ab334` round 2 reasoned "Note that each task_id corresponds to a hypothesis in the plan". Nothing checks that every hypothesis got evidence, because nothing records which task tests which hypothesis.
- **Options (to decide):** (a) keep tasks separate from hypotheses, and rename the payload's `hypothesis`/`hypothesis_id` to the task's question and id, which is a contract change for Yousef; or (b) link them: each planned task names the hypotheses it tests, carried as a real `hypothesis_id`, so the gate can check coverage. That's a planning-prompt change on the Analyst side. Where the "do NOT map" rule came from is still to be confirmed.

**T21. A parent is judged by its name, not by what it ran.** *High. Open (Analyst).*
- **Evidence (`c90ca5f9`):** every OneDrive row has the one path `C:\Users\Mariam\AppData\Local\Microsoft\OneDrive\OneDrive.exe` (1,086 rows as the process, 40 as a parent). That's OneDrive's normal per-user install location, so a path check would not flag it. What it ran would: four kinds of PowerShell, all `-ExecutionPolicy Bypass`, sent to the Analyst in `facts`:

  | Events | Command |
  |---|---|
  | 26 | `Invoke-WebRequest` of `http://192.168.40.211/update/win-agent-2.4.1.bin` to `%TEMP%\svcupdate.dat` (the alert) |
  | 18 | `-EncodedCommand JABlAG4AdgA6AHUA…` (decodes to `$env:username`) |
  | 18 | `$count = (Get-Process).Count` |
  | 18 | `$targets = @('10.0.10.1','192.168.40.211',…)`, a sweep over a list of addresses |
- **Synthesis** scored H2, "OneDrive.exe initiated a scheduled background update", highest (80) and wrote that "the user's routine OneDrive usage" keeps H3 plausible. It never weighed what OneDrive.exe spawned. Same pattern as T4 (by name, not path), one level up: by name, not behaviour.
- **Fix (Analyst side):** for each parent, synthesis states what it spawned before scoring. A code fact can carry the child command lines per parent (B10/F8 already compute them). Since B22 the parent's own SHA256 is in `facts`; a task naming it as a `file_hash` gets VirusTotal.

**T22. Synthesis describes rounds and tasks that never ran.** *Medium. Open (Analyst).*
- **Evidence:** `874ab334` round 2 and `c90ca5f9` round 2 both reasoned over a "Round 3" that hadn't run yet, attributing findings to it. `c90ca5f9` also cited T1, which was dropped at handoff (T14). The payload labels rounds as `[BROKER FINDINGS - Round 2]`; the plan lists every task, run or not.
- **Fix candidates:** `plan_slim` lists only the tasks that were sent (T14), and the header says which round this is and how many have run.

**T23. The evaluation header never states the event time.** *Low. Open (Analyst).*
- **Evidence (`c90ca5f9`):** synthesis gets task windows and row times in UTC `Z`, but nothing in the evaluation prompt says when the alert's event happened. It has to infer it from the windows, which are widened to event ±1h (B19) or reach days back (T18).
- **Fix (Analyst side):** the evaluation header states it once, labelled: "event 2026-10-06T11:51:16Z, notable 2026-10-06T11:59:55Z", from `normalized_seed.event_time` and the notable's `_time`.

**T24. Task questions and row counts are cited as findings.** *High. Open (Analyst).*
- **Evidence (`89674d75`, round 2, TRUE_POSITIVE 98):**
  - "CrowdStrike telemetry revealed anomalous process behavior." No CrowdStrike source is connected. T4's *question* asked for CrowdStrike, and the Broker answered it from Sysmon in Splunk.
  - "followed by execution of svcupdate.dat". No row shows svcupdate.dat run. No row shows it written either: no Sysmon 11 names it in any task (B26).
  - "lateral movement attempts". No task returned any.
  - The refs list described T1 as "asset verification of 192.168.40.211". Nothing can verify that (B20).
- **Round 3 (95):**
  - "high-volume uncategorized Windows events (4688, 1, 4105) showing suspicious process activity". That's a count of rows the Broker couldn't categorise, not their content.
  - The `$env:username` encoded command was read as an indicator, which is T6's pattern.
- **Related:** T7 (alert and hypothesis wording cited). Here it's the task's wording.

**T25. Verdicts that meet the score rule are refused on one bad ref, or on the ref format.** *High. Open (decision pending).*
- **Round 2:** H1 98 against H3 78 met the rule (≥85, lead ≥20). 5 of 6 refs held. `T3:endpoint` was refused because T3's endpoint sub-analyst was cut off on both calls (B15) and produced nothing. One refused ref sends the whole verdict back (`run_trace.verdict_gate`), and T3's question returns as a gap.
- **Round 3:** 95 against 60. All 9 refs were written as `G1:T1:identity`, the task id followed by a `T1:` prefix, so all 9 were refused.
- **Effect:** two evaluations that met the score rule became more rounds, and the fourth flipped (T26).
- **Also:** the refs that held point at domains whose observations were all "omitted for size" (B14). The gate checks the stored findings, so the Analyst cited evidence it never read.
- **For Mohammed:**
  - Should the gate accept a verdict when most refs hold, dropping and reporting the bad ones?
  - Should a malformed ref like `G1:T1:identity` be normalised, or refused with the reason sent back to synthesis?
- **Recurred (`8807fafa` round 2, 2026-10-11):** TP 90 against 30 met the rule. All 3 refs were refused:
  - `T1:file` and `T3:file` name no domain or block (the Analyst's format).
  - `T2:network` had 4 observations and was refused only because two of T2's siem steps were recorded as incomplete with 0 rows. That was B28: their rows had been filed under other categories. The refusal read "step s1_net is ok" (B32).
  - `3bf5fce8` wrote block ids (`T1:processes#1`, `T3:connections#1`, `T4:file_events#1`), all held, and stopped after one round. Both runs' first evaluations were TP 90, so the gate, not the evidence, decided which took one round.
  - With B28 fixed, `8807fafa` would still have been refused on `T1:file`. Dropping bad refs and keeping the verdict when enough hold would have stopped it after one round.
- **Recurred in every round of `a818a3fd`, `e8d949af` and `942115f7` (2026-10-11):**
  - 5 of 6 rounds met the score rule and were refused on refs. In 4 of them the refused ref pointed at an endpoint domain lost to B15 (G3).
  - In one, the refused refs were cited blocks the gate misread (G1).
  - The sixth failed on scores, with no reason recorded (G2).
  - Registered as gate bugs G1–G3 under Webapp integration.

**T26. Synthesis reads gap tasks G1–G3 as hypotheses H1–H3, and copies scores from an evaluation that never ran.** *High. Open (Analyst; W8 compaction contributes).*
- **Evidence (`89674d75` round 4):** this was the first synthesis with a compacted round (W8).
  - Its reasoning maps "G1: Lack of explicit threat intel hits for 192.168.40.211 -> High confidence (98)". That's round 2's H1/H2/H3 scores read as G1/G2/G3.
  - It then describes a "Round 4" evaluation of H1 90 / H2 82 / H3 83. Round 4's evaluation was the one it was writing. It output exactly those scores, after 4,669 tokens of reasoning.
- **Outcome:** H1 went from 95 to 90 and H3 from 45 to 83 with no new evidence, because round 4 re-ran round 3's tasks (W10).
  - The reasoning says "the current evidence doesn't explicitly show a backdoor download". The alert's own command line is that download.
  - Round 4's payload names neither `svcupdate.dat` nor `win-agent-2.4.1.bin`: every observation and command line was omitted for size (B14).
- **Our share:**
  - The payload's `hypothesis_id`/`hypothesis` hold the task id and the gap text (T20), so "G1 … hypothesis" reads like a hypothesis.
  - `compact_round` sends earlier evaluations' `hypothesis_scores` back, which invites anchoring.
- **Fix candidates:**
  - Compacted rounds carry the questions, the answered domains and the gaps, but no scores.
  - The payload names a task as a task (T20 option a).

**T27. The first evaluation leans non-malicious.** *High. Open (Analyst planning and scoring).*
- **Evidence (first evaluation of the last 7 runs on `ar-f6eddb5b-df6`, H1 TP / H2 FP / H3 BENIGN):**

  | Run | Scores | Leading |
  |---|---|---|
  | `9410e664` | 20 / 70 / 90 | BENIGN (VERDICT_REACHED) |
  | `25965109` | 60 / 70 / 90 | BENIGN |
  | `99e26b1e` | 30 / 40 / 70 | BENIGN |
  | `5dc65b8c` | 78 / 95 / 88 | FALSE_POSITIVE |
  | `c90ca5f9` | 60 / 80 / 75 | FALSE_POSITIVE |
  | `874ab334` | 65 / 70 / 75 | none (lead 5) |
  | `89674d75` | 98 / 65 / 78 | TRUE_POSITIVE (refused, T25) |

  6 of 7 led with a non-malicious hypothesis on the same host, user and kind of activity.
- **Cause 1, hypothesis wording (planning).** H2 and H3 describe what the telemetry literally shows, plus an innocent motive. H1 adds claims no telemetry can show.
  - `5dc65b8c` H3: "OneDrive.exe launching the PowerShell session as part of its functionality". Every OneDrive → PowerShell row matches it.
  - `99e26b1e` H1: "decodes into malware that destroys critical system files or exfiltrates sensitive data". `89674d75` H1 names "DarkCrystal RAT".
  - Synthesis scores "how well the combined findings match that hypothesis description" (`system_prompt.txt:28,48`). A description that restates the rows always fits; one that adds attribution or impact loses on every row that doesn't show it.
- **Cause 2, credit from absence (T8).** Missing malicious specifics count *for* BENIGN.
- **Cause 3, commands read one at a time, at face value.** "The encoded PowerShell command decoded to '$env:username' indicates benign environmental verification" (`25965109`); "the decoded command reveals only environment variables" (`99e26b1e`). Each command looks harmless alone. Their combination is never weighed as a pattern: the parent process, `-ExecutionPolicy Bypass`, the address sweep, and the download from `192.168.40.211` to `%TEMP%\svcupdate.dat`. Same family as T21 (judged by name, not behaviour).
- **Cause 4, structure.**
  - There are two non-malicious hypotheses against one malicious one, scored independently (T9). A non-malicious one is nearly always the runner-up, and H1 must lead *both* by 20.
  - The BENIGN definition ("often due to a noisy or overly sensitive detection rule", `system_prompt.txt:9`) is always available as an explanation.
- **Broker contributions, already addressed:** VirusTotal on a private IP read as "clean" (B18, `874ab334`); 0 observations reaching the Analyst (B14). Sub-analyst wording such as "temporary directories containing diagnostic scripts" (`89674d75` L3) is interpretation, against B11's translate-not-judge rule.
- **Fix candidates (Analyst side, to decide):**
  - Each hypothesis names the observation that would confirm it *and* the one that would refute it. H2/H3 must name something checkable (a change ticket, a known deployment server, a signed updater), not the activity itself (T3).
  - Score from cited observations only. An absent observation leaves a score unchanged in both directions.
  - Before scoring, synthesis states what each parent spawned, as one sequence (T21).
  - Decide what the scores mean (T9). Mutually exclusive scores remove the two-against-one effect.

## Context pipeline

**P1. `event_time` is the detection time, not the activity time.** *High. Partly fixed (C6).*
- **Evidence:** the notable's `_time` is 15:04:02+03:00, which is when the search fired. Its `firstTime` is `2026-09-27T14:55:17` local, so 11:55:17Z, 9 minutes earlier. Before `58d39c3`, `event_time` was the browser's clock (`cecd266a`, SOC3).
- **Status:** now the notable's `_time` in UTC. It should come from `firstTime` or `orig_time`. `firstTime` has no offset, so take the offset from `_time`.
- **Fixed since (10-06, `run_trace.notable_event_time`):** `normalized_seed.event_time` is ESCU's `firstTime` with `_time`'s offset applied, in UTC.
- **Which times reach the Analyst (`c90ca5f9`, 2026-10-09).** The whole context contract goes to planning, so the Analyst sees every one of these:

  | Field | Value | What it is |
  |---|---|---|
  | `normalized_seed.event_time` | 2026-10-06T11:51:16Z | The activity: `firstTime` + `_time`'s offset. **The planning prompt anchors every window on this**, and `to_task_file` widens to it ±1h |
  | `finding.firstTime` / `lastTime` | 2026-10-06T14:51:16 | The same instant, local, **no offset**: read as UTC it is 3 h late |
  | `finding._time` | 2026-10-06T14:59:55+03:00 | The notable: when ES wrote it, 8.5 min after the event |
  | `finding.info_search_time`, `orig_time`, `time` | 11:59:54Z / 11:59:55Z (epoch) | The same notable time, as epochs |
  | `finding.info_min_time` … `info_max_time` | 11:49:00Z … 11:55:00Z (epoch) | The correlation search's own window, which contains the event |
  | `normalized_seed.ingest_time` | 2026-10-09T10:59:05Z | When the alert was imported into SmartOps |
- **What reaches the Broker:** only the task windows. The Broker never sees the alert's times, and `TimeWindowPin` sets every Splunk call to the task window.
- **Risk:** five different instants in one context, two of them without a zone (`firstTime`) or as bare epochs. `c90ca5f9` planned on the right one (T4/T5 end at 11:51:16Z); `874ab334` placed T3 a day early (2026-10-05). Candidate: send planning only `event_time` and the notable time, labelled, and keep the rest in the raw `finding`.
- **Open decision (Mohammed):** does planning still see the raw time fields beside UTC `Z` copies, or only the two labelled instants (`event_time`, a new `notable_time`)? The safer default is only the two. Not built until decided.
- **Optional (Splunk admin):** set the MCP service account's time zone to UTC. Then `_time`, `firstTime` and any `strftime` come back in UTC and the offset assumption goes away. B23 works without it.

**P2. The seed drops the command line and the parent path.** *High. Open.*
- **Evidence:** `normalized_seed.process.process_name` is filled from the form's *Signature / Action* field (`webapp/static/app.js:127`), not from the alert. `command_line` and `parent_process_path` are always `null`, and `entities` holds only `hostname` and `user`. The notable's `process` (the full command line with `-ExecutionPolicy Bypass`) and `parent_process` reach the Analyst only inside the raw `finding` dump.
- **Impact:** a direct cause of T4.
- **Fix:** map `process`, `process_name` and `parent_process` into `normalized_seed.process`, and add the parent image as an entity.

**P3. Hardcoded non-existent index.** *Medium. Open (C4).*
- **Evidence:** `source_context.index` is `"win_sysmon"` (`webapp/static/app.js:81` and `:104`). The data is in `windows_lab`.

**P4. OpenCTI lookups use the wrong types.** *Medium. Open.*
- **Evidence:** `powershell.exe` was queried as a *domain* observable. The `CISA AA23-347A` search returned unrelated malware (Royal, Uroburos, ZeroCleare, INCONTROLLER, WellMess) into the context.

**P5. The ESCU matcher scores rule names only.** *Medium. Open (C5).*
- **Evidence:** see T12. The corpus in the repo also lacks the `description` field that some runs' corpus had.

## Tool Broker and sub-analysts

**B1. Observations drop the parent path.** *High. Fixed (`e475a84`, 2026-10-05).*
- **Evidence:** rows with a masquerading parent (`C:\Users\Public\splunkd.exe` / `C:\Users\Administrator\Desktop\splunkd.exe`) in each run's `evidence.json`:
  - `cecd266a`: 15 / 10
  - `072fd610`: 12 / 10
  - `a8118db9`: 0 / 5
  - `04a15495`: **0 / 0**

  Where they were retrieved, **0** mentions reached the analyst payload. The observation read *"5 identical PowerShell commands under Administrator"*. `04a15495` never retrieved them at all and still concluded TRUE_POSITIVE (see T6).
- **Fix:** keep `ParentImage` (path) in the process-row projection and in the observation template.
- **Done:** parent path first in the projection (`0964e3a`); `tstats … datamodel=` sets categorised and `Processes.*` columns read (`616b27c`); rarest values in the summary (`b64c575`); siem prompt retries a 0-row sourcetype and groups by the parent path (`1cda901`). On `check-B1` the path reached the rows the endpoint sub-analyst was shown.
- **The narrative still drops it, and prompts can't fix that on 8B.** check-B1b added a full-path rule, and check-B1c added a parent-path slot to the worked example. On B1c the sub-analyst was shown the 4 Desktop-parent rows, cited their set, and described it as "disk cleanup and system checks". Both prompt edits were reverted. The same failure applies to every domain: the minority rows (a rare logon source, a rare domain, a rare parent) are what a few-sentence narrative drops.
- **Fix (`e475a84`):** each domain's finding carries `summaries`, the code-computed account (`formatting.summarise_rows`) of every non-empty set routed to it, cited or not. It crosses into `analyst-payload.json`, while raw rows still stay out. Live `check-B1d` passed: the endpoint summaries showed `C:\Users\Administrator\Desktop\splunkd.exe=4`, even though the narrative left it out. The size of this is capped (B9).
- **Live re-run `ded5cac1` (2026-10-05):** the path reached the Analyst. T3's endpoint summaries carried 5 sets with the parent `C:\Users\Administrator\Desktop\splunkd.exe`, and T4's showed `svchost.exe=33, C:\Users\Administrator\Desktop\splunkd.exe=24`. The synthesis prompt was 8,751 tokens, well inside the window. Synthesis still returned FALSE_POSITIVE 92 ("splunkd.exe is documented to execute such commands") and never mentioned the path. Delivery is fixed; reading the path is not, which is T4 on the Analyst side.
- **Open:** the webapp system prompt doesn't yet explain what `summaries` is, so it arrives as unexplained JSON. That's the likely next lever for T4. Also, on `ded5cac1` T5 sent no summaries at all: its long narratives used up the per-task share (B9).
- **Narrative names (B1c, this branch):** the narrative is what synthesis reads, and it names a file by its short name. `formatting.name_expansions` appends to each narrative, under *Names in this narrative, computed over every row*, one `~` line per file name the narrative mentions, giving the full paths and counts behind it over every routed row. At most 5 names, a name with several files first. Counts only, no judgement, and the model's prose is unchanged. Offline on `ded5cac1`'s stored reports, no model calls: T3 gives `"splunkd.exe" … is 2 files: C:\Users\Administrator\Desktop\splunkd.exe=26, C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe=20`; T4 gives `1 file: C:\Users\Administrator\Desktop\splunkd.exe=180`; and T5, which sent no summaries, now carries the Desktop path too. Whether synthesis reads it still needs a replay or a live run.
- **Live run `e1461da6` (2026-10-05, 2 loops, Broker $0.49 + $2.58):** the path reached the Analyst both ways. The L2-T1 endpoint narrative itself wrote *"Eight of these runs had parent process C:\Users\Administrator\Desktop\splunkd.exe"*, and the L3-FU1 name line read `"splunkd.exe" … is 2 files: …SplunkUniversalForwarder\bin\splunkd.exe=211, C:\Users\Administrator\Desktop\splunkd.exe=44`. Loop 2 synthesis quoted the Desktop parent in its reasoning, and still called splunkd "a legitimate application". Loop 3 returned TRUE_POSITIVE 98 on the encoded commands and the downloads from `192.168.40.211`, without the path (T13). Seen once: when a narrative names many single-path helper binaries (the forwarder's `splunk-*.exe`), they fill the 5 name lines.
- **Synthesis replay on `ded5cac1` (2026-10-05, two FS8B calls at temperature 0, same prompt and message except the narratives):** arm A had the stored narratives, arm B the same narratives plus the name lines. Arm B's message carried all 3 name footers (`Desktop` 9 times against 6), and **neither arm's reasoning cites the Desktop or Public path**. B's reasoning mentions splunkd 5 times, only through the hypotheses' wording and the plan. Both returned TRUE_POSITIVE (A 98 with H1 92 / 38 / 45; B 90 with 90 / 30 / 20), on PowerShell enumeration, `Invoke-WebRequest` and network activity, which is T6's pattern, not the masquerade. The original run was FALSE_POSITIVE 92, so the flip comes from the evaluation header and plan_slim of `330d1bc` (it already shows in arm A), not from B1c. One sample per arm, so that flip is also within T2's instability. **Result: delivery is fixed up to the Analyst's input, and the 8B Analyst still doesn't use the path.** Further prompt work on the Analyst is T4, on the Analyst side.

**B9. The handoff to the Analyst had no size limit.** *High. Fixed (`e475a84`).*
- **Evidence:** B1's summaries took T3's payload from 2,428 to 17,011 characters, and added 27,443 across `072fd610` round 2. The Analyst has a 32,768-token window with 4,096 reserved for output, and the webapp resends every earlier round in each synthesis call (`max_loops` 3). Uncapped, round 2 would probably overflow.
- **Fix:** `HANDOFF_CHAR_BUDGET` (`subagent_analysts/packing.py`) is worked out from the Analyst's window: window − output − 4,300 tokens for the system prompt and plan (measured on `072fd610`) − margin, ÷ 3 rounds. That's about 20.7k characters per round, split across the file's tasks. `HypothesisFindings.for_analyst(max_chars)` always keeps narratives and observations, adds summaries with cited sets first, and records how many it left out. Full summaries stay in `findings.json`.
- **Offline, `072fd610` round 2:** the batch is 19.6k characters. T7 keeps `processes#1`, whose powershell parents are only `C:\Users\Administrator\Desktop\splunkd.exe=3, C:\Users\Public\splunkd.exe=2`. A compact format (dropping time and single-value lines) was measured and rejected: it saved only 22%, and the single-value lines carry the signal.
- **Batch water-fill (B9a, this branch):** on `ded5cac1` the round's budget was split evenly per task (6,915 each), then evenly per domain. T3 left 2.3k unused while T5, whose narratives and observations alone took 6,520, sent none of its 31 summaries. `contracts.pack_for_analyst` now packs the whole batch from one budget: the narratives always cross, and the rest is filled smallest need first, with what each domain leaves (including crumbs) passed on. `for_analyst` is its one-task case. Re-packed offline from the stored findings: batch 20,569 of 20,745 characters, and every domain with summaries sends some. T3 sends 2 + 3, T4 4 + 2 + 1, and T5 3 + 3 + 1, up from 0. The per-run `analyst-payload.json` keeps its per-task share.
- **Live `e1461da6`:** the round 3 batch was 20,587 of 20,745 characters, and all 9 domains across FU1–FU3 sent at least one summary. Before, a long-narrative task sent none.
- **Open (webapp):** resending only the latest round, instead of every round, would triple each round's budget. Then set `_ANALYST_ROUNDS` to 1.
- **Overrun (`dce405e5`):** the batch payload was 23,532 characters against the 20,745 budget. Narratives always cross, and one endpoint narrative carried 11.3k characters of code-written `enc#` lines (B10c), so the budget can't hold when narratives alone exceed it.

**B2. Narrow task windows miss the activity.** *Medium. Open (follows P1).*
- **Evidence:** `072fd610` T1 and T4 searched `12:04:02–12:05:02Z`; the command ran at 11:55:17Z. Only the broad tasks found it.

**B3. Steps planned for families with no tool.** *Medium. Fixed in `58d39c3`.*
- **Evidence:** `cecd266a` called `investigate_edr` 3 times ("tool not found in registry").
- **Fix:** `plan_fetch` refuses such plans and points the model to siem. No recurrence in 3 later runs.

**B4. Time-zone misread in the sub-analyst evidence.** *High. Fixed in `58d39c3`.*
- **Evidence:** `cecd266a` said *"no process activity"* in a `14:53:35Z` window, then listed rows at `17:53:53+03:00`, which is the same instant.
- **Fix:** row times are rendered in UTC.

**B5. A subagent hit its output-token cap.** *Medium. Open.*
- **Evidence:** `cecd266a` T4: 19 queries used up the cumulative 12,000-token cap, and the recovery call also produced no structured answer. The evidence was kept, but the summary was lost.
- **Since:** not reproduced in the 4 runs after it (`072fd610`, `04a15495`, `a8118db9`, `ded5cac1`: 0 "no structured answer" lines). Why the recovery failed can't be told from the record, because the recovery's own `stop_reason` was overwritten with the first loop's. It is now logged first (`recovery call stop_reason=… answered=…`), so the next occurrence can be diagnosed. No fix until then.

**B6. Follow-up tasks inherit every entity and the widest window.** *Medium. Open.*
- **Cause:** the synthesis prompt emits only a question per follow-up (see the `ponytail:` note in `run_trace.follow_up_tasks`).
- **Impact:** follow-ups are broad by construction. This contributes to T6.

**B7. Unconnected families were named in what the models read.** *Medium. Fixed on this branch.*
- **Evidence:** `cecd266a`: 3 `investigate_edr` calls, and "EDR not available" in the classifications. `check-T3` (after the description fix): the plan rationale still said "EDR may also have relevant file/process telemetry".
- **Cause:** four paths that ignored configuration. The static domain descriptions ("use investigate_edr"), the subagent's `gaps:` instruction, the `plan_fetch` schema's `family` enum, and the `TaskClassification.tool_families` enum.
- **Fix:** `domains.describe()` names a redirect only when its target is configured, and tells the Broker Splunk holds endpoint and network telemetry when EDR or NDR is absent. The `gaps:` line and both schema enums list configured families only, and `investigate()` drops unconfigured families from `answer.gaps`. `family_is_configured` now lives in `tools/registry.py`.

**B8. `tstats` was unreliable.** *Medium. Fixed on this branch.*
- **Evidence:** 34 of 143 `tstats` calls used `Processes.host` or `All_Traffic.host` (the CIM field is `dest`) and returned 0 rows silently. On `072fd610`, one narrow empty `tstats` marked `Endpoint.Processes` dead and cancelled 34 later calls, while the model held 106 rows on a wider filter.
- **Fix:** the siem prompt lists the CIM field names per data model. `TstatsDeadEndGuard` learns deadness only from an unfiltered query (no `where`, or only `nodename=`), and cancels a `tstats` that names `host`, `Computer`, `CommandLine`, `Image` or `ParentImage`, giving the CIM field to use.
- **Not covered:** narrow windows (B2, follows P1).

**B10. Encoded PowerShell was fetched but never decoded.** *High. Fixed on this branch.*
- **Evidence:** on `e1461da6`, FU1 asked the Broker to "decode base64-encoded arguments in PowerShell commands". The rows held `-EncodedCommand JABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQA=` 24 times. Nothing could decode it, so FU1 came back as "encoded commands" again, and synthesis treated "persistent encoded PowerShell" as its main TRUE_POSITIVE reason. The command decodes to `$env:username`.
- **Cause:** the follow-up asked for a transformation, not a retrieval, and no tool could do one. The Broker never sees rows (`_digest` sends counts, not content), so it couldn't have done it in context either.
- **Fix:** a Strands `@tool` on the Broker agent, `decode_encoded_commands(step_id)` (`tools/native/decoder.py`). The Broker names a step it already dispatched. Code finds that step's results through `StepOutcome.result_ids` (O2), base64-decodes every `-EncodedCommand`/`-enc`/`-e` argument as UTF-16LE, and writes the text onto the row as `decoded_command`, first, so key-capped generic rows still show it. The processes line renders it as `decoded=`. The Broker gets only `rows=N decoded=M` back, so the "counts, not content" rule holds. Lookalikes are rejected: `-ExecutionPolicy` isn't an encoded flag, and `-e Bypass` decodes to non-ASCII noise. The Broker prompt says to fetch the command lines first, then decode by step id.
- **Offline on `e1461da6` FU1:** 11 rows annotated, each rendering `decoded=$env:username`, including tstats rows whose command-line column the row line never showed (`cmdline=-`).
- **Ceiling:** one transform, base64 of UTF-16LE. Layered obfuscation (gzip inside base64, `-bxor`, `[char]` arrays) would need a real deobfuscator, which is the case for adding CyberChef. Whether the Broker calls the tool for a "decode" follow-up still needs a live run.

- **Live `67da804d` (2026-10-05): the step-id design misses.** The encoded rows were in T1, T2, T4 and T5. The Broker called the tool only on T3, the one goal that said "encoded", and T3's rows had none. The Broker can't know which step holds an encoded command, because it never sees rows.
- **Rework (B10b), Mohammed's design: tag in loop N, decode on request in loop N+1.**
  - **Tag:** after each task, code records every real encoded argument in `<runs_root>/<run_id>/encoded.json` under a stable `enc#<sha1[:6]>` signature (`decoder.record`, called from `main.py`).
  - **Show:** the sub-analyst handoff lists the signatures next to the narrative: `~ encoded command enc#784267: 2 events, parent …\Desktop\splunkd.exe=1`. The plain text isn't shown until a task asks for it.
  - **Decode:** in a later loop, a task that names the refs (or just asks to decode) leads the Broker to call `decode_encoded_commands(refs)`. Code writes `~ enc#784267 (parent …) decodes to: $env:username` into `BrokerReport.decoded`, and `gather` puts it in the endpoint narrative under "Decoded by code, on request:". No sub-analyst call is made. The Broker still gets counts only.
  - **Removed:** the step-id path and the `decoded=` row rendering.
- **Offline on `67da804d`:** the four tasks give one signature, `enc#784267`, which decodes to `$env:username`.
- **Live `dbb0e75c`:** the registry was written, and the payload carries 4 `enc#784267` lines. Synthesis then hit the 4,096-token cap with no JSON (T15), so there was no follow-up loop. The decode path in loop N+1 is still unproven live.
- **Ceiling:** it only works if the Analyst asks for the decode. A run that stops after loop 1 never decodes.
- **Live `9322c93a` (2026-10-06):** that ceiling was hit. Loop 1 tagged 32 commands and the Analyst returned TRUE_POSITIVE 98 with no follow-up, citing "obfuscated PowerShell" it never read; `decode_encoded_commands` was never called. The reasoning never named the `Desktop\splunkd.exe` and `Public\splunkd.exe` parents. The earlier run `67da804d`, on the same notable, said BENIGN 95.
- **Rework (B10c):** code now decodes in the loop that sees the rows. Each handoff line carries the plain text, e.g. `~ encoded command enc#784267: 87 events, parent …\Desktop\splunkd.exe=…; decodes to: $env:username`. It states facts only; what a parent path means is the Analyst's call. The on-request path is removed: the tool, `encoded.json`, `BrokerReport.decoded` and the Broker prompt paragraph. Offline on `9322c93a`'s rows: 32 signatures, about 5.5k characters of decoded text.
- **Live `dce405e5` (2026-10-06):** 39 decoded lines reached the payload, all in T4's endpoint narrative, including `enc#784267 … decodes to: $env:username`. Synthesis quoted decoded content ("installing Atomic Red Team, modifying inputs.conf"), text that appears only in the decoded lines, so it reads them. It didn't cite `$env:username` or its Desktop/Public parents (T13).
- **Open: the decoded block crowds out the summaries.** The T4 endpoint narrative was 12,957 characters, 11,313 of them `enc#` lines, mostly Ansible WinRM wrappers and forwarder config edits. Narratives always cross (B9a), so every domain in the batch was cut to 1 summary (4–8 omitted each), and the payload overran its budget (B9). Candidates: move the `enc#` lines into the droppable summaries tier, or cap the block (e.g. rarest parent first, N lines, "… M more in findings.json").
- **Not handled:** 6 commands decode to a second `-EncodedCommand` (the Ansible exec wrapper under `cmd.exe`). Splunk cut their command lines at about 2k characters, so the inner command is incomplete.

**B11. Sub-analyst narratives judge and misread fields.** *Medium. Open.*
- **Evidence (`dce405e5`):**
  - **Judging:** T1 endpoint: two PowerShell processes "contained suspicious commands involving $uri = 'http://192.168.40.211/update/'". "Suspicious" is the Analyst's call; the sub-analyst's job is to translate.
  - **Field misread:** T2 network: "splunkd.exe processes connecting to two endpoints (C:\Users\Administrator\Desktop\splunkd.exe and C:\Users\Public\splunkd.exe)". Those are the processes' image paths, not connection endpoints.
  - **Count misread:** T4 identity: "Over 10849 events, the Administrator successfully logged into 10849 destinations". The event count is reported as a count of distinct destinations.
  - **Detections read as telemetry:** T1's "two PowerShell processes on host localhost.localdomain at 12:04:02 and 12:04:55 UTC" came from the siem subagent's `index=notable powershell.exe` and `index=risk powershell.exe` searches, not from endpoint events. The 12:04:02 row is this alert's own notable (`host` is the ES server, the time is when the search fired), and the 12:04:55 one is another ES detection (`$uri = 'http://192.168.40.211/update/win-agent-2.4.1.bin'`). The rows were left uncategorised, and the narrative presented them as process executions on a second host. The alert was counted as evidence about itself.
- **Impact:** synthesis repeated T1's "suspicious" as "clearly malicious" (T7's pattern, one layer down), and its "T1 shows malicious PowerShell commands" rests on ES detection records, not on telemetry.
- **Fix:** to be decided. Prompt rules have failed on the 8B sub-analysts before (B1b, B1c), so a code-side check is the likelier lever: flag verdict words in a narrative, and compare the numbers a narrative states against the set's computed summary.
- **Logon type (`3bf5fce8`, 2026-10-11):** "five successful remote interactive logons … logon type 5 (remote interactive)". Type 5 is a service logon. Fixed on `broker-k4-ab-fixes`: `formatting._field` writes `logon_type=5 (Service)` from the Windows table, so the model quotes a name it was given.

**B12. A sub-analyst cut off twice loses its whole domain.** *Medium. Fixed on `smartops-loop-fix`.*
- **Evidence (`78cd60ec`):** T1 endpoint's first reply and its re-ask both hit `max_gen_len`, and the payload carried "endpoint analyst produced no parseable finding after a re-ask" in place of the domain's narrative. The narrative itself had been written.
- **Fix:** when the re-ask is also cut off, `analyze._invoke_with_one_reask` parses the reply without its last line (the one the limit cut through), and logs the dropped tail. If even that has no narrative, the domain is still reported empty.
- **Verified live (`b3aa0dd2` loop 4):** endpoint's re-ask hit the limit too; the finding was kept and the last line dropped. The dropped line was a whole observation ending in its citation (`… repeated once [processes#2]`), so the limit fell between lines; dropping it anyway is the known cost of not telling a finished line from a cut one.
- **Still open:** endpoint was lost once in loop 2 and once in loop 3 with "re-ask still produced no parseable finding", not a cut-off. The parse error's reason was not logged; it is now, so the next run will say which rule failed.

**B13. The siem subagent probes indexes one by one.** *Medium. Fixed on `smartops-loop-fix`.*
- **Evidence (`c7dbf51d` T1):** queries ran against `windows_lab` (38), `win`, `botsv3`, `main`, `osquery`, `security_log`, `unix`, `notable` and `risk`. The host's events are all in `windows_lab`. The probing cost $0.45 of the task's $0.61.
- **Fix:** the siem system prompt now names the allowlist (`SMARTOPS_SIEM_INDEXES`, or the domain default) and asks for one `tstats … by index, sourcetype` over all of them before searching only the indexes that hold the host.
- **Live (`b3aa0dd2`):** T1's siem spend fell from $0.61 (`c7dbf51d`) to $0.32 on the same question; loop 2's five tasks cost $0.31–$0.73 each.

**B14. Code footers inside the narratives pushed every observation out.** *High. Partly fixed on `smartops-loop-fix`.*
- **Evidence (`874ab334`):** L2 sent 0 of 42 observations and 0 of 62 set summaries; L3 sent 0 of 37 and 0 of 113. Narratives always cross (B9a), and they were 18,968 (L2) and 28,391 (L3) characters, of which the code footers were 62% and 73%. The largest was the no-rows footer (F8): 26 lines in L2, 47 in L3. The batch still shipped over budget (23.8k and 31.8k against 16.5k), and the packer's warning never reached `broker-L*.log` (O6).
- **Fix:** the footers move to their own field, `facts`, on `DomainRecord` (renamed from `DomainJudgement`, which no longer judges) and `DomainNarrative`. `narrative` is the model's prose again. Over budget, `pack_for_analyst` drops empty-search lines first, then command lines, then summaries, then observations; names and decoded lines are kept, and each drop leaves an "omitted for size" line. The no-rows block is a count plus at most 3 searches, those naming the task's own entities first. Decoded text is cut at 400 characters, like command lines.
- **Still open: the budget itself.** Re-packed offline from 874ab334's stored findings, L2 is 17.3k and L3 20.1k against 16,480, still with 0 observations. The model's prose is 7.2k/7.6k, the JSON structure of 18 domain objects about 5k, and L3's kept decoded lines 5.2k. `HANDOFF_CHAR_BUDGET` assumes 2.5 characters per token; round 3's synthesis ran about 3.2. Options (to decide): re-measure the ratio, send the payload without indentation, or accept that observations give way at 6 tasks per round.
- **Recurred on `89674d75`:**
  - The payloads sent 0 observations: 51 were omitted in round 2, 59 in round 3 and 52 in round 4.
  - Every round warned that narratives alone exceed the budget.
  - With 3 tasks a round (rounds 3 and 4), observations still didn't fit, so it isn't only "6 tasks per round".
  - The command lines went too. Round 4's payload names neither `svcupdate.dat` nor the download URL. Synthesis then said no download was shown (T26) and asked FU1 to "extract full PowerShell command-line arguments", which the Broker had already fetched in rounds 2–4.
- **Cause (2026-10-11): the budget was set from assumptions that don't hold.**
  - **Characters per token:** the budget assumed 2.5, a rate measured on raw SIEM rows. The payload JSON measured 3.76 on `89674d75`: round 3's synthesis prompt grew 4,789 tokens for round 3's 17,985 characters.
  - **Rounds read in full:** the budget divided by 3, but synthesis reads 2 rounds in full (`FULL_ROUNDS`). Older rounds go as compact records of about 0.9–1.8 kB each.
  - **Headroom:** the largest synthesis prompt was 13.5k tokens against a 24.5k ceiling (the 32,768 window minus the 8,192 reply), so about 11k tokens went unused while every observation was dropped.
- **Done (`packing.py`):**
  - `_HANDOFF_CHARS_PER_TOKEN = 3.5` for the payload. The sub-analysts' 2.5 for raw rows is unchanged.
  - `_ANALYST_ROUNDS = 2`, matching `FULL_ROUNDS`. `tests/test_verdict_gate.py` holds the two equal.
  - `_COMPACT_ROUNDS_RESERVE = 4,000` tokens is set aside for about 10 compacted rounds.
  - `HANDOFF_CHAR_BUDGET` goes from 16,480 to 27,608 characters.
  - The trimming order is unchanged: empty searches, then command lines, then observations.
- **Replayed on `89674d75`** (stored findings re-packed):

  | Round | Observations sent | Command-line blocks kept |
  |---|---|---|
  | 2 (6 tasks) | 43 of 51 | 1 of 5 |
  | 3 (3 tasks) | 59 of 59 | 3 of 3 |
  | 4 (3 tasks) | 52 of 52 | 3 of 3 |

  - `svcupdate.dat` is in every round's payload.
  - Only empty-search lists were trimmed in rounds 3 and 4.
  - Summaries still give way: they're 34–54k characters a round untrimmed.
- **Ceiling:** a run past about 12 rounds outgrows the compact reserve (`ponytail:` note in `run_trace.compact_round`).

**B15. The endpoint sub-analyst is cut off on both calls, and the answer is lost.** *Medium. Diagnostics added.*
- **Evidence:** both calls hit `max_gen_len` (3,072 each, 6,144 billed) in `874ab334` L2-T2, T4 and T5, and in `25965109` T4 and T7. Not only large slices: 874ab334 T4's prompt was 3.8k tokens a call. The domain was lost with "no NARRATIVE block" (twice) and "no OBSERVATIONS or CITATIONS block" (once); the payload carried the placeholder sentence.
- **Cause:** not established. The thinking closed (1.5k characters were kept), so about 2,400 tokens of answer had no NARRATIVE block, and nothing recorded the answer.
- **Done:** when the re-ask fails, both replies' `stop_reason`, token count and the first and last 300 characters of the answer are logged. The prompt or `max_gen_len` changes wait for that evidence.
- **First logged failures (`89674d75`):** every reply was `stop_reason=length` at 3,072 tokens.
  - L2-T3 endpoint wrote 7,509 and 9,095 characters of answer.
  - L4-G2 network wrote 11,234 and 8,628.
  - It isn't the thinking. Every reply starts `NARRATIVE:`, and the answer runs out while copying full PowerShell command lines into the narrative and observations.
  - L2-T3's re-ask repeated one sentence ("Host … ran processes under user … started by OneDrive.exe; one command line, …") until it was cut off.
  - It's not endpoint-only: L4-G2 is the network domain.
  - T3's empty endpoint domain later cost round 2 its verdict (T25).
- **Options (to decide):**
  - Cap quoted command lines in the sub-analyst's rows (they're already in `facts`).
  - Raise `max_gen_len`.
  - Stop the re-ask when the first reply was cut off, and treat it as a length failure, not a format failure.
- **Cause (2026-10-11): the prompt asked for output that grows with the number of sets, under a fixed 3,072-token cap.**
  - The narrative rule was "one short paragraph per evidence set … two to five sentences for a set with rows, one sentence for a set with none. Every set you were given must appear in it."
  - L2-T3 endpoint was given 16 sets with rows plus about 11 empty ones. L4-G2 network was given 18 sets plus the empty ones.
  - The template also showed the shape "one command line, `<command>`", so the model retyped full command lines.
  - L4-G2's replies then cited `dns_resolutions#145` through `#371`, one by one. Those ids don't exist, so it was a counting loop, not real citations.
- **Already in place, so not changed:**
  - Rows already cut command lines at 200 characters (`formatting._CMDLINE_LIMIT`).
  - A cut-off reply already gets a length-specific re-ask ("keep it short"). If that reply is also cut off, the finished lines are salvaged.
  - `max_gen_len` stays at 3,072, because raising it takes evidence space from every domain.
- **Done (`prompts.py`, every domain):**
  - The narrative has one paragraph per kind of activity, and sets of the same kind share one paragraph, cited to each.
  - It stays under 400 words however many sets there are.
  - Long values (command lines, scripts, URLs) are named by their first few words and cited, because code passes the full text on.
  - `rows=0` sets are left out: code already lists every empty search in `facts`.
  - The endpoint template now reads "one command line, starting `<first few words>`".
- **Live check:** no `stop_reason=length` in `broker.log`.
- **Recurred (`8807fafa` L2, 2026-10-11):** endpoint on T3 (36 file events) and T4 (20 processes) hit 3,072 tokens on both calls, and both domains were lost. Every reply repeats the grouping example's sentence ("Host … ran processes under user …, started by …; one command line, starting …, repeated") for group after group, including for file-event rows. The per-set rule is gone, so the loop is the example being copied, not the set count.
- **Change waiting (`broker-k4-ab-fixes`, uncommitted):** all three bodies say "write each group once: never write the same sentence twice", and the endpoint body says the shape is for process sets only. It ships after a replay of `8807fafa` L2 T3/T4 endpoint shows no repeat and no `stop_reason=length`. The replay on 2026-10-11 could not run: Bedrock rejected the API key in `.env`.
- **Recurred live with that prompt (`a818a3fd` L2-T4):** both replies repeated "Host … started by OneDrive.exe; one command line, starting powershell.exe, repeated." to 3,072 tokens, and the domain was lost. The prompt lever failed.
- **Code lever (`9190ad4`, `broker-a818-fixes`):** each sentence of 40+ characters is kept once before parsing; the re-ask quotes the looped sentence and its count; when both replies are cut off, the first reply's finished lines can be salvaged too. The prompt text was committed beside it (`broker-a818-fixes`).
- **Live (`e8d949af` tier B, `942115f7` tier A), the dedupe helps but doesn't close it:**
  - Repeats were dropped in 17 replies (4 to 123 sentences each). Endpoint parsed after a drop on `942115f7` L2-T1 (123 dropped), L2-T2, L3-G1 and L3-G4.
  - Endpoint was still lost 6 times, both calls at 3,072: `e8d949af` L2-T1, L2-T2 and L3-G1 (every endpoint domain with rows in that run), and `942115f7` L2-T3, L3-G3 and L3-G5.
  - The loops that survive are near-duplicates: the same shape sentence with a different parent or user per process group, so no two are identical. With 20 rows a set and many distinct parents, the shape template alone fills the 3,072 tokens.
  - Every lost endpoint domain then refused its round at the gate (G3).
- **Next lever (to decide):** stop asking the model to enumerate process groups. Code already computes the per-set summaries; the narrative could describe the set in a fixed number of sentences, with the group list carried in `facts`. Alternatives: a per-domain `max_gen_len` for endpoint, or cutting at the first near-duplicate (same sentence with values masked).
- **A/B (2026-10-11), the 6 lost endpoint slices, one first call each at temp 0:**
  | Prompt | Parsed |
  |---|---|
  | Current | 0/6, every reply the example sentence to 3,072 tokens |
  | OBSERVATIONS first | 2/6, the loop moved into the observations |
  | OBSERVATIONS first, no example | 4/6; one copied the grounding rule's `(e.g. …)` quote, one skipped NARRATIVE |
  | O → N → C, no example, no grounding quote | 5/6; T2 wrote one observation per grouped row and ran out before NARRATIVE |
  | **NARRATIVE first (unchanged), no example, no grounding quote** | **6/6**, 500–900 tokens; 942115f7 L2-T3 still hit the cap, but on a citation loop after the narrative |
  - The narratives now carry what the old prompt lost on all six, e.g. the OneDrive → PowerShell → download chain.
  - The near-duplicate cut and a larger `max_gen_len` were not tried: a cut after generation still has no OBSERVATIONS to save, and a loop fills any cap.
- **Done (`prompts.py`, every domain):** the per-group SHAPE sentence is replaced by one shared `_grouping_block`: one or two sentences per kind of set, naming the values its computed summary lists first, never one sentence per value. The three grounding `(e.g. …)` quotes are gone. The block order is unchanged.
- **Verified through `gather_finding` (production path):** the 6 tasks, all 3 domains: every domain with evidence (15) parsed, no re-ask failed. Two network replies still over-ran (9 repeats collapsed; 29 observations against the 10 limit) but parsed.
- **Waiting on Mohammed:** a code safety net (a cut-off reply with cited observations and no NARRATIVE keeps the observations); dropping the length re-ask (it repeats itself at temp 0).
- **Held live (`2a71757f`, tier A, 5 tasks):**
  - No `stop_reason=length`, no repeated sentence dropped, and no re-ask in any of the 15 domain calls.
  - The sub-analyst phase took 44 s, against 1m19s–2m14s on the 10-11 baselines.
  - Every endpoint domain with rows reached the payload, and the gate accepted all 4 endpoint refs.
  - The narratives describe the OneDrive → PowerShell → `win-agent-2.4.1.bin` download in four tasks.
  - Still open: narratives carry copied times and counts that the prompt forbids, and T3 calls event codes 4100/4104 "blocked scripts" (B11).

**B16. VirusTotal re-queries the same indicator in every task; tasks run in sequence.** *Medium. Cache fixed; parallel tasks deferred.*
- **Evidence:** `25965109` looked up one hash 7 times in one round. Round 2 of `874ab334` took 10.5 minutes, 1–4 minutes per task, one after another.
- **Fix:** `virustotal._lookup` caches answers per process (one round); errors aren't cached, so a rate limit is retried. Running tasks in parallel stays deferred (`main.py` phase A, Splunk quotas) until a live run measures the headroom.

**B17. A PID sent inside the process name.** *Low. Fixed on `smartops-loop-fix`.* `process=powershell.exe (PID 12345)` crossed as one value; `to_task_file` now sends `process=powershell.exe` and `process_id=12345`. `12345` also looks like an Analyst placeholder.

**B18. VirusTotal was queried for a private IP, and the result read as clean.** *High. Fixed on `smartops-loop-fix`.*
- **Evidence (`874ab334` T2):** the Broker looked up `192.168.40.211`, an RFC 1918 address. The network narrative said "a reputation check … resulting in a score of 92 with no detected threats", and synthesis weighed "the internal IP's clean VirusTotal score (92)" against the malicious hypothesis. VirusTotal holds no meaningful reputation for a private address.
- **Fix:** a non-global IP is never sent: `queryable_entities` leaves it out, and a model-called lookup returns "private address, not looked up" without a request.

**B19. Lookup tasks with a zero-length or no window are dropped.** *High. Fixed on `smartops-loop-fix`.*
- **Evidence (`c90ca5f9`):** T1 (full path of `svcupdate.dat`), T2 (is `192.168.40.211` part of the organisation's infrastructure) and T3 (hash of `svcupdate.dat`) each had start = end = `2026-10-06T11:51:16Z`, the event instant. They're lookups, not questions about a period; the schema makes the Analyst write a window anyway. `run_trace.to_task_file` checks `start < end` before it widens every window to event ±1h, so all three were dropped: the three that would have answered the run's own questions.
- **Fix (planned):** widen first, check after: a missing or zero-length window becomes the alert's own window (event ±1h). A task is dropped only if its window is unusable even then. T2 isn't a search at all (B21).
- **Done:** `to_task_file` widens to event ±1h first and checks after; every window it sends is written in UTC `Z`. With no event time, a zero-length window is still dropped, costing only its own task. Test: c90ca5f9's T1 goes out as 10:51:16Z–12:51:16Z.

**B20. Follow-ups repeat the round's searches, and questions no source can answer are fetched anyway.** *Medium. Open.*
- **Evidence (`c90ca5f9` round 3):** FU1 ("file reputation for svcupdate.dat using VirusTotal") had no hash in scope (T3, which would have found it, was dropped), so the Broker ran SIEM searches instead. FU2 ("is svcupdate.dat in trusted software repositories or patch management systems") names a source nothing connects to. Both re-ran round 2's file-event and process searches (Sysmon 11/23/26 and 1 on the same file and process): $1.56 for no new evidence. Neither came back saying it couldn't be answered. With B6, every follow-up also carries the union of the round's entities and its widest window.
- **Fix (planned):** the Broker's plan states when a question needs a source or an observable it doesn't have, and the step returns that as the answer instead of substituting searches. Scoping follow-ups to the task they follow (B6) cuts the repeats.
- **Split by owner (2026-10-09):**
  - **Scoping (Analyst side):** synthesis `follow_up_tasks` carry only a question, so the handoff can't tell which task a follow-up follows and gives it the round's union (`run_trace.follow_up_tasks`). Ask: each follow-up names the task it follows (`follows: "T3"`), or carries its own `entity` and `time_window`. The handoff then inherits that task's scope; a follow-up with neither keeps today's union.
  - **"Can't answer" (Broker side):** changes the Broker prompt and plan contract. To be framed and agreed before coding.
- **Again on `89674d75`:** none of these were reported back as unanswerable. Each was fetched as SIEM searches instead:
  - T1: "authorized software distribution point within the organization's asset inventory".
  - T4: "CrowdStrike telemetry".
  - G1: "threat intel hits" for a private IP.
  - FU2: "map … to organizational maintenance procedures".
  - FU3: "validate file integrity … through digital forensics tools".

- **Proposed design (2026-10-11), for agreement:**
  - The Broker's system prompt lists what each connected source can answer: Splunk for host, network and auth telemetry, and VirusTotal for public IPs, domains and hashes. It also lists what nothing connected can answer: asset inventory, CMDB, patch management, EDR consoles and forensics tools.
  - `plan_fetch` gains an optional `unanswerable: [{question, reason}]`, filled when a question needs a source or an observable the Broker doesn't have.
  - `unanswerable` items cross to the Analyst as gaps, worded "no connected source holds …", with no SIEM substitution.
  - A task that is entirely unanswerable dispatches nothing and costs only the planning call.
  - On `89674d75` this would have caught T1 (asset inventory), T4 (CrowdStrike), G1 (threat intel on a private IP), FU2 (maintenance procedures) and FU3 (forensics tools).
- **Done (agreed 10-11), `broker-a818-fixes`:**
  - `FetchPlan.unanswerable: [Unanswerable{question, reason}]`. A plan may have no steps when it has unanswerable questions, and then dispatches nothing.
  - The Broker prompt has a "QUESTIONS NO SOURCE CAN ANSWER" block. It names no unconfigured family (B7): a product the Broker has no tool for is covered as "any product whose tool is not offered to you".
  - The plan's items go to `RetrievalSummary.unanswerable` (findings.json) and `AnalystPayload.unanswerable`, as lines worded by code: `No connected source holds this: <question> (<reason>)`. The size budget never trims them.
  - **Webapp half (routed):** the latest round's payload JSON reaches synthesis unchanged (`webapp/main.py:738`). `run_trace.compact_round` may drop the field for earlier rounds.
  - **Held live (`451334ad`):** T2 and G1 each recorded "present right now" and "current ACLs" as unanswerable, and the lines reached the payload. Still open (Analyst side): L2 synthesis re-queued the same question as gap G1, spending $0.31 for the same answer.

**B21. A private address isn't stated as one.** *Medium. Fixed on `smartops-loop-fix`.*
- **Evidence (`c90ca5f9` round 2):** synthesis called `192.168.40.211` "external". It's RFC 1918. Since B18 VirusTotal no longer reports on it, and nothing else says what it is.
- **Fix (planned):** a code fact for each IP entity and each address in the rows' destinations: "192.168.40.211: private (RFC 1918) address". Computed, not judged.
- **Done:** a `facts` block, "Private addresses in these rows and this task", lists the scope's private IPs first, then every private IPv4 in any row value, capped at 8. The address in c90ca5f9 sat in a download URL, not an address field. One check (`virustotal.is_private_ip`, `is_global`) serves both this and VirusTotal's skip. Over c90ca5f9's rows it lists `192.168.40.211` (150 events), `192.168.40.212`, `10.0.10.1`, `10.0.10.20` and `127.0.0.1`.

**B22. The parent process's hash never reaches the Analyst.** *Medium. Fixed on `smartops-loop-fix`.*
- **Evidence (`c90ca5f9`):** 6 rows carry OneDrive.exe's own SHA256 (`DCC9F3B8D19239C39E0152B4ECC35036A17B5D5A81E9CC9AB989795EF19C2254`). `alert_entities` adds the alert's `file_hash`, which here is powershell.exe's image hash. No task named the parent's hash, so VirusTotal was never asked whether this OneDrive.exe is Microsoft's.
- **Fix (planned):** the hashes of the alert row's process and its parent both go into the alert scope, so the Broker can choose VirusTotal for either.
- **Correction:** the alert context has no hash at all. c90ca5f9's notable names the process and parent by name and path only, so `alert_entities` has nothing to add. OneDrive.exe's hash came only from round 3's Sysmon rows (FU1), and it never reached the payload.
- **Done instead:** a `facts` block, "File hashes in these rows", gives each file's SHA256 with its event count, scope files first, capped at 8. For Sysmon, the hash belongs to `ImageLoaded`/`TargetFilename` when the row names one, else to `Image`. Over c90ca5f9's rows: OneDrive.exe `DCC9F3B8…` and powershell.exe `1C84C863…`. The Analyst can now ask a `file_hash` task, which the Broker sends to VirusTotal.

**B23. Row times reach the sub-analysts in several zones and formats.** *Medium. Fixed on `smartops-loop-fix`.*
- **Evidence (`c90ca5f9`):** rows carried `first_seen`/`last_seen` as 18 epochs and 12 naive `10/05/2026 14:…` local strings, and Sysmon's `UtcTime` naive (it is UTC). `formatting._utc` converted only `_time`/`time`/`timestamp`, so the rest passed through unconverted beside UTC task windows.
- **Done:** `formatting.utc_row` converts every time-named field (time/first/last/earliest/latest/utc) once, before rendering, in `format_row`, `format_result_set` and `summarise_rows`. Epochs (10 digits) and offset-bearing values → UTC `Z`; `UtcTime` is read as UTC; a naive value takes its own row's `_time` offset, otherwise it is marked `(zone-unknown)`, never guessed. The siem prompt now asks for times as Splunk stores them, not `strftime`/`convert ctime` output. `tests/test_run_times_utc.py` walks the newest stored run's `tasks.json` and `analyst-payload.json` and fails on any time that isn't UTC `Z`.
- **Left alone:** the vended Splunk skill's `strftime(_time, "%Y-%m-%d %H:%M:%S UTC")` example labels search-head local time as UTC. It's third-party; the siem prompt rule overrides it.

**B24. The Splunk MCP session dies mid-round, nothing restarts it, and the round hangs.** *High. Fixed on `smartops-loop-fix`; live check pending.*
- **Evidence (`89674d75` round 5):**
  - FU1 finished at 17:51:09Z: 3 siem steps, 25 queries.
  - From FU2's first query on, every `splunk_run_query` failed at once with `MCPClientInitializationError: the client session is not running`. That happened 60 times (`L5/broker.log`).
  - Then no line for 21 minutes, until the run was stopped at 18:13:10Z. The webapp kills a round after 1,800 s (`webapp/main.py:835`), so left alone it would have ended at 30 minutes as a Broker failure.
- **Why every call failed:**
  - Strands' `MCPClient` keeps the session on a background thread.
  - If the transport raises after the handshake, the thread exits and `_close_future` resolves. This applies to any exception except "unknown request id" (`_handle_error_message`).
  - From then on `_is_session_active()` is false, and `call_tool_async` raises before sending anything (`strands/tools/mcp/mcp_client.py:911`).
  - The exception is kept in `_close_exception` and logged only at DEBUG, so the log doesn't say what killed the session.
- **Why nothing reconnected:**
  - `tools_for()` (`tools/registry.py:566`) calls `load_tools()`, which sees `_tool_provider_started` and returns the cached tools, still bound to the dead client.
  - `warm_mcp_clients()` does `stop()` then a restart, but only once, at process start.
- **Why it hung instead of failing:**
  - Each failure reaches the siem agent as an ordinary error result, so it kept calling.
  - No wall-clock limit applies to a fetch step. Nothing in the fetch path uses `asyncio.wait_for`. The 120 s `read_timeout` covers Bedrock only. MCP calls carry no `read_timeout_seconds`.
  - Which await blocked isn't recorded, so the exact cause of the hang is not established. The likely one is a call sent while the session was closing, whose future never resolves.
- **Trigger:** not established, because it was logged at DEBUG only.
  - The last thing the session served was FU1's `ps_scriptblocks` step: every 4104 script block on the host, 6.9 MB of evidence (B27).
  - The other transport failure seen before is splunkd's `500 bad character in reply size` (see `warm_mcp_clients`).
- **Fix (to agree before coding):**
  1. In `tools_for()`, a client that had started and is no longer active gets `stop()` and a fresh `load_tools()`. That's the reset `warm_mcp_clients` already does, applied at the one place every dispatch passes through.
  2. Log `_close_exception` at WARNING when that happens.
  3. A step whose tool returns "client session is not running" ends as `error` instead of spending its turns.
  4. A wall-clock cap per mission, so a stuck await ends one step, not the round.
- **Done:**
  1. `registry._reset` is shared with `warm_mcp_clients`. It catches the `RuntimeError` that `stop()` raises from the dead session, logs its cause at WARNING, and still re-claims `PROCESS_CONSUMER`.
  2. `_load_tools_off_loop` resets a client whose session has ended (`_session_died`) before `load_tools()`. It does this under the per-client lock, so parallel steps reset it once. A client whose startup failed never started, so it isn't retried on every step.
  3. `subagents._SessionWatch` counts calls refused with "the client session is not running" and sets `AfterToolsEvent.end_turn` after that batch. The recovery call reports what was already collected, and the step returns `ERROR` "MCP session lost (N call(s) refused)" with its evidence kept, so a re-dispatch reconnects through (2).
  4. `investigate()` runs the mission under `asyncio.wait_for(…, MISSION_TIMEOUT_SECONDS=900)`. A timeout returns `ERROR` with the evidence collected so far. The reservation is released, not settled, so a timed-out step's spend is missing from the ledger (marked `ponytail:`).
  - Tests: `engine/tests/test_mcp_session_and_result_size.py`. The watch was also checked through Strands' real `HookRegistry`.

**B25. The Broker writes the task's IP as the host's address.** *Medium. Open.*
- **Evidence (`89674d75` L2-T1, step `siem_processes`):** "process creation events on host ar-f6eddb5b-df6 (192.168.40.211)".
  - `192.168.40.211` is the download server in the alert's command line, not the host. The flows to it in the rows come from `10.0.10.20`.
  - The handoff adds the alert host to every task (`alert_entities`), and the Broker paired the two scope values.
- **Fix candidate:** the Broker's user turn labels each entity's role, since the alert row already says which address is the destination.
- **Done instead (2026-10-11):** the IP came from the Analyst's own task entities (`ip 192.168.40.211`, `host ar-f6eddb5b-df6`), which carry no role, so code has no role to label. `broker._prompt_for` now says, under the entities: "Each entity is a separate value: never write an ip as a host's address unless a returned row shows that host with that ip."

**B26. siem tasks disagree on whether svcupdate.dat is in the data, and `no_data` is reported beside returned rows.** *Medium. Open (check in Splunk first).*
- **Evidence (`89674d75` L3-G2, `siem_file_events`):**
  - Status `no_data`. The note says "svcupdate.dat does not appear in any indexed event for this host during the 2026-09-29 to 2026-10-06 window".
  - That came after 8 searches with `host="ar-f6eddb5b-df6"`, including `_raw="*svcupdate*"`, all returning 0 rows.
- **In the same round:**
  - L3-G3 ran `index=windows_lab sourcetype=XmlWinEventLog "svcupdate.dat"` with no `host=` and got 12 rows, all `Computer=ar-f6eddb5b-df6`.
  - The rows are Sysmon 1, 4104 and 4100 for four downloads: 10-05 11:42Z, and 10-06 10:40Z, 10:53Z and 11:51Z.
  - L2-T6 and L5-FU1 found the same rows.
- **Unexplained:** the visible difference is the `host=` filter. Why it returns 0 here is not established, because the rows don't carry `host`.
- **Status:** the same result held 150 file-event rows for other files and was still `no_data`. P-10's rule is "ok if any query or lookup returned data".
- **Also:** no task's rows hold a Sysmon 11 (FileCreate) for svcupdate.dat, so the file write itself is unconfirmed (T24).
- **Next:** run one query with and without `host=` in Splunk before proposing a fix.
- **Checked in Splunk (2026-10-11): `host=` isn't the cause.**
  - `index=windows_lab sourcetype=XmlWinEventLog "svcupdate.dat"` returns 15 events with or without `host="ar-f6eddb5b-df6"`. Splunk's `host` field is `AR-F6EDDB5B-DF6`, and search matches it case-insensitively.
  - The cause is how G2's searches ended: every one was `stats … by EventCode, TargetFilename, Image, ProcessId, User` (or `… NewProcessName`).
  - On raw events, `stats … by` drops every event missing any by-field. Sysmon 1 and 4104 rows have no `TargetFilename`, so all 15 were dropped.
  - The same search returns 0 rows as G2 ran it, and returns the Sysmon 1 rows when `| fillnull value="-" <by-fields>` comes first.
  - G3 found the rows because its search had no `stats`.
- **Done:**
  - **Search:** the siem prompt's mechanics say `stats … by` drops events missing a by-field, and put `fillnull` on every by-field before it.
  - **Status:** `investigate()` turns a model's `no_data` into `ok` when the findings hold rows (`total_rows() > 0`, discovery listings excluded). Test: `TestRowsDecideTheStatus`.

**B27. A siem step pulls every script block on the host.** *Medium. Fixed on `smartops-loop-fix`; live check pending.*
- **Evidence (`89674d75` L5-FU1, `ps_scriptblocks`):**
  - The search was `EventCode=4104 | table … ScriptBlockText` with no content filter.
  - It returned 435 script blocks: a 10.3 MB result and 6.9 MB of evidence. FU1's `report.json` is 11.8 MB.
- **Impact:**
  - The prompt says "Keep result sets small … set a row limit". The packer then shows 20 rows.
  - A reply this large is the main suspect for B24's trigger.
  - Memory ran out on two earlier runs (`6fc4f590`, `71ef7d21`).
- **Fix candidate:** a row cap in the query guard instead of in the prompt.
- **The size is row width, not row count:** 57 rows took 696 KB and 86 rows 1.2 MB, at about 12 KB of `ScriptBlockText` a row. A row cap alone would not have fixed it.
- **Done:**
  - `guards.RowLimitCap` caps `row_limit` at 100 (the tool's default) on every call, the same way `TimeWindowPin` sets the window.
  - The evidence collector cuts every `structuredContent` cell longer than 8,192 characters, with a `…[+N chars]` marker, and rebuilds the duplicate `content` text from the capped rows. 8,192 is above Windows' 8,191-character command-line limit, so command lines, encoded PowerShell included, stay whole; only script and module source is cut.
  - Results with no `structuredContent` (VirusTotal) pass through unchanged.

**B28. Rows are filed in the wrong category, so steps read 0 rows.** *High. Fixed on `broker-k4-ab-fixes`.*
- **Evidence (`8807fafa` L2-T2):** 3 siem steps returned rows, and 2 were recorded as incomplete with 0 rows.
  - `s2_proc` (wants processes) ran `EventCode=1 OR 3 OR 4688`. `_infer_cim_category` checks connections before processes, so the whole call was filed as connections.
  - `s1_net` (wants connections) pulled `index=fortigate sourcetype=fortigate_traffic`. No rule knew FortiGate, so the rows went to `uncategorised`, which never counts.
  - `3bf5fce8` shows the same: "FortiGate … 59 times [uncategorised#2]".
- **Impact:** the steps read as not done, and the gate refused a ref on T2 that had 4 observations (T25).
- **Fix:**
  - One event-code table (`_EVENTCODE_CATEGORIES`) feeds both the query rules and a per-row split. A call's event rows (those with `_time`) are grouped by their own `EventCode`, one `ResultSet` per category, all sharing the call's `evidence_id`.
  - `stats … by EventCode` count rows are not moved.
  - `fortigate_traffic` and `index=fortigate` count as connections.
- **Re-projected from stored calls:**
  - `8807fafa` L2-T2: `s1_net` 0 → 67 rows, `s2_proc` 0 → 108.
  - L3-G4: `s1_conn` 0 → 22.
  - `3bf5fce8` L2-T3: connections 3 → 72.
  - Some counts drop (G4 `s2_proc` 40 → 19), because connection and file rows a process query returned now sit in their own category.

**B29. The required index-discovery query is filed as evidence.** *Medium. Fixed on `broker-k4-ab-fixes`.*
- **Evidence:** the siem prompt requires `| tstats count where (index=…) host=<host> by index, sourcetype` first (`subagents/__init__.py`). It counts as a search, has no category, and lands in `uncategorised`.
- **Impact:** every endpoint narrative carries "2105 / 149085 Windows event log entries with no timestamp" (`3bf5fce8`). On `89674d75` synthesis read the same line as "high-volume uncategorized Windows events … showing suspicious process activity" (T24).
- **Fix:** a `tstats` with no `datamodel=` describes the estate, so `project_siem` files it under `discovery`, like a call with no search. A `tstats` over a data model is still evidence.

**B30. Tokens and cache reads per role aren't recorded.** *Low. Fixed on `broker-k4-ab-fixes`.*
- **Evidence:** the K4 checklist asked for cache reads above 0 and output per turn against the effort allowances. `broker.log` had spend per role only.
- **Fix:** each ledger entry records how many model requests it settles. `Budget.usage_by_role()` sums calls, input, output, cache read and cache write per role, and the CLI prints one `usage <role>:` line per role after "spend by role".

**B31. siem reports `gaps: vt` with nothing vt could look up.** *Low. Prompt fixed on `broker-k4-ab-fixes`; live check pending.*
- **Evidence (`8807fafa`):** all 9 tasks reported `gaps: vt`; `3bf5fce8` (Sonnet siem) reported none. Every scope was `file_name/host/user/process`, so vt was rightly not offered.
- **VT had nothing to look up:**
  - The only SHA256 in the rows is `1C84C863…`, powershell.exe's own image hash from Sysmon EID 1 `Hashes`.
  - svcupdate.dat has no hash in any row, and no siem query asked for Sysmon 15/29, where a written file's hash would be (B33).
  - `Signed`, `Signature` and `SignatureStatus` are `-`.
  - "Is svcupdate.dat signed, by which CA, what is its hash" can't be answered by any connected source (B20).
- **Fix:** `_gaps_line` now says to name a family only when the rows hold a value it would look up (for vt: a file hash, public IP, domain or URL tied to the question), and otherwise to leave `gaps` empty. `gaps` stays `list[ToolFamily]` in the contract.
- **Recurred (`a818a3fd` L2-T1):** Haiku named vt on a host-only scope; the only hash in the rows was powershell.exe's own. The prompt rule didn't hold, so code now decides: `investigate()` drops a gap for any family `scope_gap` says the task's scope can't feed (`868980f`, `broker-a818-fixes`). Not seen in `e8d949af` or `942115f7`.

**B32. A refused ref says "step … is ok".** *Low. Fixed on `broker-k4-ab-fixes`.*
- **Evidence (`8807fafa` round 2):** "T2:network: step s1_net is ok". The step had `completed=False, status=ok`, and `_ref_problem` printed the status.
- **Fix:** the reason names the state: `rejected` or `incomplete`.

**B33. The hash questions went unanswered.** *High. Fixed on `broker-k4-ab-fixes`; the hash itself is not in the data.*
- **Evidence:** three tasks asked for svcupdate.dat's hash (`8807fafa` L2-T1 and L3-G3, `3bf5fce8` L2-T4), and one whether it is signed (L3-G5).
  - The only SHA256 in any of their rows was `1C84C863…`, powershell.exe's image hash (Sysmon 1 `Hashes`).
  - No query asked for Sysmon 15 (FileCreateStreamHash) or 29 (FileExecutableDetected), where a written file's hash is recorded.
  - Nothing told the Analyst "no hash was recorded". G3's narrative instead read `code=1` as "PowerShell executing with exit code 1".
- **Checked in Splunk (2026-10-11):**
  - `index=windows_lab EventCode IN (15, 29)` over 60 days: 5 EID 15 events on the host, all before the alert. No EID 29.
  - No EID 11 names svcupdate.dat; `svcupdate.dat` appears only in EID 1, 4100 and 4104.
  - So its hash isn't in the lab's data. That is B20's "can't answer" case, and the search should have said so.
- **Worse, on `3bf5fce8` L2-T4:** `file_events#1` held six EID 4100, 4104 and 1 rows. The query named `TargetFilename`, so the whole call was filed as file events.
  - The narrative wrote "File events occurred involving process powershell.exe creating files at … svcupdate.dat".
  - The Analyst's TRUE_POSITIVE cites `T4:file_events#1` for the file's creation. No row shows it.
  - B28's per-row split now files the EID 1 and 4104 rows as processes and script blocks.
- **Fix:**
  - The siem specialisation says where hashes live: an executed image in Sysmon 1 `Hashes`, a written file only in Sysmon 15/29 `Hash` matched on `TargetFilename`, and "say so" when neither names the file.
  - Sysmon 15/29 rows count as file events.
  - Rows render `event_code=` instead of `code=`, so an event code can't be read as an exit status.

**B34. Aggregate rows skip the per-row event-code split.** *High. Fixed on `broker-a818-fixes` (PR #6).*
- **Evidence (`a818a3fd`):** B28's split moved only rows with `_time`. Haiku summarises with `stats count min(_time) as first max(_time) as last by EventCode, Image, …`, so its rows have no `_time` and kept the query's category.
  - L2-T4 and L3-G1: EID 1 rows (powershell.exe under OneDrive.exe, 16 events) were filed as file events, and G1's narrative said "file_events#2 … powershell.exe having event_code 1".
  - L2-T4 `s3_network`: the EID 3 row powershell.exe → 192.168.40.211:8888 was filed as DNS and rendered "source, query, answer, RCODE not recorded".
- **Fix (`2ab6bb2`):** a row moves by its own `EventCode` unless it is a pure code count (only `EventCode`, `count`, `first`, `last`, `host`, `index`, `sourcetype`). 4100/4103 are `script_blocks` (the B28 leftover).
- **Re-projected:** L2-T4's network step goes from 5 to 9 connection rows, the 8888 row included. G1's file step goes from 7 rows to 2 real file events.
- **Live (`e8d949af`, `942115f7`):** the T3 network narrative states "port 8888 with 6 events".

**B35. Sysmon network fields weren't read.** *High. Fixed on `broker-a818-fixes`.*
- **Evidence (`a818a3fd` L2-T4):** `_FIELDS["connections"]` and `["dns_resolutions"]` had no Sysmon EID 3/22 spellings, so rows rendered `dest=-`. The network analyst read `count=269` as "269 bytes" and guessed "port 53"; the real port was mDNS 5353.
- **Fix (`67718cd`):** `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort`, `Protocol`, `QueryName` and `QueryResults` are read.

**B36. One task's output-token holds refused its own third step.** *High. Fixed on `broker-a818-fixes`.*
- **Evidence (`a818a3fd` L3-G1):** `s3_network` came back "siem not attempted: budget exhausted" with $9.96 of $10 left. The 200k output cap per task held the Broker at 11 × 4k = 44k and each siem dispatch at 25 × 2k + 6k = 56k: 44k + 3 × 56k = 212k. The incomplete step then got `G1:endpoint` refused.
- **Fix (`6a8255b`, `0ce24c0`):** `OUTPUT_TOKENS_PER_TURN` is now low 1k, medium 1k, high 2k. The refusal log names which limit refused the call and the amounts.
- **Measured, output per model call:**

  | Run | Tier | siem | Broker | vt |
  |---|---|---|---|---|
  | `a818a3fd` | B | 747 (Haiku) | 340 (Sonnet) | — |
  | `e8d949af` | B | 642–898 (Haiku) | 304 (Sonnet) | 274 (Haiku) |
  | `942115f7` | A | 443–491 (Sonnet) | 537–583 (Opus) | — |

  Every role read from cache (`cache_read` above 0). No "budget exhausted" in either run.

**B37. `covered` was the subagent's own claim.** *Medium. Fixed on `broker-a818-fixes`.*
- **Evidence (`a818a3fd` L2-T1):** "not covered: script_blocks" beside two `script_blocks` rows the endpoint narrative cites.
- **Fix (`8902b52`):** every CIM category that code projected rows into counts as covered.

**B38. Pure code-count rows are narrated as events.** *Medium. Fixed on `broker-a818-fixes`.*
- **Evidence (`a818a3fd` T3, T4):** `stats count by EventCode` sets (`{EventCode, count}` only) stay `uncategorised`. The narratives say "three uncategorized events with event codes 1, 4100, 4104", and L3 synthesis wrote that the codes "reinforce the idea of malicious activity".
- **Fix (Mohammed, 10-11):** a call whose rows are all `{EventCode, count…}` is filed as `discovery` (`projection.project_siem`), like B29's index count: no slice, no step completion.

**B39. A step's status is its last dispatch's.** *Medium. Fixed on `broker-a818-fixes`.*
- **Evidence (`2a71757f` T2, `onedrive_file_registry`):** `rows_retrieved=5`, `completed=true`, `status=no_data`. The first dispatch returned the 5 rows, and the second found none.
- **Cause:** `broker.evaluate_step` (`broker.py:641`) sets `outcome.status = result.status` on every dispatch, while `rows_retrieved` accumulates. B26 made a single result's status follow its rows; the step-level status was not changed.
- **Effect:** the persisted `step_outcomes` and the UI say both "found 5" and "no data" for one step.
- **Fix (proposed):** derive the step's status from its cumulative rows: `ok` when `rows_retrieved > 0`, otherwise the last dispatch's.

**B40. A `-` placeholder counts as a value; a hash lost its file.** *High. Fixed on `broker-a818-fixes`.*
- **Evidence (`2a71757f` T1, T3):**
  - `facts` read `(file not named): SHA256 1C84C863…`.
  - The rows are Sysmon EID 1 with `Image=…\powershell.exe`, `TargetFilename=-`. It is powershell.exe's own hash; T2's facts print it as `powershell.exe: SHA256 1C84C863…`.
  - Synthesis wrote "the binary had a SHA256 hash of 1C84C863…" for svcupdate.dat, called it "a suspicious hash", and named it among the verdict's main reasons.
- **Cause:** `formatting._first` (`formatting.py:61`) returns the first key that is present and non-empty. Since the `fillnull` rule (B25), every empty field is `-`. So `hashes_in`'s `_first(row, "ImageLoaded", "TargetFilename", "Image")` stops at `TargetFilename=-`, before it reaches `Image`.
- **Class:** `_first` has 10 call sites. Any row where an earlier key holds `-` hides a later key's real value.
- **Fix (proposed):** treat `-` like empty in `_first`. Test: an EID 1 row with `TargetFilename=-` and `Image=powershell.exe` names powershell.exe.
- **Analyst side (routed):** synthesis called a hash suspicious with no reputation behind it. No task looked the hash up: T3's Broker had no hash in scope at plan time, so VT wasn't offered, and the gap was reported (T21).

**B41. The packer's over-budget warning repeats.** *Low. Fixed on `broker-a818-fixes`.*
- **Evidence (`2a71757f` T2 endpoint):** "evidence over budget, rendered at row_cap=20" logged 7 times for one domain.
- **Cause:** `fitted_row_cap` re-runs `pack_evidence` to read its row cap, and each run logs. The cost is string formatting only; the noise hides other warnings.

**Not reproduced:** `ConnectionResetError 10054` in all three siem subagents (seen once on 2026-09-30, before `cecd266a`). It hasn't recurred in the 5 runs since.

## Webapp integration

**W1. Two different plans per investigation, and the UI shows the one that isn't executed.** *High. Open.*
- **Evidence:**
  - *Process Event & Build Context* calls `/api/analyst/start` (`_do_analyst`, with an inline prompt), and its plan is shown in section 5.
  - *Run Full Investigation* then calls `/api/run`, which plans again from scratch with `prompts/system_prompt.txt` (`webapp/main.py:537`) and executes that plan.
  - The first plan is stored as `analyst_memory` and never used. In SOC3 the two plans had different tasks and windows (section 5: 4 tasks on 30 Sep; loop 1: 3 tasks on 27 Sep).
- **Impact:** a reviewer audits a plan that wasn't run, and the Analyst model is billed twice.
- **Fix:** plan once, and pass that plan to `/api/run`.

**W2. A stale run was fed to the Analyst, and the exit code was ignored.** *Critical. Fixed in `58d39c3`.*
- **Evidence:** SOC3's 18 Broker loops all returned `cli-20260921T091324`, a scripted run from 21 September. The release ignored the Broker's exit code and read the newest `findings.json` on disk.
- **Fix:** `--batch-id` payloads, an exit-code check, and no fallback to other runs.

**W3. Tasks passed as entity kinds the engine rejects.** *High. Fixed in `58d39c3`.* The release passed seed keys such as `hostname:` as `--entity` kinds. Tasks now go through the `task-input.v1` file.

**W4. A hardcoded siem stub ran outside every guard.** *High. Fixed in `58d39c3`.* It ran `index=sysmon OR index=main … | head 50` and reported Splunk errors as `ok`.

**W5. A demo alert was pre-filled in the form.** *Medium. Fixed in `58d39c3`.* Clicking *Process Event* before the import finished investigated fake data. The defaults are removed, and an empty form is refused.

**W6. Unescaped model and log text in `innerHTML`.** *Medium. Fixed in `58d39c3`.* Alert and log text is attacker-influenced; it is now escaped.

**W7. The two planning prompts disagree.** *Medium. Open.*
- **Evidence:**
  - The section-5 prompt allows entity kinds `host|ip|user` and anchors windows ±1 h on `event_time` (`webapp/main.py:339`, `:352`).
  - The loop prompt allows `host|ip|user|domain` and, since `58d39c3`, anchors on `normalized_seed.event_time` in UTC.
- **Fix:** resolved by W1 (one plan, one prompt).

**W8. `max_loops` is 15, but the synthesis prompt only has room for 3 rounds.** *High. Open.*
- **Why 15:** headroom, not a target. `b3aa0dd2` hit max loops at 3 with T1's parent-process question still unanswered, so 3 was too few for the loop to finish.
- **Strands' compaction doesn't cover it.** `SummarizingConversationManager` manages a Strands `Agent`'s own message history. The main Analyst calls Bedrock directly (`call_llm`, httpx), and each synthesis is one message rebuilt from every round, so nothing compacts the rounds.
- **Problem:** `webapp/main.py` re-sends every earlier round's payload on each synthesis call. The Broker's per-round budget (`HANDOFF_CHAR_BUDGET`, 16,480 characters) is sized so that 3 rounds plus the plan plus 8,192 output tokens fit the 32,768-token window (`packing._ANALYST_ROUNDS = 3`). `b3aa0dd2`'s synthesis prompts grew 7,406 → 12,009 → 13,934 tokens over three rounds. At that rate the prompt passes ~24k, where the output no longer fits, in about round 6, and Bedrock rejects or truncates the call.
- **Cost:** about $2.50 of Broker spend per full round on `b3aa0dd2`, so a 15-loop run can approach $35.
- **Fix (webapp, the Analyst's input; to be decided):** (a) keep the last 2 rounds in full and replace older ones with a short record built in code: each task's question, the findings cited, and what was answered. (b) Make the Analyst a Strands `Agent` with `SummarizingConversationManager`. (c) Stop when the next prompt would not fit. Lowering `_ANALYST_ROUNDS` to 15 instead would leave each round ~3k characters, which is too small to carry findings.
- **Done (option a):** synthesis reads the last 2 rounds in full. Each older round becomes `run_trace.compact_round`: each task's question, the domains with observations, and the evaluation that followed (scores, verdict, refs, refused refs, gaps). On `b3aa0dd2`, rounds of 18.2k, 17.0k and 7.2k chars compact to 1.8k, 1.0k and 0.9k. The verdict gate still checks refs against every round's payload. Not yet run past round 4.
- **First live compaction (`89674d75` round 4):** round 2 was compacted. Synthesis read its `hypothesis_scores` as scores for the G tasks and copied an evaluation that never ran (T26). Scores in the compact record are a candidate to drop.

**W10. Gap statements become tasks verbatim, so a round can repeat the last one exactly.** *Medium. Repeat filter on `smartops-loop-fix`; gap wording open (Analyst).*
- **Evidence (`89674d75`):**
  - Round 3's tasks were round 2's three evidence gaps, used as questions: "Lack of explicit threat intel hits for 192.168.40.211", "Uncorroborated attacker identity", and T3's question, which the gate re-added for its refused ref (T25).
  - Round 3 refused all its refs, so the same three gaps came back. Round 4's `tasks.json` is identical to round 3's: questions, entities and window.
  - The repeat cost $3.47 in Broker spend for evidence already fetched.
  - Neither gap is a question a search can answer (B20).
- **Code:** `run_trace.follow_up_tasks` (`webapp/services/run_trace.py:247`) turns each gap into a task when synthesis gives no follow-ups. That's the T17 workaround.
- **Fix candidates:**
  - Skip a follow-up whose question and scope match a task that already ran, and end the run when the whole round would repeat.
  - Turning gaps into questions is the Analyst's side.
- **Done:**
  - `follow_up_tasks` drops a follow-up whose question (ignoring case and spacing), entities and window match any task already sent. `main.py` passes every task sent so far.
  - With nothing new, the run ends: "No new follow-up tasks (none given, or all already asked)".
  - Replayed on `89674d75`, round 3's three follow-ups are all dropped. The run would have ended after round 3 instead of re-running it.

**W9. The browser falls back to the notable time when the event time didn't resolve.** *Medium. Open (frontend, smartops-worker).*
- **Evidence:** `webapp/static/app.js:260` takes `event_time` from the import, else `raw._time`, the notable time (8.5 min after the event on c90ca5f9). Silent.
- **Fix (frontend):** no fallback; show "event time unresolved".

**W11. The webapp opened its own Splunk MCP client.** *Medium. Fixed on `broker-k4-ab-fixes`.*
- **Evidence:** `webapp/services/splunk_mcp.py` (from `58d39c3`) built a raw `mcp` session with its own URL, token and TLS-skip handling for the alert reads (`webapp/main.py`: events, notables, ESCU rules). It ran beside the backend's `smartops.tools.registry`, which owns `mcp_servers.json`, the TLS rule and dead-session resets.
- **Fix:** `registry.call_tool(family, name, arguments)` runs one tool call on the family's client, outside any agent: started once, reset if its session died, and raising on a tool error. `splunk_mcp.run_query` now delegates to it. Checked live: two queries in a row on one session.

### Evidence gate (`run_trace.verdict_gate` / `_ref_problem`)

None of the four rounds in `e8d949af` and `942115f7` (2026-10-11) reached VERDICT_REACHED, and the gate decided each one. T25 holds the policy question (should one bad ref block a verdict?). These are defects in the gate as written.

**G1. A block cited inside a multi-id bracket is refused.** *High. Open.*
- **Evidence (`942115f7` round 2):** BENIGN with H3 90 against H2 60 met the score rule. `T1:processes#1` and `T1:processes#4` were refused as "neither a domain with observations nor a block cited in T1's findings". T1's endpoint observation reads "Multiple executions of OneDrive.exe … [processes#1 processes#4 processes#5]". `T1:processes#5` held only because another observation cites it alone.
- **Cause:** `_ref_problem` looks for the literal text `[processes#1]` in the narrative and observations. The sub-analysts write several ids in one bracket, and the parser accepts it (`analyze.py`'s run-together id handling).
- **Fix:** read the ids out of every bracket (split on spaces and commas), or use the domain's citations instead of the text.

**G2. A verdict blocked on its scores records no reason.** *Medium. Open.*
- **Evidence (`942115f7` round 3):** verdict TRUE_POSITIVE with scores H1 70, H2 90, H3 80. The scores fail the rule (lead 10), so the status is REQUIRES_INVESTIGATION, but `refused_refs` and the gate's gaps are empty. The ref `DNS_resolutions#3:network` (task and block swapped) was never checked or reported.
- **Cause:** `verdict_gate` checks refs and writes reasons only when the scores pass (the T17 feed noted 2026-10-08).
- **Fix:** always check refs and always record why the status is REQUIRES_INVESTIGATION: scores (top, lead), a verdict that disagrees with its own top hypothesis, and bad refs.

**G3. A ref to a lost domain refuses the round, and the re-ask loses it again.** *High. Open (with T25 and B15).*
- **Evidence:**
  - `e8d949af` round 2: TP 95, lead 90. Refused only on `T1:endpoint`, whose sub-analyst was cut off twice (B15).
  - T1's question returned as round 3's G1, whose endpoint domain was lost the same way. Round 3 was refused on `G1:endpoint`, and the run ended with no verdict.
  - `942115f7` round 2: `T3:script_blocks#1` was refused because T3's endpoint was lost.
- **Effect:** while B15 recurs, any verdict that cites an endpoint domain is refused, and the follow-up repeats the question that loses it.
- **Fix candidates:** refuse a ref to a domain the payload marks as failed ("produced no parseable finding") with that reason, instead of "neither a domain with observations…", and don't turn it into a follow-up that reruns the same retrieval. Or T25's "keep the verdict when enough refs hold".

## Cost

**K1. About $5–12 per Broker loop.** *Medium. Fixed (`0e82b4c`).*
- **Evidence:** `cecd266a` $12.28, `072fd610` $9.07, `04a15495` $5.45 (2 loops), `a8118db9` $8.24 (3 loops). One T5 query returned 181 rows with full encoded command lines (837k characters, about 200k tokens), and the agent loop re-sends that on every turn.
- **Fix:** cap long values (command lines) in what the model sees, and keep full rows in `evidence.json`.
- **Done:** the fetch subagents use Strands' `ContextOffloader` (preview above about 2,500 tokens, no retrieval tool). Evidence is captured first at `SDK_FIRST` and stays full. `072fd610-L2-T3`: $1.56 before, $0.72 and $0.79 after.

**K2. A blank `SMARTOPS_LLM_PROVIDER` doesn't stop Broker model calls.** *Medium. Fixed on this branch.* The engine still finds a model from the other AWS settings. Only `--scripted` was guaranteed free.
- **Fix:** `SMARTOPS_LLM_PROVIDER=none` returns no provider (the scripted invoker) even with credentials present. Blank still means "detect", so a blank line in a copied `.env` doesn't change behaviour. The sub-analyst model has its own switch (`SMARTOPS_ANALYST_MODEL_ARN`).

**K3. 19 loops on empty input.** *Medium. Fixed.* SOC3 spent 18 synthesis calls re-reading the same stale findings. W2 removed the stale input, `max_loops` was 3 (15 since 2026-10-08, W8), and the T1 gate stops a confident verdict that cites no evidence. The teammate branch's `max_loops` 9999 was not ported.

**K4. One model for every Broker call.** *Medium. Fixed on `smartops-loop-fix` (2026-10-11); tier A held on `451334ad` and `ea38cb13`. Re-measure the holds when a tier preset changes.*
- **Before:** the Broker planner, both fetch subagents (siem, vt) and every recovery call ran on one `ModelChoice`, Sonnet 4.6 on Bedrock (`AWS_BEDROCK_MODEL_ID`).
- **Done: the Broker on the Anthropic API, with one model per role.**
  - `Provider.ANTHROPIC` uses Strands' `AnthropicModel`, through the `strands-agents[anthropic]` extra (anthropic SDK 0.125.0).
  - It is chosen only by `SMARTOPS_LLM_PROVIDER=anthropic`. Bedrock stays selectable, and rollback is manual: `SMARTOPS_LLM_PROVIDER=bedrock`.
  - `budget.model_choices_from_env()` gives `broker`, `siem` and `vt` their own choice. `main.py` builds all three eagerly and logs them: `model: anthropic tier=A broker=… siem=… vt=…`.
  - `domain_runner` takes a family→choice map.
  - vt was already a model agent with `virustotal.TOOLS` whenever a model is configured, so it only needed its own tier.
  - The recovery call stays on its family's model, because switching models mid-conversation drops the agent's thinking blocks.
- **Tiers** (`SMARTOPS_BROKER_TIERS`; per-role `SMARTOPS_MODEL_ID_<ROLE>` and `SMARTOPS_EFFORT_<ROLE>` override them):

  | Role | A | B |
  |---|---|---|
  | Broker planner | `claude-opus-5-5`, effort high | `claude-sonnet-5-5`, effort high |
  | siem subagent | `claude-sonnet-5-5`, effort medium | `claude-haiku-5-5`, effort medium |
  | vt subagent | `claude-haiku-5-5`, effort low | `claude-haiku-5-5`, effort low |

- **API differences handled:**
  - **Sampling:** Opus 5.5, Sonnet 5.5 and Haiku 5.5 reject `temperature`/`top_p`, so the Anthropic provider sends neither.
  - **Forced tool choice:** Strands forces `tool_choice: any` when a turn ends without the answer tool. Opus 5.5 and Sonnet 5.5 reject that with a 400, so a small `AnthropicModel` subclass sends `auto` for those two. Haiku 5.5 accepts forced use. If the model still skips the tool, the step takes the existing no-answer `ERROR` path.
  - **Caching:** top-level `cache_control: ephemeral` caches the tools and system prompt.
- **Output caps follow effort:** the loop-wide output caps were sized for Sonnet 4.6, which did not think (siem had about 480 tokens a turn). Now a role with an effort gets `turns × OUTPUT_TOKENS_PER_TURN[effort]`, with low 1,000, medium 2,000 and high 4,000 (`budget.loop_output_tokens`). On both tiers that gives the Broker 44,000, siem 50,000 and vt 25,000. Recovery gets 4,000 plus one turn's allowance. A role with no effort (Bedrock) keeps 16,000 / 12,000 / 4,000. The allowances are estimates, to be reset from the smoke run's per-turn usage.
- **Cost calculation:**
  - New `PRICING` rows, with live rates from platform.claude.com on 2026-10-11:
    - `claude-opus-5-5`: $4/$20, cache read 0.05×.
    - `claude-sonnet-5-5`: $2/$10, cache read 0.05×.
    - `claude-haiku-5-5`: $0.10/$0.50.
  - `claude-sonnet-5` was $3/$15 and is now $2/$10.
  - Haiku 5.5 bills a request whose prompt (input plus cache reads plus cache writes) is over 100k tokens at $0.50/$2.50. That threshold is judged per request, so the budget now settles each model request on its own (`budget.call_usages`, from Strands' per-cycle metrics), not the loop's summed usage.
  - The two copies of the camelCase usage bridge became one, `budget.usage_from`.
- **Tests:** `engine/tests/test_model_tiers.py` (13) covers:
  - presets, overrides and the Bedrock fallback;
  - request params: no sampling, effort, `cache_control`;
  - tool-choice relaxation;
  - rates;
  - output caps per effort;
  - per-request pricing: two 60k calls at the low rate and one 120k call at the high rate.
- **First A/B run (2026-10-11), same alert (event 2026-10-06T11:51:16Z), one run each:**

  | | A, `3bf5fce8` (Opus planner, Sonnet siem) | B, `8807fafa` (Sonnet planner, Haiku siem) |
  |---|---|---|
  | Rounds, wall clock | 1, 4.6 min | 2, 8.2 min |
  | Tasks, steps | 5, 12 (all complete) | R2: 4, 6 (2 recorded incomplete, B28). R3: 5, 8 |
  | Broker cost | $1.04 (siem $0.74, planner $0.30), $0.21 a task | $0.27 (R2 $0.12, R3 $0.15), $0.03 a task in R2 |
  | Sub-analyst cut-offs | 0 | 4 (endpoint T3, T4; B15) |
  | First evaluation | TP 90/60/40, 3 refs held, VERDICT_REACHED | TP 90/30/20, all 3 refs refused (T25, B28) |
  | End | verdict | R3 synthesis cut off at 8,192, no JSON (T15) |

  - No `limit_*` stop and no 400 in either run: the effort-based output caps held, and relaxing forced tool choice caused no failure.
  - Cache reads and output per turn were not recorded (B30, now fixed), so the allowances are still estimates.
  - **Why A took one round and B two:** the gate, not the evidence. Both first evaluations were TP 90. A cited block ids; B cited `T1:file`, `T3:file`, and a T2 ref our step bookkeeping refused (B28, B32).
  - B is about a quarter of A's Broker cost per round. One run each does not separate tier quality from the gate's behaviour; rerun B after B28.

## Audit trail

**O1. The context contract isn't saved with the run.** *Medium. Fixed (`c85eb93`).* `investigation.jsonl` recorded the plan, the Broker run and the synthesis, but not the contract the Analyst was given. Comparing runs meant rebuilding it. The `analyst_plan` line now carries it as `context`.

**O2. The dispatch-to-step link isn't recorded.** *Low. Fixed on this branch.* `072fd610` T7 had 2 steps and 2 dispatches, and nothing records which dispatch served which step. Still true on `ded5cac1`: `step_outcomes[].dispatches` was only a count. `StepOutcome.result_ids` now lists the `SubtaskResult.task_id` of each dispatch that served the step, which is the join to `report.json`'s `results`.

**O3. The Broker log is written only at the end of a loop.** *Low. Fixed (`c85eb93`).* `broker-L<n>.log` stayed at 0 bytes while the loop ran. The child process was unbuffered, but the webapp's own file handle used block buffering. It's now line-buffered.

**O4. Sub-analyst gate drops never reached the run's Broker log.** *Low. Fixed on `smartops-loop-fix`.* The gates log every sentence, figure and domain they drop as a warning, but the CLI configured logging at ERROR without `--verbose`. So `broker-L<n>.log` never showed what the Analyst lost. The `smartops.subagent_analysts` loggers now log at WARNING. Verified on `b3aa0dd2`: packing row caps, the re-ask failures and the N2 salvage all appear in `broker-L<n>.log`.

**O5. One investigation was 9 traces in 12 folders.** *Medium. Fixed on `smartops-loop-fix`.*
- **Evidence (`874ab334`):** each Broker task opened its own root span, so round 2 was 6 traces and round 3 three; the Analyst's plan and synthesis calls had none. The files sat in 12 sibling folders under the runs root (`874ab334/`, `874ab334-L2/`, `874ab334-L2-T1/<stamp>/`, …), joined only through `investigation.jsonl`.
- **Fix:** one folder: `runs/<run_id>/investigation.jsonl`, and per round `L<n>/tasks.json`, `broker.log`, `analyst-payload.json` and `T<k>/` with `report.json`, `evidence.json`, `findings.json` and `traces.json`. The webapp sets `SMARTOPS_OUT_DIR` for each round, and the standalone CLI keeps its `<task_id>/<stamp>/` layout. One trace: the webapp derives a trace id from the run id, writes it on every `investigation.jsonl` line, and passes a W3C `TRACEPARENT` to each round. The engine's `smartops.round` span opens under it, with every task's spans inside. Older runs aren't migrated.
- **Not covered:** the Analyst's own model calls have no spans (the webapp has no exporter); the `trace_id` on their `investigation.jsonl` lines joins them.

**O6. Warnings didn't name the task, and the packer's overflow wasn't logged.** *Low. Fixed on `smartops-loop-fix`.* `874ab334` lost endpoint 3 times and the log couldn't say in which task. Every log line now carries `task=<task_id>` (a contextvar set per task, carried into the sub-analyst threads), and the `contracts` logger is at WARNING beside `smartops.subagent_analysts`.

## Security

**S1. Live credentials are in git history.** *Critical. Removed from the tree; rotated (Mohammed, 2026-10-12). Confirm the `33ccf52` keys (C1–C2) were in that rotation.*
- **What:** the Bedrock API key, the VirusTotal key, the Splunk JWT and password, and the OpenCTI token. `.env.example` held the real OpenCTI token.
- **Where:** pushed on `origin/main`, `origin/integration` and `origin/feature/task-broker-input`. `58d39c3` removes them from the tree, not from history.
- **New (2026-10-05):** `origin/updated-analyst-agent` (`33ccf52`) commits a `.env` with the AWS access and secret keys, the FS8B key, the Splunk token and the VT key, plus a hardcoded OpenCTI token and a Splunk user and password as code defaults. It was ported by hand, not merged, so none of it is on `post-analyst-update-integration`.
- **Action:** rotate all of them, and have the branch deleted or rewritten.

**S2. A Splunk Web scraper replaced the official MCP server.** *High. Fixed (C3).* `mcp_servers.json` points at the official server again (17 tools, time-bounded queries).

## Architecture

From the 2026-10-11 over-engineering and duplication audit (`AR`, not `A`: `A#` is `docs/analyst-bug-report.md`'s prefix). Dead-code claims were checked by grep over all tracked source outside tests. `subagent_analysts/`, `guards.py` and `contracts/` were not read line by line for shorter forms. About 420 lines and 2 dependencies could go.

**AR1. Six webapp routes have no caller in the UI.** *Low. Open.*
- **Evidence:** `webapp/static` calls only `/api/run*`, `/api/import-from-splunk`, `/api/incident-queue`, `/api/escu` and `/api/opencti`. Nothing calls these:
  - `/api/analyst`, `/api/analyst/start`, `/api/analyst/result/{id}` and `/api/synthesis` (`webapp/main.py:378-537`), with `_do_analyst`, `_run_analyst_job`, `_analyst_jobs`, `AnalystRequest` and `SynthesisRequest`.
  - `/api/list-detection-rules` and `/api/import-from-splunk-by-rule` (`webapp/main.py:272-310`).
  - The only references are in the untracked `tests/test-integration/` scratch files: saved HTML and drive scripts.
- **Fix:** delete them (~195 lines).

**AR2. The webapp has its own Foundation-Sec-8B client.** *Medium. Open, one question first.*
- **Evidence:** `webapp/services/llm_service.py` repeats `subagent_analysts/model.py`'s `AnalystModel`: the prompt template, the `invoke` body, the cold-start retries and the reasoning/answer split, with its own temperature, top_p and `max_gen_len` defaults. Two clients for one model can drift, the same pattern W11 removed for Splunk MCP.
- **Question:** its header says it calls Bedrock through httpx to get around "boto3 Windows socket issues". Is that still true? If not, the webapp calls `AnalystModel.invoke` (~-100 lines).

**AR3. A global boto3 monkeypatch duplicates `AnalystModel`'s bearer auth.** *Medium. Open.*
- **Evidence:** `engine/src/smartops/main.py:46-67` (from `d113695`, the integration release) replaces `boto3.Session.client` at import time. Every `bedrock-runtime` client in the process prefers bearer auth and picks up `FS8B_API_KEY`.
  - `AnalystModel._bearer_client` already does this for its own client only, through `ScopedEnvTokenProvider`.
  - Its docstring says why the key must not leak into other clients. The patch makes it leak into all of them, including Broker-tier Bedrock clients.
- **Fix:** delete the patch (~-22 lines) and confirm the analyst still authenticates through `_bearer_client`.
- **Blocker (found 2026-10-11):** the patch also overrides `_bearer_client`. That client is built through `boto3.Session(...).client(...)`, so the patch re-registers the token provider with `FS8B_API_KEY`. Live sub-analysts therefore authenticate with `FS8B_API_KEY`, not `SMARTOPS_ANALYST_API_KEY`. The two `.env` values differ, and that explains why `scratchpad/replay_endpoint.py` (which never imports `smartops.main`) is rejected. Before deleting the patch, set `SMARTOPS_ANALYST_API_KEY` to the working key (owner action).

**AR4. Four engine symbols only tests use.** *Low. Open.*
- `TaskInputFile.analyst_tasks()` (`contracts/task_input.py:208`), `Budget.output_tokens_remaining` (`budget.py:680`), `create_replay_subagent_runner` (`replay.py:360`) and the VirusTotal outcome's `is_partial` (`virustotal.py:264`).
- **Fix:** delete them and their tests (~-46 lines of source).

**AR5. The runs-root lookup is written out 7 times.** *Low. Open.*
- **Evidence:** `os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR` at `broker.py:1227`, `main.py:740` and `:1022`, `blind_compare.py:230` and `:1201`, and `replay.py:133`. `webapp/services/run_trace.py:115` hardcodes the variable name and the default.
- **Fix:** one `runs_root()` in `broker.py`, imported everywhere else.

**AR6. `extract_json` scans braces by hand.** *Low. Open.*
- **Evidence:** `webapp/services/llm_service.py:101` has a nested depth-counting loop with a bare `except:`.
- **Fix:** try `json.JSONDecoder().raw_decode(text, i)` at each `{` (~-15 lines). Merge it into AR2's fix if that lands.

**AR7. `bench._pinned_skills` only delegates.** *Low. Open.*
- **Evidence:** `engine/src/smartops/bench.py:67` wraps `pinned_skills_enabled()` and yields `skills_enabled()`, under a 15-line docstring.
- **Fix:** use `with pinned_skills_enabled(...)` at the call site.

**AR8. Two launchers disagree.** *Low. Open.*
- **Evidence:** `start_server.bat` runs uvicorn on port 8001 with a hand-set `PYTHONPATH` and no `uv`. `start.ps1` uses `uv` on port 8013 and parses `.env` itself, which `webapp/main.py` already does with `load_dotenv`.
- **Fix:** keep `start.ps1` without its `.env` loop; delete `start_server.bat`.

**AR9. Unused root dependencies.** *Low. Open.*
- **Evidence:** the root `pyproject.toml` declares `mcp` and `botocore`. The webapp imports neither (since W11 its Splunk reads go through `smartops.tools`). The engine gets both through strands and boto3.
- **Fix:** drop both.

**AR10. There is no frontend.** *Medium. Open (frontend, smartops-worker).*
- **Evidence:** `frontend/` is an empty, untracked folder (created 2026-08-04, no commits). The only UI is `webapp/static`: `index.html`, `app.js` (1,238 lines), `style.css` and a separate `debug.html` (413 lines), served by FastAPI's `StaticFiles` from `webapp/main.py`.
  - That UI is a vanilla-JS stopgap: no components, no build, no tests, and one 1,238-line script holding the queue, the import, the run stream and the trace view.
  - `debug.html` is a second page with its own run and stream calls; nothing links to it from the main UI.
  - UI issues already pile up against it (W1, W9), and each one is fixed in that one script.
- **Fix:** build the real frontend in `frontend/` against the webapp's `/api/*` contract, then retire `webapp/static`. Until it exists, keep the stopgap vanilla and delete the empty `frontend/` folder so nothing suggests it is started.

**AR11. The codebase's file structure needs work.** *High. Open: the next session puts everything where it belongs.*
- **Context:** this came up while tracing AR3 (2026-10-11). AR3 is fixed on its own (the `.env` key, then delete the patch), and this is deferred out of that fix.
- **Evidence:**
  - **`webapp/` holds five jobs** (checked 2026-10-11):
    | Job | Where it is now |
    |---|---|
    | Frontend | `static/` (`app.js` 1,238 lines, `index.html`, `style.css`, `debug.html` 413) and the `/` and `/debug` routes |
    | Main Analyst | `prompts/system_prompt.txt`; `services/llm_service.py`; `main.py` `_do_analyst`, `/api/synthesis` and the round loop `_run_investigation` (:639-780); `run_trace.py` `verdict_gate`, `_ref_problem`, `compact_round` and `follow_up_tasks` |
    | Context pipeline | `main.py` Splunk import, incident queue, detection rules, OpenCTI (`_gql`, `_search_*`) and ESCU; `run_trace.py` `alert_entities`, `notable_event_time`, `notables_spl` and `group_notables`; `services/splunk_mcp.py` |
    | Broker handoff and audit trail | `main.py` `_run_broker_proc_streaming`; `run_trace.py` `to_task_file`, `broker_runs`, `handshake`, `record`, `trace_id`/`traceparent` and `runs_dir` |
    | API server | the FastAPI app and run control (`/api/run`, stop/pause/resume/stream) |

    `run_trace.py` covers three of these jobs and `main.py` four. A change to one job (the gate, say) lands in a file shared with the others, and ownership (Analyst owner, smartops-worker, us) can't follow the files.
  - One model, two configurations. `SMARTOPS_ANALYST_*` (the engine's sub-analysts, `5caf246`) and `FS8B_*` (the webapp Analyst, from the integration release `d113695`) name the same imported-model ARN. They hold different keys, and each has its own client (AR2). The `.env` reason, "kept separate so the two can point at different imports", has never been used.
  - The webapp imports private engine symbols: `run_trace.py` takes `_FULL_ID_SEARCH_RE` and `_expand_bare_ids` from `subagent_analysts/parse.py`.
  - Dev tools ship inside the engine package: `bench.py` (1,051 lines), `blind_compare.py` (1,354) and `replay.py` (about 360), about 18% of `engine/src/smartops`.
  - Very large modules: `main.py` (about 1,450 lines), `broker.py` (about 1,450), `subagent_analysts/analyze.py` (1,312), and `subagents/__init__.py` (1,093), which keeps the whole subagent loop in a package `__init__`.
  - Split ownership at the root: two manifests (root and `engine/`, see AR9), two launchers (AR8), and an empty `frontend/` (AR10).
- **Questions for Mohammed:**
  - the target home of each `webapp/` job above (for example `frontend/`, an Analyst package, a context package, and a thin API server that wires them);
  - one Foundation-Sec configuration or two;
  - where dev tools live (`engine/tools/` or a separate package);
  - whether the engine exposes a public surface the webapp imports from instead of private names;
  - the target layout for the large modules.
- **Next session.** Agree the layout first, then move code without changing behaviour (moves only, tests green after each). It touches webapp files, which the Broker-side-only rule normally keeps off limits, so confirm the scope at the start.

**Checked, not issues:**
- `_estimated_input_tokens` in `broker.py` and `subagents/__init__.py`: the formulas differ (the subagent's caps turns at 8 and adds tool schemas).
- The guard classes' `_check` and `_learn` in `guards.py`: each one enforces a different rule.
- The three `_build_parser` and `_run` functions in `main.py`, `bench.py` and `blind_compare.py`: each belongs to a different CLI entry point.

## Priorities

**For the Analyst owner, from 2026-10-09** (the Broker side of each is done or not needed):
- **B20 / B6:** follow-ups name the task they follow (or carry their own entity and window), so the handoff can scope them.
- **T21:** state what each parent spawned before scoring it; ask VirusTotal about the parent's hash, now in `facts` (B22).
- **T22, T14:** reason only over tasks that ran and rounds that happened.
- **T23:** the evaluation header states the event and notable times once, in UTC `Z`.
- **T15, T17:** c90ca5f9's round 3 thought through 8,192 tokens and wrote nothing; the run ended after 2 of 15 rounds.
- **T8, T10:** no reasoning from absence; status and verdict from one vocabulary.
- **From `89674d75`:**
  - T24: cite only what rows show, not task questions or row counts.
  - T26: G tasks are not hypotheses; never copy scores from earlier rounds.
  - W10: gaps written as questions a source can answer.

**Broker and webapp, from `89674d75`** (ours):
- **Done, live check pending:**
  - B24, B27, W10 (10-10).
  - B14, B15, B26, B25 (10-11).
- **Next, in order:**
  1. **Live run:** check the 10-10 list (reconnects, no hung step, sizes, no repeated round), plus observations in every payload, no `stop_reason=length`, and no `no_data` beside rows.
  2. **B20:** the "can't answer" design above, once agreed.
  3. **K4:** A/B live runs of the tier presets.
  4. **T25 (Mohammed to decide):** whether one bad ref, or a malformed one, should block a verdict.

**Broker and gate, from `a818a3fd`, `e8d949af`, `942115f7` (2026-10-11 close)** (ours):
- **Done, PR #6 (`broker-a818-fixes`):** B34–B37, the B31 code filter, the B15 dedupe and re-ask. Live on the two runs: no budget refusal, the 8888 connection reached a narrative, no `gaps: vt`.
- **Next, in order:**
  1. **B15:** the endpoint loop still loses the domain (6 times in 2 runs). Decide the next lever (above).
  2. **G1:** read multi-id brackets in `_ref_problem`. Small, and it alone blocked `942115f7` round 2.
  3. **G2:** record why every REQUIRES_INVESTIGATION was reached.
  4. **G3 / T25:** what a ref to a lost domain should do.
  5. **B38:** where pure code-count rows go.

**Broker, from `2a71757f` (2026-10-11 baseline)** (ours):
- **Held live:** B15 (`18f7719`), B22 (the hash reached `facts`), B36 (no budget refusal), B14 (observations in every domain).
- **Next, in order:**
  1. **B40:** treat `-` as empty in `_first`; it fixes the misattributed hash and every other masked field.
  2. **B39:** the step's status follows its rows.
  3. **B15 follow-ups (decide):** the safety net, and dropping the length re-ask.
  4. **Parallel fetch (decide):** serial fetch was 5m55s of the 6m39s Broker phase.
  5. **B41:** log once per slice.


1. **Rotate the credentials** (S1).
2. **Make the verdict trustworthy:** a code-side stop gate (T1), a single plan (W1), a structured command line and parent path in the seed (P2), and the parent path kept in observations (B1). These four together decide whether a true positive is reached for the right reason.
3. **Fix the activity time:** `event_time` from `firstTime` (P1).
4. **Reduce cost:** cap long values in what the model sees (K1).
5. **Stabilise the scores:** baseline, evidence-only scoring, and consistent scores across hypotheses (T2, T8, T9).
