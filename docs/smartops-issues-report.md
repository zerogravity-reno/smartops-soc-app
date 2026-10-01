# SmartOps Issues Report

**As of:** 2026-10-01. **Code:** branch `task-broker-integration-fix`, commit `58d39c3` plus the Tool Broker fixes for B7 and B8 (PR into `main` pending).

**Scope:** the whole pipeline: context pipeline, Analyst (plan and synthesis), Tool Broker and sub-analysts, webapp integration, cost, audit trail and security. Items that also appear in `docs/analyst-bug-report.md` keep their IDs there (A#, C#) and are cross-referenced here.

## Evidence base

All runs investigated the same Splunk ES notable: *Threat - Custom - Windows PowerShell Process Discovery*, host `ar-f6eddb5b-df6`, user `Administrator`, `_time 2026-09-27T15:04:02+03:00`. Run `cecd266a` is the exception: it investigated *Malicious PowerShell Process - Encoded Command* on the same host.

| Run | Date | Outcome | Notes |
|---|---|---|---|
| SOC3 (saved UI page) | 2026-09-30 | FALSE POSITIVE 70%, 19 loops | Built before the integration fixes; the Broker handoff returned a stale run every loop |
| `cecd266a` | 2026-09-30 | FALSE POSITIVE 95%, 1 loop | Narrow task windows 3 h off (dropped `+03:00`) |
| `072fd610` | 2026-09-30 | TRUE POSITIVE 95%, 1 loop | First run after the time fixes |
| `04a15495` | 2026-10-01 | TRUE POSITIVE 90%, 2 loops | First evaluation leaned benign (30/90/90) |
| `a8118db9` | 2026-10-01 | TRUE POSITIVE 95%, 3 loops | First evaluation leaned benign (40/80/90) |
| `6fc4f590` | 2026-10-01 | no verdict | Stopped mid-Broker because the test machine ran out of memory; not a product fault |

Runs live in `.smartops/runs/<run_id>/`. The `072fd610` trace is at `tests/test-integration/trace-072fd610.html`.

**Severity:** **Critical** means it produces a wrong verdict, or a security exposure. **High** means it can produce a wrong verdict, or makes a verdict untrustworthy. **Medium** means cost, wasted work, or misleading output. **Low** means cosmetic or minor.

## Summary

| ID | Area | Issue | Severity | Status |
|---|---|---|---|---|
| T1 | Triage | Verdict accepted without meeting the stop rule (no code gate) | High | Open (A1) |
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
| P1 | Context | `event_time` is detection time, not activity time | High | Partly fixed (C6) |
| P2 | Context | Seed drops the command line and parent path | High | Open |
| P3 | Context | Hardcoded non-existent index `win_sysmon` | Medium | Open (C4) |
| P4 | Context | OpenCTI lookups use wrong types; unrelated intel added | Medium | Open |
| P5 | Context | ESCU matcher scores rule names only | Medium | Open (C5) |
| B1 | Broker | Observations drop the parent path, so it never reaches synthesis | High | Open |
| B2 | Broker | Narrow task windows miss the activity | Medium | Open (follows P1) |
| B3 | Broker | Planned steps for families with no tool (`investigate_edr`) | Medium | Fixed in `58d39c3` |
| B4 | Broker | Sub-analyst misread a `+03:00` row as outside a `Z` window | High | Fixed in `58d39c3` |
| B5 | Broker | Subagent hit its output-token cap; recovery produced no answer | Medium | Open |
| B6 | Broker | Follow-up tasks inherit every entity and the widest window | Medium | Open |
| B7 | Broker | Unconnected families (edr, ndr) named in what the models read; host questions steered off Splunk | Medium | Fixed on this branch |
| B8 | Broker | `tstats` unreliable: non-CIM fields return 0 rows; one filtered empty result killed a data model | Medium | Fixed on this branch |
| W1 | Webapp | Two different plans per investigation; the UI shows the one not executed | High | Open |
| W2 | Webapp | Stale run fed to the Analyst; exit code ignored | Critical | Fixed in `58d39c3` |
| W3 | Webapp | Tasks passed as `--entity` kinds the engine rejects | High | Fixed in `58d39c3` |
| W4 | Webapp | Hardcoded siem stub ran outside every guard | High | Fixed in `58d39c3` |
| W5 | Webapp | Demo alert pre-filled in the form | Medium | Fixed in `58d39c3` |
| W6 | Webapp | Model and log text inserted into `innerHTML` unescaped | Medium | Fixed in `58d39c3` |
| W7 | Webapp | Planning prompts disagree (entity schema, window rule) | Medium | Open |
| K1 | Cost | About $5–12 per Broker loop; long results re-sent every turn | Medium | Open |
| K2 | Cost | Blank `SMARTOPS_LLM_PROVIDER` does not stop Broker model calls | Medium | Open |
| K3 | Cost | SOC3 ran 19 loops on empty input | Medium | Open (T1, W2) |
| O1 | Audit | Context contract not saved with the run | Medium | Open |
| O2 | Audit | Dispatch-to-step link not recorded | Low | Open |
| O3 | Audit | Broker log written only at the end of a loop | Low | Open |
| S1 | Security | Live credentials in git history | Critical | Removed from tree; **rotation pending** (C1–C2) |
| S2 | Security | Splunk Web scraper replaced the official MCP | High | Fixed (C3) |

## Triage logic (Analyst plan and synthesis)

**T1. Verdict accepted without meeting the stop rule.** *High. Open (A1).*
- **Evidence:** SOC3 stopped at FALSE_POSITIVE with H2 80 / H3 75. That fails the prompt's own rule (top ≥ 85 and leads by ≥ 20). The SOC2 run stopped at H1 35.
- **Cause:** the loop ends on the model's self-reported `status` (`webapp/main.py:580`), and no code checks `hypothesis_scores`.
- **Fix:** compute the stop decision in code from the scores. Treat `status` as advisory.

**T2. Scores are unstable on the same input.** *High. Open (A2).*
- **Evidence:** `04a15495` loop 2 scored 30 / 90 / 90, then loop 3 scored 90 / 60 / 30. `a8118db9` went 40 / 80 / 90, then 75 / 65 / 68, then 95 / 65 / 30. SOC3 drifted 0/0/0 → 30/70/50 → 30/60/70 → 40/80/75 across loops that had *no new evidence*.
- **Impact:** a verdict can come down to which loop the run stops on. 2 of 3 true-positive runs passed through a confident benign state on the way.
- **Fix:** define a neutral baseline for "no evidence". Score only from cited observations, and require new evidence before a score can move.

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

**T7. Alert text and hypothesis wording are cited as evidence.** *High. Open (A4).*
- **Evidence:** `072fd610`'s verdict says *"through splunkd.exe compromise"*. That's hypothesis H1's own wording; nothing shows the real Splunk was compromised. "CISA AA23-347A" in the verdict comes from the alert annotations.
- **Fix:** label the alert facts and the plan text as non-evidence in the synthesis prompt, and require every claim in the verdict to cite an observation id.

**T8. Reasoning from absence.** *Medium. Open.*
- **Evidence:** `072fd610`: *"lack of benign indicators… confirm the malicious nature"*. The prompt itself says absence of evidence isn't evidence of absence.

**T9. Hypothesis scores aren't mutually consistent.** *Medium. Open.*
- **Evidence:** `04a15495` loop 2 scored FALSE_POSITIVE 90 *and* BENIGN 90 at the same time, for mutually exclusive outcomes.
- **Fix:** define what a score means (a probability, or independent support) and enforce it.

**T10. Status and verdict vocabulary are mixed.** *Medium. Open (A8).*
- **Evidence:** `a8118db9` loop 2 emitted `status: REQUIRES_INVESTIGATION` with `verdict: BENIGN, confidence 90`. SOC3's reasoning debates whether `UNCERTAIN` and `REQUIRES_INVESTIGATION` are verdicts or statuses.

**T11. Task entity kinds the Broker can't search.** *Medium. Open (A6).*
- **Evidence:** `072fd610` dropped T5 (`service`) and T8 (`command`); `a8118db9` dropped T5.
- **Fix:** list only the allowed kinds in the planning prompt, and validate in code before the handoff. Today the check exists only at conversion time (`run_trace`).

**T12. Wrong reference rule, and contradictory alignment judgements.** *Medium. Open (A7, C5).*
- **Evidence:** a Process Discovery alert (T1057) was matched to *Malicious PowerShell Process - Encoded Command* (T1027). In SOC3, the section-5 plan judged the alignment ALIGNED and the loop-1 plan judged it NOT_ALIGNED.

## Context pipeline

**P1. `event_time` is the detection time, not the activity time.** *High. Partly fixed (C6).*
- **Evidence:** the notable's `_time` is 15:04:02+03:00, which is when the search fired. Its `firstTime` is `2026-09-27T14:55:17` local, so 11:55:17Z, 9 minutes earlier. Before `58d39c3`, `event_time` was the browser's clock (`cecd266a`, SOC3).
- **Status:** now the notable's `_time` in UTC. It should come from `firstTime` or `orig_time`. `firstTime` has no offset, so take the offset from `_time`.

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

**B1. Observations drop the parent path.** *High. Open.*
- **Evidence:** rows with a masquerading parent (`C:\Users\Public\splunkd.exe` / `C:\Users\Administrator\Desktop\splunkd.exe`) in each run's `evidence.json`:
  - `cecd266a`: 15 / 10
  - `072fd610`: 12 / 10
  - `a8118db9`: 0 / 5
  - `04a15495`: **0 / 0**

  Where they were retrieved, **0** mentions reached the analyst payload. The observation read *"5 identical PowerShell commands under Administrator"*. `04a15495` never retrieved them at all and still concluded TRUE_POSITIVE (see T6).
- **Fix:** keep `ParentImage` (path) in the process-row projection and in the observation template.

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

## Cost

**K1. About $5–12 per Broker loop.** *Medium. Open.*
- **Evidence:** `cecd266a` $12.28, `072fd610` $9.07, `04a15495` $5.45 (2 loops), `a8118db9` $8.24 (3 loops). One T5 query returned 181 rows with full encoded command lines (837k characters, about 200k tokens), and the agent loop re-sends that on every turn.
- **Fix:** cap long values (command lines) in what the model sees, and keep full rows in `evidence.json`.

**K2. A blank `SMARTOPS_LLM_PROVIDER` doesn't stop Broker model calls.** *Medium. Open.* The engine still finds a model from the other AWS settings. Only `--scripted` is guaranteed free.

**K3. 19 loops on empty input.** *Medium. Open (T1, W2).* SOC3 spent 18 synthesis calls re-reading the same stale findings.

## Audit trail

**O1. The context contract isn't saved with the run.** *Medium. Open.* `investigation.jsonl` records the plan, the Broker run and the synthesis, but not the contract the Analyst was given. Comparing runs meant rebuilding it.

**O2. The dispatch-to-step link isn't recorded.** *Low. Open.* `072fd610` T7 had 2 steps and 2 dispatches, and nothing records which dispatch served which step.

**O3. The Broker log is written only at the end of a loop.** *Low. Open.* `broker-L<n>.log` stays at 0 bytes while the loop runs, so the task folders are the only live progress signal.

## Security

**S1. Live credentials are in git history.** *Critical. Removed from the tree; rotation pending (C1–C2).*
- **What:** the Bedrock API key, the VirusTotal key, the Splunk JWT and password, and the OpenCTI token. `.env.example` held the real OpenCTI token.
- **Where:** pushed on `origin/main`, `origin/integration` and `origin/feature/task-broker-input`. `58d39c3` removes them from the tree, not from history.
- **Action:** rotate all of them.

**S2. A Splunk Web scraper replaced the official MCP server.** *High. Fixed (C3).* `mcp_servers.json` points at the official server again (17 tools, time-bounded queries).

## Priorities

1. **Rotate the credentials** (S1).
2. **Make the verdict trustworthy:** a code-side stop gate (T1), a single plan (W1), a structured command line and parent path in the seed (P2), and the parent path kept in observations (B1). These four together decide whether a true positive is reached for the right reason.
3. **Fix the activity time:** `event_time` from `firstTime` (P1).
4. **Reduce cost:** cap long values in what the model sees (K1).
5. **Stabilise the scores:** baseline, evidence-only scoring, and consistent scores across hypotheses (T2, T8, T9).
