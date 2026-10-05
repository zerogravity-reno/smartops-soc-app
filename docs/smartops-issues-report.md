# SmartOps Issues Report

**As of:** 2026-10-05. **Code:** branch `post-analyst-update-integration`, cut from `main` at `8b07441` (PR #2 merged), plus the hand port of the teammate's analyst branch (`330d1bc`) and the B1c, K2 and O2 fixes.

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
| T1 | Triage | Verdict accepted without meeting the stop rule (no code gate) | High | Partly fixed (`330d1bc`) |
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
| B1 | Broker | Observations drop the parent path, so it never reaches synthesis | High | Fixed (`e475a84`, narrative names on this branch); live re-run pending |
| B2 | Broker | Narrow task windows miss the activity | Medium | Open (follows P1) |
| B3 | Broker | Planned steps for families with no tool (`investigate_edr`) | Medium | Fixed in `58d39c3` |
| B4 | Broker | Sub-analyst misread a `+03:00` row as outside a `Z` window | High | Fixed in `58d39c3` |
| B5 | Broker | Subagent hit its output-token cap; recovery produced no answer | Medium | Open |
| B6 | Broker | Follow-up tasks inherit every entity and the widest window | Medium | Open |
| B7 | Broker | Unconnected families (edr, ndr) named in what the models read; host questions steered off Splunk | Medium | Fixed on this branch |
| B8 | Broker | `tstats` unreliable: non-CIM fields return 0 rows; one filtered empty result killed a data model | Medium | Fixed on this branch |
| B9 | Broker | Handoff to the Analyst had no size limit; B1's summaries would overflow its window | High | Fixed (`e475a84`); webapp round compaction open |
| W1 | Webapp | Two different plans per investigation; the UI shows the one not executed | High | Open |
| W2 | Webapp | Stale run fed to the Analyst; exit code ignored | Critical | Fixed in `58d39c3` |
| W3 | Webapp | Tasks passed as `--entity` kinds the engine rejects | High | Fixed in `58d39c3` |
| W4 | Webapp | Hardcoded siem stub ran outside every guard | High | Fixed in `58d39c3` |
| W5 | Webapp | Demo alert pre-filled in the form | Medium | Fixed in `58d39c3` |
| W6 | Webapp | Model and log text inserted into `innerHTML` unescaped | Medium | Fixed in `58d39c3` |
| W7 | Webapp | Planning prompts disagree (entity schema, window rule) | Medium | Open |
| K1 | Cost | About $5–12 per Broker loop; long results re-sent every turn | Medium | Fixed (`0e82b4c`) |
| K2 | Cost | Blank `SMARTOPS_LLM_PROVIDER` does not stop Broker model calls | Medium | Fixed on this branch (`none`) |
| K3 | Cost | SOC3 ran 19 loops on empty input | Medium | Fixed (W2, T1 gate, `max_loops` 3) |
| O1 | Audit | Context contract not saved with the run | Medium | Fixed (`c85eb93`) |
| O2 | Audit | Dispatch-to-step link not recorded | Low | Fixed on this branch |
| O3 | Audit | Broker log written only at the end of a loop | Low | Fixed (`c85eb93`) |
| S1 | Security | Live credentials in git history | Critical | Removed from tree; **rotation pending**; new leak in `33ccf52` (C1–C2) |
| S2 | Security | Splunk Web scraper replaced the official MCP | High | Fixed (C3) |

## Triage logic (Analyst plan and synthesis)

**T1. Verdict accepted without meeting the stop rule.** *High. Partly fixed (`330d1bc`, A1).*
- **Evidence:** SOC3 stopped at FALSE_POSITIVE with H2 80 / H3 75. That fails the prompt's own rule (top ≥ 85 and leads by ≥ 20). The SOC2 run stopped at H1 35.
- **Cause:** the loop ends on the model's self-reported `status` (`webapp/main.py:580`), and no code checks `hypothesis_scores`.
- **Fix:** compute the stop decision in code from the scores. Treat `status` as advisory.
- **Done (`330d1bc`):** `run_trace.verdict_gate` sets `status` in code: top ≥ 85, a lead of ≥ 20, and at least one non-`ALERT:` entry in `evidence_refs`, which the evaluation schema now asks for. The trace keeps the model's own status as `model_status`. Not yet measured on a live run.

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

**B9. The handoff to the Analyst had no size limit.** *High. Fixed (`e475a84`).*
- **Evidence:** B1's summaries took T3's payload from 2,428 to 17,011 characters, and added 27,443 across `072fd610` round 2. The Analyst has a 32,768-token window with 4,096 reserved for output, and the webapp resends every earlier round in each synthesis call (`max_loops` 3). Uncapped, round 2 would probably overflow.
- **Fix:** `HANDOFF_CHAR_BUDGET` (`subagent_analysts/packing.py`) is worked out from the Analyst's window: window − output − 4,300 tokens for the system prompt and plan (measured on `072fd610`) − margin, ÷ 3 rounds. That's about 20.7k characters per round, split across the file's tasks. `HypothesisFindings.for_analyst(max_chars)` always keeps narratives and observations, adds summaries with cited sets first, and records how many it left out. Full summaries stay in `findings.json`.
- **Offline, `072fd610` round 2:** the batch is 19.6k characters. T7 keeps `processes#1`, whose powershell parents are only `C:\Users\Administrator\Desktop\splunkd.exe=3, C:\Users\Public\splunkd.exe=2`. A compact format (dropping time and single-value lines) was measured and rejected: it saved only 22%, and the single-value lines carry the signal.
- **Open (webapp):** resending only the latest round, instead of every round, would triple each round's budget. Then set `_ANALYST_ROUNDS` to 1.

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

**K1. About $5–12 per Broker loop.** *Medium. Fixed (`0e82b4c`).*
- **Evidence:** `cecd266a` $12.28, `072fd610` $9.07, `04a15495` $5.45 (2 loops), `a8118db9` $8.24 (3 loops). One T5 query returned 181 rows with full encoded command lines (837k characters, about 200k tokens), and the agent loop re-sends that on every turn.
- **Fix:** cap long values (command lines) in what the model sees, and keep full rows in `evidence.json`.
- **Done:** the fetch subagents use Strands' `ContextOffloader` (preview above about 2,500 tokens, no retrieval tool). Evidence is captured first at `SDK_FIRST` and stays full. `072fd610-L2-T3`: $1.56 before, $0.72 and $0.79 after.

**K2. A blank `SMARTOPS_LLM_PROVIDER` doesn't stop Broker model calls.** *Medium. Fixed on this branch.* The engine still finds a model from the other AWS settings. Only `--scripted` was guaranteed free.
- **Fix:** `SMARTOPS_LLM_PROVIDER=none` returns no provider (the scripted invoker) even with credentials present. Blank still means "detect", so a blank line in a copied `.env` doesn't change behaviour. The sub-analyst model has its own switch (`SMARTOPS_ANALYST_MODEL_ARN`).

**K3. 19 loops on empty input.** *Medium. Fixed.* SOC3 spent 18 synthesis calls re-reading the same stale findings. W2 removed the stale input, `max_loops` is 3, and the T1 gate stops a confident verdict that cites no evidence. The teammate branch's `max_loops` 9999 was not ported.

## Audit trail

**O1. The context contract isn't saved with the run.** *Medium. Fixed (`c85eb93`).* `investigation.jsonl` recorded the plan, the Broker run and the synthesis, but not the contract the Analyst was given. Comparing runs meant rebuilding it. The `analyst_plan` line now carries it as `context`.

**O2. The dispatch-to-step link isn't recorded.** *Low. Fixed on this branch.* `072fd610` T7 had 2 steps and 2 dispatches, and nothing records which dispatch served which step. Still true on `ded5cac1`: `step_outcomes[].dispatches` was only a count. `StepOutcome.result_ids` now lists the `SubtaskResult.task_id` of each dispatch that served the step, which is the join to `report.json`'s `results`.

**O3. The Broker log is written only at the end of a loop.** *Low. Fixed (`c85eb93`).* `broker-L<n>.log` stayed at 0 bytes while the loop ran. The child process was unbuffered, but the webapp's own file handle used block buffering. It's now line-buffered.

## Security

**S1. Live credentials are in git history.** *Critical. Removed from the tree; rotation pending (C1–C2).*
- **What:** the Bedrock API key, the VirusTotal key, the Splunk JWT and password, and the OpenCTI token. `.env.example` held the real OpenCTI token.
- **Where:** pushed on `origin/main`, `origin/integration` and `origin/feature/task-broker-input`. `58d39c3` removes them from the tree, not from history.
- **New (2026-10-05):** `origin/updated-analyst-agent` (`33ccf52`) commits a `.env` with the AWS access and secret keys, the FS8B key, the Splunk token and the VT key, plus a hardcoded OpenCTI token and a Splunk user and password as code defaults. It was ported by hand, not merged, so none of it is on `post-analyst-update-integration`.
- **Action:** rotate all of them, and have the branch deleted or rewritten.

**S2. A Splunk Web scraper replaced the official MCP server.** *High. Fixed (C3).* `mcp_servers.json` points at the official server again (17 tools, time-bounded queries).

## Priorities

1. **Rotate the credentials** (S1).
2. **Make the verdict trustworthy:** a code-side stop gate (T1), a single plan (W1), a structured command line and parent path in the seed (P2), and the parent path kept in observations (B1). These four together decide whether a true positive is reached for the right reason.
3. **Fix the activity time:** `event_time` from `firstTime` (P1).
4. **Reduce cost:** cap long values in what the model sees (K1).
5. **Stabilise the scores:** baseline, evidence-only scoring, and consistent scores across hypotheses (T2, T8, T9).
