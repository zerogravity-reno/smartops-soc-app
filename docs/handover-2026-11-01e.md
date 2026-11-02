# Handover: B51 reliability review for Claude (2026-11-01 e)

Start here after `handover-2026-11-01d.md`. Mohammed is taking the design discussion to Claude. No reliability fix has been approved or implemented in this session.

## Ownership and working state

- Mohammed owns scope and architecture. Frame the issue and agree on the fix before coding.
- Work is limited to the Broker side. `analyst.py` and the Analyst prompt belong to Yousef; findings there are for Mohammed to raise.
- Ponytail full is active: smallest complete change, reuse existing checks, retain audit evidence.
- Review and tests ran on `fix/preserve-rendered-evidence` at `49b04db`, which includes main `75f63bf` plus PR #17's rendering changes.
- Mohammed directed this handover onto existing PR #17 (`fix/preserve-rendered-evidence`). An initial documentation branch, `docs/handover-b51-reliability`, was pushed, but its PR creation was cancelled; no separate documentation PR was created. The checkout is back on PR #17's branch. Agree on implementation scope before coding.
- Existing untracked runbooks, plans, handovers and investigation directories were preserved. The plan files cited below are local/untracked; keep raw investigation artifacts out of commits.
- GitHub was checked during this session: PR #15 and PR #18 are merged; PR #17 remains open at `49b04db`. Current main was `75f63bf`. Recheck before starting implementation.

## What happened this session

1. Read the previous handover and explained B51.
2. Ran the saved seven-task B51 regression: passed.
3. Ran the existing offline app flow test and the separate synthesis-to-verdict test: both passed. The app flow test intentionally ends with no Analyst payload; it is not a complete live investigation.
4. Built the frontend and started the backend, serving the frontend at `http://127.0.0.1:8013`, without reload. The UI/ESCU smoke check passed. Backend process was PID 7124 (exec session 65628); verify it is still running. It was started on PR #17's branch before switching to this documentation branch, so restart before testing changed code. No live investigation was initiated by Codex.
5. Mohammed supplied saved run `f0f30aa6` for review against the latest PRs. Artifacts are local under `.smartops/runs/f0f30aa6/`.

## B51: distinguish the shipped fix from the unresolved issue

- **Shipped in PR #15:** budget-aware packing protects code command evidence before model prose, uses rendered JSON size, includes command parents, omits empty domains and rejects citation-only observations.
- **Original unresolved issue:** unchecked sub-analyst narratives can misattribute or interpret evidence and still reach synthesis. Narratives are only omitted when the budget requires it; they are not universally removed or claim-verified.
- `docs/smartops-issues-report.md` already records this as **B51**, with B11 recording earlier narrative misreads. Its status text is stale: it does not clearly distinguish the shipped packing work from remaining reliability work. Do not create a duplicate issue.
- `docs/b51b-plan.md` is a **parked draft**, not an approved implementation. It proposes a larger two-layer redesign. It explicitly says to retain narratives in the audit record if revived. Do not treat the entire draft as authorized.

## Findings from f0f30aa6

### What worked

- L2's handoff includes the download command, its output filename and its OneDrive parent together in code facts. B51's evidence-delivery fix worked here.
- Re-rendered with `json.dumps(..., indent=2)`, L2 is **13,199** characters and L3 is **12,973**, both within **13,272**.
- Follow-up scoping behaved as intended in this example: FU1 fell back to alert +/-1 hour; FU2 retained its explicit wider window (then expanded to include event +/-1 hour). It did not inherit the historical task's widest window.
- B52 E removed **six unsupported observations** in L2: two from T1, one from T2 and three from T4.

### Broker-side reliability gaps

1. **Rejected observations have an unchecked narrative route.** In L2 T4, observations about script blocks executing encoded commands were rejected, but related wording remained in the narrative that reached the Analyst. The verifier updates observations, not narrative text.
2. **Verification failure allows observations through.** L3 FU2's verifier raised `MaxTokensReachedException`. Its observations remained; `traces.json` says `skipped: verifier unavailable or incomplete`. That status is not part of the Analyst handoff. This matches the implemented skip policy, rather than a missing invocation.
3. T3's narrative calls a VirusTotal reputation value of zero "low reputation". The actual reported counts were zero malicious, zero suspicious and 71 undetected. Those counts establish neither maliciousness nor safety; the wording can steer interpretation.

Evidence: L2/L3 `analyst-payload.json`, L2 `broker.log` warnings, L3 `broker.log` around lines 63-89, and per-task `traces.json`. Do not publish these raw artifacts.

### Analyst-side findings: raise only

- Final synthesis assumes developer activity/custom binaries without supporting evidence and treats the hash as suspicious.
- It cites `FU3:endpoint`, although only FU1 and FU2 ran in L3 and no FU3 task exists in the saved run.
- Final telemetry records `model_status=REQUIRES_INVESTIGATION`, but post-gate output is `VERDICT_REACHED / BENIGN`, confidence 78, scores H3=88, H1=65, H2=40.
- Current main's numeric gate accepts 88 with a 23-point lead, forces the winning hypothesis's verdict, clears follow-ups and does not validate evidence references or unresolved gaps. The local Analyst file matched the fetched main blob `be45c335c4b42b33d6155b67ee93104d7939e2e6`.
- An offline gate replay using saved scores/references and model status reproduced acceptance with the nonexistent citation retained. The replay supplied a synthetic follow-up to confirm it is cleared; the original raw follow-up JSON is not separately stored in telemetry, so do not describe that synthetic task as part of the original model response.
- These observations show the final verdict is insufficiently supported. They do not prove the underlying activity was malicious, or that narratives alone caused the verdict. No controlled model replay isolated causation.

## What the feedback loops actually review

Mohammed remembered a Broker review of sub-analyst narratives. The agreed B52 plan and implementation are narrower:

- **B52 D, Broker review:** `broker.py:review_step` reviews the SIEM agent's retrieval, search scope and cited result rows against the task. This happens before domain sub-analyst narratives are generated. It does not review those narratives afterward.
- **B52 E, claim-support check:** `subagent_analysts/analyze.py:_check_claims` checks presence observations against cited rows, re-asks once for unsupported claims, rechecks corrections and removes unsupported observations. It does not verify the full narrative.
- `gather()` generates domain findings, applies `_check_claims`, saves traces, and converts findings into records. `_as_record()` preserves the narrative. `pack_for_analyst()` copies it into the handoff.
- `docs/b52-plan.md` sections D/E explicitly scope these checks and allow skipped verification without blocking. Withholding unchecked observations would change that policy and needs agreement.

## Proposed direction, NOT approved

Discuss two choices with Claude: remove unchecked narratives from the handoff, or extend verification to cover them. Also decide what happens when verification fails.

Codex recommended the smaller change:

1. Keep narrative generation and full audit narratives, but always leave narrative empty in the shared Analyst handoff projection. Retain existing fields; no two-layer contract redesign or new review model.
2. Derive name expansions from final observations instead of narrative text, while proving important paths and parent relationships still cross.
3. Preserve code-authored translation/grounding failure notices. They currently use narrative text; removing that field's content must not turn failures into apparent empty evidence.
4. On failed/incomplete verification, withhold affected presence observations from the handoff, retain them in audit, and send code evidence plus an honest verification-failure notice. This is a proposed change to B52 E's skip policy.
5. Fix necessary UI consumers: `domState()` and finding cards currently use narrative to determine whether a domain has content. Observations, summaries and facts must still display, with old saved runs supported.

This proposal is not a guarantee of correct final verdicts. It does not change Yousef's reasoning, reference validation or gate.

## Implementation map if agreed

- `engine/contracts/src/contracts/reasoning.py`: `pack_for_analyst`, `_says_something`, empty-domain handling and trim policy. Retain the published field shape where possible; inspect generated-schema implications if descriptions/models change.
- `engine/src/smartops/subagent_analysts/analyze.py`: `_check_claims`, `_as_record`, final observations, failure notices and audit retention.
- `engine/src/smartops/subagent_analysts/formatting.py`: `name_expansions`; keep name/path evidence grounded in rows.
- `engine/src/smartops/subagent_analysts/verify.py`: understand existing limits and error path; do not assume increasing tokens solves narrative bypass.
- `frontend/src/format.ts`, `frontend/src/components/Cards.tsx`: domain status and evidence display.
- Tests: packer, claim checks, name expansions, empty exhibits, summary preservation, failure handling, published schemas and frontend rendering/status.
- Update the existing B51/B52 entries in `docs/smartops-issues-report.md` to describe actual scope and validation. Keep unrelated PR #17 rendering work separate.

## Validation completed

Commands used the existing `.venv`, with pytest's cache disabled because `.pytest_cache` is inaccessible in this sandbox.

- `.venv/Scripts/python -m pytest -q -ra -p no:cacheprovider engine/contracts/tests/test_pack_for_analyst.py::test_d6b48ef0_keeps_the_download_within_budget`: **1 passed**.
- `.venv/Scripts/python -m pytest -q -ra -p no:cacheprovider tests/test_app_e2e.py::test_an_alert_runs_from_the_api_through_a_real_broker_round tests/test_analyst_loop.py::test_one_round_to_a_verdict_streams_the_stages_in_order`: **2 passed, 3 warnings** about an unawaited MCP shutdown coroutine.
- `.venv/Scripts/python -m pytest -q -ra -p no:cacheprovider engine/contracts/tests/test_pack_for_analyst.py tests/test_analyst_handoff.py tests/test_verdict_gate.py engine/tests/test_claim_check.py engine/tests/test_analyst_formatting.py`: **125 passed**.
- Frontend `npm run build`: passed after an escalated retry; first sandbox attempt failed with Vite subprocess `EPERM`.
- `.venv/Scripts/python .github/scripts/smoke.py`: **UI and ESCU lookup passed**.
- Offline saved-run assertions: both payloads fit budget; download and parent share a fact; FU3 reference has no task; gate accepts saved scores and retains that invalid reference.
- Initial sandbox backend startup could not connect to MCP. Stopped it and restarted outside the sandbox; startup completed. Startup alone is not a validated live integration.

## Next with Claude

1. Agree on the Broker-only reliability boundary and failed-verification policy before implementation.
2. Add small sanitized regressions for narrative bypass, verification failure, audit retention, failure notices and UI evidence-only findings; retain the seven-task download/budget regression.
3. Run relevant Python and frontend checks, then the full Python suite before sharing application changes. No live model calls unless explicitly requested.
4. Raise the separate Analyst findings with Yousef through Mohammed. Do not send messages or update Asana on Mohammed's behalf without instruction.

No application files, prompts, manifests, lockfiles or repository policy were changed for this review. No branch was deleted, and PR #17 was not merged.
