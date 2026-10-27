# Handover: Analyst bug sweep, B14 reverted, PR #15 still open (2026-10-27 b)

**Start here.** This replaces `docs/handover-2026-10-27.md`. The rules still apply:
- Mohammed owns scope and architecture.
- **The Analyst isn't ours.** That covers `analyst.py` and `prompts/analyst_system_prompt.txt`, and also any value of theirs that a Broker constant mirrors. Our side is the Broker, the subagents and the sub-analysts.
- The Analyst gets its task questions and the answers fetched, never what happened inside the Broker loop.

## State
- **Branch:** `broker-memory`, PR #15 → `main`. Keep it open.
- **Local commits not yet pushed** (pushing updates PR #15; ask first):
  - `2342977` docs: G13 logged (issue #16).
  - `f4c5d52` revert(B14): `analyst.MAX_GEN_LEN` back to Yousef's 16,384, and our `packing._ANALYST_GENERATION_RESERVE` back to match.
- **Tests:** 1,475 pass (`.venv/Scripts/python -m pytest engine/tests engine/contracts tests -q`). `analyst.py` and the Analyst prompt are identical to `main`.
- **B52:** A–D done on PR #15 but not yet checked live. E and F are open.

## What happened today
1. **Full app run `f497dca4` (`c75abeae` context): the Broker never ran.** The Analyst's first call answered in the evaluation format (a verdict, no tasks), and `analyst.py:501` accepted it as a direct verdict.
   - Every run since 10-26 does this: 4 of 4, after 26 of 26 planned normally up to 10-25.
   - It isn't caused by our code: nothing that feeds that call has changed since `c75abeae` planned.
   - Filed as **G13 / issue #16**, assigned to Yousef.
2. **B14 is open again.** `ed27070` had lowered the Analyst's `MAX_GEN_LEN` (16,384 → 12,288) to widen our handoff budget. That is the Analyst's setting, so it's reverted. The handoff budget is back to 13,272 characters, so a big round can drop observations again (on `20592fea`, all 27 were dropped).
3. **Analyst bug sweep.** Every Analyst bug in the issues report was tested against the current code.
   - The email to Yousef (CC Mariam) is saved as a draft in Gmail (and Outlook), **not sent**. It asks him to confirm which bugs exist. Once he confirms, we open a GitHub issue per bug, assigned to him.
   - The tests are in `C:\Users\pcc\AppData\Local\Temp\claude\D--projects-Smartops-SOC-App\27cd03dc-124c-453a-8de6-4497d9a600f4\scratchpad\analyst_bugs\`:

     | File | What it is | Result |
     |---|---|---|
     | `test_analyst_code.py` | No model | 24 fail (bug present), 3 pass (T11, T15, T17 fixed) |
     | `probe_analyst_live.py` | About 20 Foundation-Sec calls; replays saved runs through today's `investigate()` | Results in `live/summary.json` |

   - They fail by design. Don't put them on PR #15. If they're wanted in the repo, they go on their own branch for Yousef.
   - **Confirmed:**
     - Code: G2, G4–G12, AR6, T14 (code side), T20, T23, T26 (code side), T28–T30, W10, B6.
     - Live: G13, T2, T7, T8, T9, T12, T18, T27.
   - **Dropped:**
     - Not reproduced: T3, T10, T16, T22.
     - Can't check: T5 and T19 (runs not saved locally).
     - Only on Yousef's 10-25 runs, code unknown: T6, T4/T13/T21.

## Next
1. **B14, a Broker-side fix:** each round's payload must fit 13,272 characters without dropping observations. The test case is `20592fea` L2. This is ours to fix now.
2. **The live A–D check.** A full app run can't reach the Broker until #16 is fixed. Use the Broker-only replay of `c75abeae` L2→L3 instead (about $1.5; needs Mohammed's OK). The script is `replay_d.py` in the same scratchpad's `replayD/` folder, adapted from the step C replay. It logs every Broker tool call with its turn number, how each invocation stopped, and the review card's size. It checks that:
   - `review_step` is called after each dispatch;
   - reviews share a turn with the next dispatch;
   - no run hits `limit_turns`;
   - the cards stay bounded.

   The first try was stopped early in L2.
3. **B52 E then F**, patched into PR #15 (plan mode first). Mohammed wants this once A–D is confirmed.
4. **Owner items:**
   - Mohammed: send the email; push the two commits; merge #15.
   - Yousef: #16, plus any Analyst changes from 10-26 that he hasn't pushed (none are on GitHub). If he pushes them, rerun both test files against his branch.

## Notes
- Start the server from the repo root. Started from `engine/`, run records go to `engine/.smartops/runs` (as with `f497dca4`).
- The lab Splunk answers. `curl` exits 60 because of its self-signed certificate; the engine connects through the `.env` TLS setting. Don't use `-k`.
