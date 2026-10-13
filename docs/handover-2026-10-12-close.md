# Handover: Broker list cleared, AR11 integration fixed, parallel fetch (2026-10-12 close)

**Start here in a new session.** This replaces `docs/handover-2026-10-12-eve.md`. The current status table is "Where things stand" under Priorities in `docs/smartops-issues-report.md`.

## Current state
- **Branch:** `broker-a818-fixes`, PR #6. HEAD is `847d2fd`. 20 commits since `241447c`, **none pushed**.
- **Tests:**
  - `uv run pytest -q engine/contracts engine/tests tests`: 1303 passed.
  - `cd frontend; npm test`: 13 passed.
  - `npm run build`: clean.
- **Uncommitted, and not ours:** the frontend session's work. That's `engine/src/smartops/main.py` (RunLog), `frontend/*`, `tests/test_run_control.py` and `.gitignore`. smartops-worker commits it separately. AR3's deletion in `main.py` was committed hunk-only, so their lines are still unstaged and intact.
- **Server:** `start.ps1` runs with `--reload`, so it picked up every change. The last live run is `ae7d41b0`.

## Done this session
### Broker bugs: no Broker work left
| ID | Fix | Commit |
|---|---|---|
| B42 | An unanswerable reason is at most 60 chars and names only what's missing | `4759d2b` |
| B43 | The private-address footer reads "(not internet-routable)", with no mention of VirusTotal | `ad5afe6` |
| B44 | The siem mission names the categories the step is judged on; an incomplete step's digest names the missing ones | `5b75365` |
| B45 | `run_round` runs `gc.collect()` inside its own loop, so no anthropic client closes on the next round's loop | `28ca7f7` |
| B11 | Grouped rows render `events=N`, not `count=N` (it was read as "bytes" and "actions") | `0430974` |
| B16 | A round's tasks fetch in parallel, `FETCH_CONCURRENCY = 3` | `cfab611` |
| B10 | Closed: the B10c rework was already verified live | (report) |
| B5 | Closed: not reproduced since 2026-09-30 | (report) |

- **Broker status:** 40 fixed, 1 partly fixed (B20), 2 open (B2, B6).
  - B2 and B6 are On-Hold in Asana.
  - B20's "can't answer" half is fixed. Its scoping half, like B2 and B6, needs the Analyst's follow-ups to name the task they follow. Nothing on the Broker side remains.
- **B16 sizing:**
  - The lab search head allows 16 concurrent searches (6 + 1/CPU × 10).
  - The MCP account is `admin` (srchJobsQuota 50).
  - A task runs up to ~3 siem steps at once, so 3 tasks peak near 9 searches.
  - Each task's log lines are buffered and written whole, in task order.
  - A `ponytail:` comment says a production Splunk with a non-admin account needs its own number.

### AR11 integration regressions (smartops-worker's merge; fixed here, numbered AR)
- **AR12** (`7901a43`, `0b15cdf`): the Splunk client stayed failed after one bad handshake.
  - Strands' `load_tools()` returns `[]` while `_connection_failed` is set. Only `stop()` clears it, and in-process `start()` warmed once per server.
  - The queue kept working because `registry.call_tool()` reconnects on its own.
  - Fix: warm every round, and reset a sticky failure at dispatch.
  - Runs `75984491` and `16386362` had no SIEM because of this.
- **AR13** (`ef1bde8`): `AnalystPayload.not_searched` says, in code-written words, when a source left domains empty, so silence isn't read as "nothing found". The field isn't in the published schemas.
- **AR14** (`ef1bde8`): `run_round` raises when an unreachable source left the round with no rows, which ends the run as a Broker failure.
- **AR3** (`7d6fb77`): the global boto3 bearer patch is deleted.
  - Verified first: the Analyst authenticates with `SMARTOPS_ANALYST_API_KEY` both with and without importing `smartops.main`, and a bogus key gets `AccessDenied`.
  - `FS8B_API_KEY` is retired from `.env.example`, the README and `docs/integration.md`.
  - The current key is not the one leaked in `d113695`.

### Frontend and docs
- **W9 and P3** (`3978b9f`), in `frontend/src/contract.ts`, with a new `contract.test.ts`:
  - W9: an unresolved event time stays unset instead of falling back to the notable time.
  - P3: the hardcoded `win_sysmon` is gone.
- **Report:**
  - W1 and W7 are closed as removed with AR1/AR11.
  - The README route table matches `main.py`.
  - smartops-worker rewrote the README for the AR11 layout (`8185ec6`).
- **Asana** ("Broker bug fixing", parent `1219394496434075`):
  - 41 of 45 subtasks closed, and the parent's notes rewritten.
  - Status field: B2, B6, B20 On-Hold; B16 Testing; B44, B45 Completed.

## Live verification, `ae7d41b0` (2 rounds, VERDICT_REACHED)
- **Held:**
  - AR12: siem ran in both rounds.
  - AR3: no `AccessDenied`.
  - B45: 0 "Event loop is closed".
  - B44: the file step searched file and registry events on its first dispatch.
  - B43: synthesis never mentioned VirusTotal.
  - B11: no count read as bytes or actions.
- **Not exercised:** B24 and AR13/AR14 need an outage. B16 went in after this run.

## Next, in order
1. **B46, waiting on Mohammed's go** (not yet in the report or Asana).
   - Problem: a step that searched its categories and found nothing is marked incomplete instead of confirmed empty.
   - Cause: `evaluate_step` blocks `confirmed_empty` when any `uncategorised` set exists, even one with 0 rows.
   - Seen on `ae7d41b0` L2-T4 `task_artifacts`: a `stats count by EventCode, sourcetype` left an empty `uncategorised` set.
   - Why it matters: an incomplete step makes the gate refuse refs to that task (seen on `c8dd42cf`).
   - Fix: block only when `uncategorised` holds rows. One line plus a test.
2. **Live run for B16:** a 3+-task plan. Check the round-1 Broker phase time, and look for siem `error`/`no_data` that a Splunk queue would cause.
3. **Route to the Analyst owner** (Mohammed sends):
   - The published schema gained `maxLength: 60` (B42).
   - `AnalystPayload` gained `not_searched` (AR13).
   - G1–G3.
   - Follow-ups should name their task (B2, B6, B20).
   - T8: `16386362` reasoned from the silence.
   - T15: `16386362` was cut off listing refs `T1`…`T51`.
   - The `ae7d41b0` round-1 ref `T1:processes#1` named a block T1 doesn't have.

## Owner actions (Mohammed)
- Delete `FS8B_API_KEY` from the local `.env`; nothing reads it since AR3.
- S1: confirm the `33ccf52` keys were in the rotation.

## Out of our scope (Mohammed, 2026-10-12)
- The context pipeline: P2, P4, P5 (`context.py` OpenCTI/ESCU, the seed's parent path).
- Anything in `analyst.py`, including AR6 (`extract_json`).

## Gotchas
- Shell heredocs mangle `"\n"` escapes in Python source written through them. Use the Edit tool for code.
- `main.py` holds another session's uncommitted work. Stage only your own hunk (`git hash-object -w` + `git update-index --cacheinfo`), as AR3 did.
- Keep the `analyze`/`subagents` imports at the end of `broker.py`, or the import cycle comes back.
- `broker.run_round` wraps `_round`. `main.py` has its own unrelated `_run_round`.

## Addendum: `b7359eab` checked, work paused (2026-10-12 17:55)
- **Held on `b7359eab`:**
  - B16: 5 tasks fetched concurrently in 90 s, with 0 failures and no Splunk queue errors.
  - B44: T2's file step searched every EventCode on its first dispatch.
  - B45: 0 tracebacks.
  - B11: rows render `events=7`.
- **Not exercised:**
  - B43: no VirusTotal steps ran.
  - B24 and AR13/AR14: they still need an MCP outage.
- **New, proposed and waiting on Mohammed:**
  - B46 (above).
  - B47: empty fields render as `bytes=- uri=- action=-`, and T4 network read them as "equal byte transfers and no recorded actions". Proposed fix: leave empty fields out of the rendered row.
- **Asana is in line with the report:**
  - 42 of 45 closed, Progress 0.93.
  - B11's status field set to Completed and B16's Stage set to Done.
  - b7359eab comments added on B11, B44, B45.
  - B46/B47 listed in the parent as proposed, with no subtasks.
- **Timesheet** runs through 10-12: Broker ≈ 40.5 h (lower bound ≈ 29.4 h).
- **Next, when work resumes:** B46, then B47, once Mohammed says go.
