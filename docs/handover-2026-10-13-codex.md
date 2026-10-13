# Handover for Codex: Tool Broker work (2026-10-13)

**Start here.** You're picking up the Tool Broker side of SmartOps from a Claude Code session.
- This file stands on its own. For more depth, read these:
  - `docs/handover-2026-10-12-close.md`, including the addendum at its end.
  - The "Where things stand (2026-10-12 close)" section under Priorities in `docs/smartops-issues-report.md`.
- The owner is Mohammed. He decides scope and architecture, and nothing gets coded before he says go (see Working rules).

## What the system is (only what you need)
- **Analyst Agent** (`engine/src/smartops/analyst.py`): Foundation-Sec plans hypotheses, writes tasks and synthesises a verdict. **Not ours**: route Analyst issues to Mohammed and don't edit them.
- **Tool Broker** (`engine/src/smartops/broker.py`): this is ours.
  - It's an agent. It plans fetch steps per task and dispatches the `siem`/`vt` subagents.
  - `evaluate_step` is the one place a step's completion is judged.
  - `run_round` wraps `_round`. `main.py` has an unrelated `_run_round`.
- **Subagents** (`engine/src/smartops/subagents/`): `siem` searches Splunk through MCP and `vt` calls VirusTotal.
  - The Broker decides *what* siem looks for. The siem prompt holds search mechanics only.
- **Sub-analysts** (`engine/src/smartops/subagent_analysts/`): single-shot 8B model calls per domain (identity, network, endpoint). They aren't agents.
  - They **translate rows into narrative and never judge**: no verdicts, no "suspicious", no relevance framing.
  - The rows they read are rendered by `formatting.py`.
- **Tools and MCP** go through `engine/src/smartops/tools/` only (`registry.py`). There's no MCP client anywhere else.
- **Entry point:** `engine/src/smartops/main.py`. `start.ps1` runs the server with `--reload`.
- **Runs** land in `.smartops/runs/<run_id>/`:
  - `investigation.jsonl`
  - `L<n>/broker.log`, `L<n>/tasks.json`, `L<n>/analyst-payload.json`
  - `L<n>/T<k>/{report,evidence,findings,traces}.json`

## Current state
- **Branch:** `broker-a818-fixes`, PR #6. HEAD is `299a1f5`. About 21 commits are unpushed. **Don't push**; Mohammed pushes.
- **Tests:**
  - `uv run pytest -q engine/contracts engine/tests tests`: 1303 passed at `847d2fd`. Docs-only commits since then.
  - `cd frontend; npm test` and `npm run build` cover the frontend.
- **Uncommitted changes that aren't ours:** `engine/src/smartops/main.py` (RunLog), `frontend/*`, `tests/test_run_control.py` and `.gitignore` belong to the frontend session (smartops-worker).
  - Don't stage them.
  - If you must commit a change to `main.py`, stage only your hunk: `git hash-object -w` + `git update-index --cacheinfo`.
- **Broker bugs:** 45 tracked (B1–B45), and 42 are closed.
  - B2, B6 and B20's scoping half are open on the **Analyst side**, with no Broker work left.
  - B24 (MCP reconnect) is fixed but never seen live. It needs a Splunk MCP outage, and so do AR13/AR14.
- **Asana:** project "Broker bug fixing", parent `1219394496434075`, one subtask per B bug. It's in line with the report as of 2026-10-12 close.
  - B46 and B47 are listed in the parent's notes as *proposed*, with no subtasks.
  - Don't change Asana unless Mohammed asks.
- **Last live run:** `b7359eab`.
  - B11, B16 (parallel fetch, 5 tasks in 90 s), B44 and B45 held.
  - B43 and B24 weren't exercised.

## Next work, in order (both wait on Mohammed's go)

### 1. B46: an empty `uncategorised` set blocks `confirmed_empty`
- **Symptom:** a step that searched its categories and found nothing is marked *incomplete* instead of *confirmed empty*. The gate then refuses the Analyst's refs to that task. That happened on `c8dd42cf`.
- **Seen on:**
  - `ae7d41b0` L2-T4 `task_artifacts`: a `stats count by EventCode, sourcetype` left an empty `uncategorised` set.
  - `b7359eab` L2-T4 `conn_tls`: `uncategorised:0`. The step still came back ok there because it had connection rows. The sub-analyst also wrote an observation that rests only on the 0-row `uncategorised#1`, which triggered a WARNING at `subagent_analysts/analyze.py:966`.
- **Cause:** `engine/src/smartops/broker.py` `evaluate_step`, around line 631: `and not any(name == "uncategorised" for name, _ in counts)`. It fires on the set's *presence*, not its rows.
- **Fix:** block only when `uncategorised` holds rows, for example `and not any(name == "uncategorised" and n > 0 for name, n in counts)`.
  - Add one test next to the existing `evaluate_step` tests in `engine/tests/test_broker.py`. An empty `uncategorised` plus 0 rows in the wanted categories plus queries run should give `confirmed_empty=True`.
  - A non-empty `uncategorised` must still block.
- **Open question for Mohammed:** should the B46 fix also stop sub-analyst observations from citing 0-row sets? That would be in `subagent_analysts/` and needs his call.

### 2. B47: empty fields render as `-` and are read as values
- **Symptom (`b7359eab` T4 network):**
  - Every connection row rendered as `proto=udp bytes=- uri=- action=- events=7`.
  - The narrative said: "All six connections had equal byte transfers and no recorded actions." The rows have no byte or action fields at all, and it was 3 rows, not six.
- **Class:** the same as B40, where a `-` placeholder was counted as a value, but on the rendering side.
- **Where:** `engine/src/smartops/subagent_analysts/formatting.py`.
  - `_field()` (around line 297) defaults to `"-"`, and every `_format_*` function writes `key=<value>` unconditionally (`_format_connection` around line 330, `_format_auth_event`, `_format_dns_resolution`, and the file, registry and process formatters).
- **Proposed fix:** leave `key=-` tokens out of the rendered row, in one shared place rather than per formatter. Fix the class, not one formatter. Watch for these:
  - **The empty-line check** (the docstring around lines 425–445): `_format_connection`'s bare `src:port→dest:port` tuple counts as content. A row left with nothing after dropping placeholders must still fall back the way it does today. Read that function and its tests first.
  - **Prompt documentation:** `subagent_analysts/prompts.py` (around lines 291 and 320–351) and `shown.py` (around lines 102 and 133) show the row shape with every field. Update them to say absent fields are omitted.
  - **The narrative miscount** ("six connections" for 3 rows and 21 events) is the 8B model's. Don't add a prompt rule for it. Prompt rules have repeatedly failed on these models (see B1, B15).
- **Before coding:** write up the issue and the proposed fix for Mohammed and wait for his agreement.

### 3. Waiting on a live run (no code)
- **B24, AR13, AR14:** these need the Splunk MCP session to die mid-round. A forced check:
  1. Start a 3+-task run.
  2. Once `broker.log` shows `fetching 1/N`, kill the Splunk MCP server process.
  3. Restart it about 10 s later.
- **Pass if all of these hold:**
  - The log shows `an MCP client's session ended mid-run; reconnecting it` (`tools/registry.py` around line 680) or the "sticky" variant (around line 684).
  - The affected step is ERROR, not hung.
  - A re-dispatch succeeds, or the round ends with AR13's `not_searched` / AR14's Broker failure.
- Ask Mohammed before killing anything on his machine.

## Out of scope (Mohammed, 2026-10-12)
- Anything in `analyst.py`, including AR6 (`extract_json`), and the gate bugs G1–G3 and the T-series. They're Analyst side; route them, don't fix them.
- The context pipeline: P2, P4, P5 (`context.py`, OpenCTI/ESCU).
- Webapp and frontend files. Those belong to smartops-worker's frontend session.
- Owner actions: key rotation (S1), `.env` cleanup, pushing.

## Working rules (from Mohammed; they apply to you too)
1. **Frame the issue, then code.** State the issue and the proposed fix, get his agreement, then implement. Fix the class of bug, not the one case.
2. **Ask, don't assert, on architecture.** If research contradicts a design he chose, raise it as a question.
3. **Simplicity first.** Scope to what runs now, and don't build protection for paths that can't execute yet. Remove duplication instead of documenting it.
4. **No model arithmetic.** Code computes every count, time and sum. A prompt never asks a model to calculate.
5. **Sub-analysts translate, they don't judge.**
6. **A fix isn't done until a live run shows it.** For a named run, read what the evidence said and whether it was used, not just whether the mechanics ran. Report what held and what wasn't exercised, separately.
7. **Strands:** check the installed SDK source (`.venv/Lib/site-packages/strands`) before designing. The docs site lags it. Don't hand-roll what it ships.
8. **Docs:** after each fix, update the bug's entry in `docs/smartops-issues-report.md`: the summary table row, the detail section and "Where things stand". Add a timesheet row in `docs/broker-timesheet.md` if you track time.
9. **Commits:** small, one per fix, with a message like `fix(B46): …`. Don't push.

## Gotchas
- Shell heredocs mangle `"\n"` escapes in Python source. Edit code with a real editor or patch, not `cat <<EOF`.
- Keep the `analyze`/`subagents` imports at the end of `broker.py`, or the import cycle comes back.
- `FETCH_CONCURRENCY = 3` (B16) is sized for the lab Splunk with an admin MCP account. A `ponytail:` comment marks it.
- Each task's log lines are buffered and written whole, in task order. Order in `broker.log` isn't execution order; use file mtimes for timing.
