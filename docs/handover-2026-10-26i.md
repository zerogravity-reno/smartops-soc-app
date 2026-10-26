# Handover: PR #15 `broker-memory` (2026-10-26, i)

**Start here.** This replaces handovers b to h. The rules still apply:
- Mohammed owns scope and architecture.
- `analyst.py` and the Analyst prompt aren't ours.

## State
- **PR:** https://github.com/zerogravity-reno/smartops-soc-app/pull/15, branch `broker-memory` → `main`. It holds every unmerged Broker commit since `main` @ `010108b`: B11, B14, B48–B50, B52 A–C, B53, B54 and B56.
- **Merge:** main returned no readable branch protection (`gh api …/protection` 404), so auto-merge isn't set. Waiting on CI (`SmartOps CI`) and Mohammed.
- **Tests:** 1,447 pass (`.venv/Scripts/python -m pytest engine/tests engine/contracts tests -q`). Ruff isn't in `.venv`.
- **Superseded branches:** `fix/siem-step-c-review`, `fix/broker-run-memory`, `broker-fixes` and `docs/handover-step-c-review`. All are contained in `broker-memory` except `e52e3d4` (a stale handover doc). They can be deleted once #15 merges.
- **Untracked, not in the PR:** `docs/handover-2026-10-26{b..h}.md`, `docs/handover-step-c-review.md`, `docs/b52-plan.md` and `docs/run-20592fea-review.md`. These are superseded working notes; delete them, or ask before committing any of them.

## Done today: B56, "a count is a count, not a row" (handover h's audit)
Mohammed's answers: code records what Splunk returned and the agent judges a count; aggregate rows don't fill `min_rows`; truncation is shown, and blocks exhaustive completion; items 2, 5, 6 and 8 are in.

| Item | Fix | Where |
|---|---|---|
| 1, 7 | `ResultSet.kind` (events/count/aggregate/unknown) from the last transforming SPL command. A count set adds no rows, isn't "empty", and `total_rows()` skips it, so NO_DATA stays NO_DATA. | `projection._result_kind`, `findings.py`, `measure_step` |
| 2 | `scalar_count` decodes a lone `{count: N}`. The guard reads `[{count:"0"}]` as empty; `_absence_count` uses the same decoder. | `projection.scalar_count`, `guards.py:_result_is_empty`, `broker._absence_count` |
| 3 | `measure_step` returns a 4th value, answering event rows. `StepOutcome.event_rows` fills `min_rows`; a target-matching aggregate row still answers. | `broker.measure_step`, `_settle`, `subagents._still_missing` |
| 4 | `ResultSet.truncated/total` come from the payload. Shown on the search line (`capped: Splunk had N rows…`), the digest (`capped=`) and the exhibits. A capped set has rows, so it never proves empty or absence. | `projection._cap_of`, `subagents._search_line`, `broker._digest`, `formatting.py` |
| 5 | `row_matches`: IPs and 32/40/64-hex hashes match whole tokens (also inside command lines); names stay substring. Attribution and completion share it. | `projection.row_matches` |
| 6 | The unseen-field hint learns fields from event rows only. | `subagents._unseen_filter_fields` |
| 8 | Event rows dedupe by canonical JSON across searches (search line) and dispatches (`StepOutcome._seen_rows`, private and not persisted). | `broker.measure_step` |

Tests: `engine/tests/test_result_kind.py`, one per item. Three `test_broker` fixtures and one `test_subagents` fixture repeated identical rows; they now use distinct rows, since dedupe is the point.

**Lab facts (Splunk only):**
- `| tstats count from datamodel=Email` returns `[{count: "0"}]`, `truncated: false`, `total_rows: 1`.
- `head 50` capped at 5 returns `truncated: true`, `total_rows: 50`.

**Known limits:**
- `_result_kind` reads only `stats|tstats|chart|timechart|top|rare`; anything else is `events`.
- Dedupe keys the whole row, so two identical events with the same `_time` and `_raw` count once.
- Neither `_absence_count`'s wildcard match nor the absence template fields changed (B54 limit).

## Next
1. Get PR #15 through CI and review; fix anything CI finds.
2. **Step D:** the Broker review card (`review_step`). Keep `FinishCheck` the single resume owner.
3. Owner items, carried over: the Asana B52–B56 subtasks (`1219394496434075`), and a live model check of B56 if Mohammed wants one (it costs money).
