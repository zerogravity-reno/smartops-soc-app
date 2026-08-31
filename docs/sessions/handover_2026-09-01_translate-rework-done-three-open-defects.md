---
date: 2026-09-01
title: The translate rework is complete and measured; three defects remain, none reachable by the gate
---

# Handover — the tier translates, and now we know how well

**Branch `prompt-contract` at `80d5e13`**, 10 commits past the fork at `8969785`
(the MERGE_BASE for whole-branch review), **867 tests passing**, tree clean, 0 stale
doc anchors. The rework the 2026-08-31 handover specified is **done**: tasks A, B,
C and D all landed, and the docs describe what shipped.

What this handover adds is the part no test could give: the tier has now been
**measured against real evidence**, and it has three defects. None of them is
reachable by the grounding gate.

## What landed

| Commit | |
|---|---|
| `95fe13c`, `698f8d9` | task A — the prompts translate, they no longer judge |
| `80fc5e2` | task B/1 — contracts, schema v2 (v1 byte-identical on disk) |
| `105aa6f` | task B/2 — `parse.py`, `analyze.py`; no verdict is produced |
| `180c9ce` | task B/3 — `main.py`, `telemetry.py`, `blind_compare.py`; none read one |
| `a79a2c3` | task C — the answer key scores citation coverage |
| `1a5afa6` | task D — README, architecture, both Confluence pages, PROJECT_DOCS |
| `35b7b56` | prompt fidelity: time ranges, zero-row sets, cross-set attribution |
| `80d5e13` | `events=M` in the header; code sums the count column |

`docs/confluence-subagent-analysts.md` is **tracked now** (Mohammed's call this
session, reversing the standing instruction and closing the R14 open question).

## How it was measured, and how to repeat it

Splunk was down all session. That is not a blocker — a **saved run replays through
the live analysts** with no Splunk and no re-fetch:

```python
report = load_run_artifacts(".smartops/runs/cli-20260823T112627/20260823T112855536")
scope  = Scope.model_validate(json.load(open(
             "docs/blind-vs-shown-cli-20260823T112627-n15.json"))["scope"])
findings = await gather(report, scope, analyst_model_from_env())
```

Two things to know or you will lose an hour:

- **The rich runs are at repo-root `.smartops/runs/`, not `backend/.smartops/runs/`.**
  The `backend/` tree holds VT-only runs with no SIEM rows. `cli-20260823T112627` is
  the five-entity multivector case — identity 80 rows, network 46, endpoint 165 —
  and the only saved run with real evidence in all three domains.
- **`report.scope` is `None` on saved reports.** Take the scope from the
  `blind-vs-shown-*.json` beside it (as above) or from `BENCHMARK_CASES`.
- `load_dotenv(find_dotenv(usecwd=True))` before importing, and run under
  `env -u AWS_PROFILE` — a set `AWS_PROFILE` shadows the explicit keys in `.env`.
- Point `SMARTOPS_RUNS_DIR` at a scratch directory. Never write under `.smartops/runs/`.

## The three open defects

All three share one property that matters more than any of them individually:
**every one cites an id that resolves.** The grounding gate checks that a citation
exists, not that the sentence around it is a fair reading of the rows it names. That
is the gap, and it is structural.

**1 — The narrative grades numbers with words.** The reputation rows read
`ip=217.182.164.14 FOUND mal=1 susp=0 harmless=90`. The analyst wrote "flagged …
as suspicious/malicious". One engine of 91 is not "flagged", and grading a count is
the judgement this tier gave up. It also **regressed**: before the `35b7b56` prompt
edit it wrote the faithful "low malware presence (mal=1)". A rule saying a number is
reported as a number is drafted but unwritten — measure it, do not assume it.

**2 — A fabricated IP digit.** The run verifying the count fix wrote
`217.182.184.14` where the evidence spells `217.182.164.14`. One digit, on an
indicator, in a SOC narrative. It did not occur in the previous run. **This is the
most consequential class left** and the one to fix first: it wants a transcription
check comparing entity-shaped strings (IPs, hashes, hostnames, domains) in the
narrative against the cited rows, and flagging any that appear in neither. That is
code, not a prompt rule — the same reasoning that moved the count sum.

**3 — Host attribution and small counts.** "Host BSTOLL-L made 28 DNS queries"
where the rows read `src=192.168.247.131`; "101 processes" where `processes#11`
holds 100. Lower severity, same root: prose about rows is unchecked.

### What is already fixed, so do not re-fix it

`35b7b56` and `80d5e13` closed three others, verified by re-running the same replay
at temperature 0: **backwards time ranges 4 → 0** (print order is not time order —
most sets print oldest-first, `processes#8` prints newest-first), **content asserted
on `rows=0` sets 2 → 0**, and **cross-set attribution** (one claim merging
`processes#2`–`#6` while citing `#2`). The count defect — 7,656 events reported as
"1,063" and "1,083" in the same finding — is fixed in code, not prompt:
`_event_total()` sums the column and the header carries `events=M`.

## Two things nothing has exercised yet

- **Truncation fidelity.** Every set in every run so far printed in full, so the
  rule "say you are describing a sample of N" has never fired. It needs a slice
  large enough to bite the row cap.
- **A live end-to-end run with Splunk up.** Everything above replays saved evidence.
  The fetch path has not been exercised against this contract.

## Cost of the prompt work, for the next person editing prompts

`_PACK_TOKEN_BUDGET` is **derived**, and every system-prompt token comes straight out
of the evidence budget: 25,426 → 25,150 across this session's two prompt edits.
Margins are identity 601 / network 500 / endpoint 576 against a 500 floor — **network
is pinned at the floor by construction**, because it is the largest prompt and sizes
the reserve every domain's budget derives from. Re-measure rather than quoting a
literal; a stale `25,751` survived in five documents precisely because someone wrote
the number down.

    uv run python -c "from smartops.subagent_analysts.packing import _PACK_TOKEN_BUDGET as b; print(b)"

## State

24 commits ahead of `origin/task-broker-agent`; nothing pushed, nothing merged.
`8969785` is the MERGE_BASE for the whole-branch review. Untracked and deliberately
so: `.claude/`, `scratchpad/`.
