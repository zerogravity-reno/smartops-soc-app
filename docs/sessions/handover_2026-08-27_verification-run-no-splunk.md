---
date: 2026-08-27
title: The reviewed changes verified against the saved runs, with neither Splunk nor a model reachable
---

# Handover — 2026-08-27: verified on saved data, no Splunk, no model

Continues `handover_2026-08-26_confluence-page-written.md`, whose whole diff was
uncommitted. **It is committed and pushed now** — eight commits, `2c4f27d..fabfc6f` on
`task-broker-agent`, level with `origin/task-broker-agent`.

Two reviewer passes triaged five candidate defects and then hunted design flaws. Most of
the candidates were not defects. Three real flaws were, and one of them was live on the
production path. All of it is in the commits; this file records **the verification**,
because it was run without either backend the system normally needs and that is worth
knowing how to repeat.

## The verdict

Everything that can be exercised without Splunk or a model runs clean.

| Check | Result |
| :--- | :--- |
| `uv run pytest` | **764 passed**, 0 failed (baseline was 744; 20 added) |
| `uv run python docs/check_anchors.py` | 83 anchors verified, 13 unchecked, **0 stale** |
| `smartops-blind-compare --run cli-20260825T100434 --pack-only` | three domains packed from real rows, ~2.1k / 2.2k / 3.6k estimated tokens, none truncated, every header id resolving to a real `Evidence.id` |
| `load_run_artifacts` over every saved run | **26 of 26** |
| `load_evidence_from_run` + `ReplayToolset` per case | **23 of 23**, 788 records indexed, **0** model-authored |
| `--scripted` broker run into a disposable `SMARTOPS_RUNS_DIR` | artifact written to a timestamped path with `latest.txt`, read back, `trace_id` populated |
| `.smartops/runs/` after all of it | **untouched** — 23 cases, 26 reports, nothing modified |

**Not exercised: a live analyst model call.** `AWS_PROFILE` is set but its credential
provider needs a dependency that is not installed, so no model was reachable. The
pack-only gate builds the exact prompt an analyst would receive and stops there. The
orchestration and grounding gate behind it are covered by tests, not by a live call. Do
not read the page as saying otherwise; it now says so explicitly (Appendix C).

## What the Splunk-less run showed positively

With the MCP server unreachable the siem step came back **`rejected`**, carrying its
reason, with `completed=false` **and** `confirmed_empty=false`. The distinction between
"we looked and found nothing" and "we never got an answer" held. That is the one
distinction in this system that must never collapse, and a run with no backend at all is
the cheapest place to confirm it still does not.

## Numbers first measured this session

- **875 stored result sets = 846 SIEM result sets + 29 VT verdicts.** The 875 figure was
  already on the page; the split was not, and it makes the number checkable rather than
  quotable. **72** carry an `evidence_id`, all in `cli-20260825T100434`.
- **0 of 545.** Of the 875, 545 carry a query from which `_infer_cim_category` derives a
  category at all, and in none of them does the derived category contradict the bucket the
  rows were filed under. The new warning in `project_siem` is therefore silent on every run
  on disk — which is the point of it: the first time it fires it will be a real event.
- **1 of 26 runs carries a `scope`.** `BrokerReport.scope` postdates `430df12`, so
  replaying anything older means reconstructing the scope. `blind_compare` already does and
  records that it did.
- **788 replayable tool records** across the 23 cases, none model-authored.

## Pick this up here

1. **The one useful next check needs a model.** §11's caveat stands: no analysis artifact
   on disk exercises the link contract, and the first blind run to complete after `e3dcd99`
   will be the first one traceable end to end. That needs working credentials; it is the
   single most valuable thing to run when they exist.
2. **`docs/check_anchors.py` is committed and worth running after any edit to a cited
   file.** The previous checker lived in a session scratchpad and only verified that the
   anchored line existed. It passed while every `analyze.py` anchor on the page had slid
   onto an unrelated docstring — twice in one session, because six commits added lines
   above them.
3. **`docs/confluence-subagent-analysts.md` is still untracked**, as its own scope
   requires. Unchanged by this session.

## Process note

The anchor checker is the lesson, and it is the same one this project keeps relearning in a
new place. A check that cannot fail is worse than no check, because it reports success. The
old one asked "is line 390 inside this file?" when the question was "is line 390 still
`_finalize_finding`?" — and every anchor on the page was wrong while it said they were
fine.

The same shape turned up inside this session's own verification script: it counted
model-authored records reachable for replay by calling a `tool_names()` method
`ReplayToolset` does not have, so the count was 0 for the wrong reason. Caught by asking
what the API actually is rather than trusting a plausible name. **A green check earns
belief only once you have seen it able to go red.**
