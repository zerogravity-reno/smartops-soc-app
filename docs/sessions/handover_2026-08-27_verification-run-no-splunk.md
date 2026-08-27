---
date: 2026-08-27
title: The reviewed changes verified against the saved runs, with a live model and no Splunk
---

# Handover — 2026-08-27: verified on saved data with a live model, no Splunk

Continues `handover_2026-08-26_confluence-page-written.md`, whose whole diff was
uncommitted. **It is committed and pushed now** — eight commits, `2c4f27d..fabfc6f` on
`task-broker-agent`, level with `origin/task-broker-agent`.

Two reviewer passes triaged five candidate defects and then hunted design flaws. Most of
the candidates were not defects. Three real flaws were, and one of them was live on the
production path. All of it is in the commits; this file records **the verification**,
because it was run without either backend the system normally needs and that is worth
knowing how to repeat.

## The verdict

Everything that can be exercised without a live Splunk fetch runs clean, including the
analysts.

| Check | Result |
| :--- | :--- |
| `uv run pytest` | **764 passed**, 0 failed (baseline was 744; 20 added) |
| `uv run python docs/check_anchors.py` | 83 anchors verified, 13 unchecked, **0 stale** |
| `smartops-blind-compare --run cli-20260825T100434 --pack-only` | three domains packed from real rows, ~2.1k / 2.2k / 3.6k estimated tokens, none truncated, every header id resolving to a real `Evidence.id` |
| `load_run_artifacts` over every saved run | **26 of 26** |
| `load_evidence_from_run` + `ReplayToolset` per case | **23 of 23**, 788 records indexed, **0** model-authored |
| `--scripted` broker run into a disposable `SMARTOPS_RUNS_DIR` | artifact written to a timestamped path with `latest.txt`, read back, `trace_id` populated |
| `.smartops/runs/` after all of it | **untouched** — 23 cases, 26 reports, nothing modified |

### The live run — and it closes §11's caveat

Bedrock **is** live; it just needed warming. An idle imported model is evicted and reloads
on the next call, surfacing as `ModelNotReadyException` for a minute or two, and
`_invoke_with_warmup` waits it out (8 retries, 30s apart). Reaching it from a plain script
also needs `.env` loaded — the explicit keys are there — and any shell `AWS_PROFILE`
cleared, because its login credential provider is not resolvable here. That was the whole
of my earlier "no credentials" conclusion, and it was wrong.

So the production path ran: `gather()` over the saved evidence of `cli-20260825T100434`,
three real analyst calls, **no hypothesis passed at all**.

| Domain | Disposition | Confidence | Citations | Exhibits |
| :--- | :--- | :--- | :--- | :--- |
| identity | suspicious | 0.7 | 1 | 1 |
| network | **malicious** | 0.95 | 5 | 5 |
| endpoint | suspicious | 0.7 | 4 | 4 |

**The link contract holds end to end**: 10 citations kept, 10 exhibits (one per kept
citation, none stray), **14 distinct `Evidence.id`s of which 14 resolve** against that
run's 72-record `evidence.json`. `task_id` and `run_id` populate. `hypothesis` is `null`.

That is what §11 said would be the first artifact traceable end to end, so gap 3's caveat
is closed — with two things still true: the **committed** artifacts under `.smartops/runs/`
still carry none of it (all 10 predate the fields), and this run deliberately wrote outside
that tree because it is a protected fixture.

### The documentation defect the run found

`DomainJudgement` — the wire contract, and what `findings.json` actually holds — **has no
`citation_evidence` field**. §8's chain diagram drew one hanging off it. The freeze is on
`DomainFinding`, internal, alongside the audit fields; on the wire the link rides on
**`Exhibit.evidence_ids`**, one exhibit per kept citation, and that is strictly better for
the Analyst Agent because the exhibit carries the rows rather than a pointer into a store it
may not hold. Corrected, with both carriers drawn.

Worth noting how it was found: a print statement in the verification script raised
`AttributeError: 'DomainJudgement' object has no attribute 'citation_evidence'`. Reading
§8 would not have found it, and no test asserts the absence.

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

1. **The one thing still unproven this sprint is a live Splunk fetch.** Every run here
   read evidence off disk. The fetch tier was exercised only with the MCP server
   unreachable, where it correctly returned `rejected`. The last real retrieval was
   2026-08-25, so re-running one end to end is the first thing to do when Splunk access
   returns — and the only remaining way to find a fetch-path regression.
2. **A single disposition is one draw, not a measurement.** The same evidence, run twice
   through the same blind path minutes apart, gave identity `suspicious` at 0.85 with five
   citations and then `suspicious` at 0.7 with one. The disposition held; the confidence
   and the citation count did not. Anything quoting a single run's numbers should say so,
   which is the rule this project already applies to the skill-pack comparison.
3. **`docs/check_anchors.py` is committed and worth running after any edit to a cited
   file.** The previous checker lived in a session scratchpad and only verified that the
   anchored line existed. It passed while every `analyze.py` anchor on the page had slid
   onto an unrelated docstring — twice in one session, because six commits added lines
   above them.
4. **`docs/confluence-subagent-analysts.md` is still untracked**, as its own scope
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
