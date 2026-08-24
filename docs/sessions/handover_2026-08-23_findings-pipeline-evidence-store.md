---
date: 2026-08-23
title: Asana epic hierarchy clarified; Findings Pipeline / Evidence Store scoped, discriminator gap fixed
---

# Handover — 2026-08-23, later session: Findings Pipeline / Evidence Store

Branch `task-broker-agent`, still HEAD `e131e74` (unchanged since the earlier
handover today, `handover_2026-08-23_hypothesis-blind-tier1.md` — read that
one first for the Tier-1 hypothesis-blind work and its still-open code-review
tail; this document picks up from there). **Nothing in this session has been
committed.** `git status --short` shows the same pre-existing uncommitted
files that handover already flagged (`bench.py`, and the code-review-in-flight
edits to `broker.py`, `guards.py`, `subagent_analysts/{formatting,model,parse}.py`,
`subagents/__init__.py`, plus their tests) **plus** this session's new changes to
`contracts/src/contracts/findings.py`, `contracts/src/contracts/subtask.py`,
`contracts/tests/test_subtask.py`, `backend/src/smartops/broker.py`, and
`backend/tests/test_broker.py`. `uv run pytest` from root: **619 passed, 0
failed** (up from 605 in the earlier handover — includes both this session's
and the in-flight code-review session's new tests).

**Note for whoever commits this:** `broker.py` now carries two unrelated sets
of uncommitted edits layered on each other (the code-review fixes-in-progress
from the earlier session, and this session's `load_run_artifacts()` addition).
A plain `git add broker.py` bundles both into one commit; splitting them needs
a manual diff review first if that matters to you.

---

## THE HEADLINE: three "unnamed" Asana cards turned out to belong to two different, real epics — one not yet built at all

The user asked what was left on the Smartops Asana board and specifically
about **Findings Pipeline**, **Evidence Store**, and (initially) an
**Aggregator** concept that turned out not to exist as a card. Walking the
actual Asana parent/child hierarchy (not just the flat task list) resolved
this precisely:

```
Analyst Agent (epic, gid 1217013047525800 — NOT YET BUILT)
  "Forms hypotheses, decides what to investigate and in what order, reads
  findings, and writes the conclusion." Four responsibilities: mode selection
  (budget/allow-list/stopping criteria), hypothesis generation (competing
  benign/malicious explanations), task emission (describes what it needs
  without naming tools), assessment (replan-or-stop on deterministic policy).
  Its own "Agent Development" subtask (gid 1217013047604793) states literally:
  "In → condensed results, contract. Out → Task description."
      │
      ▼  Out → Task description (an AnalystTask: question/entity/time window)
Task Broker Agent (epic, gid 1217013047604807 — BUILT, this repo's `broker.py`)
  "In → Task from the analyst. Out → Task plus associated results
  ...dispatch the subtask and the results to the corresponding subagent to
  analyze the results against the subtask."
      │
      │   ⟵ FINDINGS PIPELINE + EVIDENCE STORE (this session's scope)
      │     route the Broker's raw+projected results to what each domain
      │     analyst needs; persist raw evidence so re-answering "what did it
      │     see" doesn't mean re-running the Broker.
      ▼
SubAgents (epic, gid 1217013047604819): identity / network / endpoint
  "It receives a subtask, and condenses its own findings before returning.
  Nothing summarizes on its behalf." Out → (condensed finding, full result).
      │
      │   ⟵ "Summary condensed finding contract/template/criteria"
      │     (gid 1217013047604821, sibling under SubAgents — NOT this
      │     session's scope) — defines the shape of that condensed finding.
      ▼
Analyst Agent (closes the loop — its own Agent Development subtask's
  "In → condensed results, contract" is this exact hand-off)
```

**What this resolves:** the Aggregator-shaped work (judge 3 domain verdicts
against the hypothesis, decide replan-or-stop, write the conclusion) is not
missing from Asana — it lives entirely inside the **Analyst Agent** epic,
which is a real, separate, currently-unbuilt epic, not a SubAgents subtask.
`architecture.md` §11's *"a richer downstream Aggregator is future work"* and
`DomainFinding`'s docstring (*"a later Aggregator cycle turns a list of these
plus a hypothesis into an AnalystVerdict per domain"*) both describe work that
belongs under Analyst Agent, not under today's SubAgents/Findings-Pipeline
scope. **Also worth registering as a live tension, not resolved this
session:** `contracts/subtask.py`'s docstrings on `Evidence`/`SubtaskResult`
still say *"the aggregator... writes them into the case file's evidence
store"* and `SubtaskResult` is *"consumed only by the aggregator"* — leftover
language from the original architecture sketch that contradicts the SubAgents
epic's current note (*"nothing summarizes on its behalf"*, edited today,
2026-08-23). Nobody has gone back to correct those docstrings yet.

---

## What landed this session

Scoped down from "Findings Pipeline + Evidence Store" to a much smaller real
gap, via `/superpowers:brainstorming` (classified bounded, not architectural,
once the actual gap size was clear — approved by the user before
implementation):

| Claimed need | Actual state found | What shipped |
|---|---|---|
| Findings Pipeline (Broker → domain analysts) | Already fully built: `route()` / `formatting.py` / `packing.py` (architecture.md §5) | No code change needed |
| Evidence Store, write side | Already fully built: `broker.save_run_artifacts()` writes `report.json` + `evidence.json` per run, collision-safe, timestamped | No code change needed |
| Evidence Store, read side | **Did not exist at all** — no `load_run_artifacts()`, and it would have silently lost every typed `findings`/`assessment` field if built naively | New `broker.load_run_artifacts(run_dir) -> BrokerReport` |
| Reload fidelity | `SubtaskResult.findings`/`.assessment` used `SerializeAsAny[Findings/Assessment]` — correct for *dumping* a subclass, but a bare `Findings`/`Assessment` annotation has no discriminator for *reading one back*, so `model_validate_json()` silently reconstructed the empty base class | Added a `tool_family: Literal[...]` discriminator to `SiemFindings`/`VtFindings`/`SiemAssessment`/`VtAssessment`; `SubtaskResult.findings`/`.assessment` are now proper discriminated unions (`Annotated[SiemFindings \| VtFindings, Field(discriminator="tool_family")]`) instead of `SerializeAsAny` |

Named `tool_family` (not `kind`) deliberately: `VtVerdict` already has a
`kind` field meaning something unrelated (ip/domain/url/hash), and
`tool_family` reuses the vocabulary already established on `Evidence.tool_family`.

**Tests added** (TDD — each written and confirmed failing before its fix):
- `contracts/tests/test_subtask.py::TestSubtaskResult::test_findings_subclass_survives_a_json_round_trip`
- `contracts/tests/test_subtask.py::TestSubtaskResult::test_assessment_subclass_survives_a_json_round_trip`
- `backend/tests/test_broker.py::TestFetchPlanAndReport::test_load_run_artifacts_round_trips_typed_findings`
  (also confirms `route()` works unchanged against a reloaded report — the
  Findings Pipeline needed zero code change once loading worked)

**Deliberately out of scope, discriminated union tradeoff worth knowing:**
adding `edr`/`ndr` findings later means adding them to the
`SiemFindings | VtFindings` union explicitly — an unlisted subclass now fails
loudly at construction (a `ValidationError`), not silently on reload. This is
a closed-union tradeoff versus the old `SerializeAsAny[Findings]`'s
open-ended-but-broken-on-reload behavior. Both `edr`/`ndr` are withheld today
regardless (no MCP server configured), so this has no live effect yet.

**Also checked and confirmed non-duplicative:** `smartops/replay.py` already
reloads `evidence.json` (only, not `report.json`), but for a different job —
replaying individual recorded tool calls into a *live, offline re-run* of a
subagent (for bench/eval/prompt-tuning), never a finished `BrokerReport`
directly. `load_run_artifacts()` is a new, complementary capability (skip
re-running anything at all), not a rebuild of what `replay.py` does.

---

## Loose ends worth knowing about

- **This session's diff is entirely uncommitted**, layered into an already-
  dirty `broker.py`/tests from the prior code-review session. See the note at
  the top of this document before committing either.
- **The `contracts/subtask.py` docstring contradiction** (aggregator-writes-
  evidence-store vs. subagent-condenses-itself) is flagged above but not
  fixed. Small doc-only correction, whenever someone next touches that file.
- **"Summary condensed finding contract/template/criteria"** (Asana, sibling
  under SubAgents) was explicitly *not* scoped into this session — it defines
  the shape of a domain analyst's condensed finding, which is a prerequisite
  for the Analyst Agent epic's "In → condensed results, contract" but not for
  anything done here.
- **The Analyst Agent epic itself does not exist in code at all yet** — no
  `analyst_agent.py`, no hypothesis-generation, no replan/stop policy. Per its
  own Asana notes it is a fourth agent in this system (Analyst Agent, Task
  Broker Agent, SubAgents' three domain analysts, and — separately — the
  siem/vt fetch subagents), not something `main.py`'s current direct
  `Broker → analyze()` orchestration provides today.
- **An earlier brainstorm this session** ("should the domain analysts be
  spawned as Broker tool calls, agentic-style?") was put on hold by the user
  before a design was reached. Worth revisiting once the Analyst Agent epic
  is real, since that epic — not the Broker — is the one the Asana notes
  describe as actually reading findings and deciding what to do next; making
  domain analysis a *Broker* tool call would hand hypothesis-aware context to
  the Broker, which is a different (and not obviously wanted) architectural
  move than making it an *Analyst Agent* tool call.

## Ranked queue for the next session

1. **Commit this session's work** (`contracts/findings.py`, `contracts/subtask.py`,
   their tests, `broker.py`'s `load_run_artifacts()`, `test_broker.py`) —
   split from the code-review-fixes diff first if you want them as separate
   commits.
2. Everything already ranked in `handover_2026-08-23_hypothesis-blind-tier1.md`
   is still outstanding and unchanged by this session: finish the in-flight
   code review, fix `_format_auth_event`'s dropped `EventCode`/`Logon_Type`,
   fix `_CONFIDENCE_RE`, the `AWS_BEARER_TOKEN_BEDROCK` env leak, the budget
   over-refund bug.
3. **"Summary condensed finding contract/template/criteria"** — the next
   natural Asana card, since it's the one prerequisite the Analyst Agent epic
   names directly ("In → condensed results, contract").
4. **Analyst Agent epic** — genuinely new work, not yet started in code at
   all: mode selection, hypothesis generation, task emission, and the
   replan-or-stop assessment loop that reads all 3 domain analysts' condensed
   findings. This is where the "Aggregator" work everyone kept looking for
   actually belongs.
5. Correct the stale "aggregator writes the evidence store" language in
   `contracts/subtask.py`'s docstrings once someone is back in that file.

## Process lessons worth keeping

- **Asana's parent/child hierarchy carried real information the flat task
  list did not.** "Findings Pipeline" and "Evidence Store" looked like
  Aggregator-adjacent work until fetching their actual parents (`Data
  Connector` → `SubAgents`) and siblings (`Summary condensed finding...`,
  `Agent Development`) — plus the epic-level notes fields, which nobody had
  been reading — showed they were something else entirely, and that the
  thing being described as "the Aggregator" was a fourth, unbuilt epic.
- **A scope that starts architectural can shrink to bounded mid-brainstorm,
  and that's worth naming out loud rather than plowing through a spec for a
  one-file fix.** The user was asked and explicitly chose to downgrade the
  process once investigation showed the real gap was a discriminator field
  plus one loader function, not a persistence subsystem.
- **Checking for an existing, non-obvious module before designing a "new"
  one paid off twice today**: `save_run_artifacts()` already existed (cut the
  Evidence Store scope by half), and `replay.py` already existed (confirmed
  the new `load_run_artifacts()` wasn't duplicating a reload path that was
  already there for a different purpose).
