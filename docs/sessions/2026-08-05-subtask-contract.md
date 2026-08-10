---
date: 2026-08-05
title: Subtask contract, EDR diagram, backend scaffolding
---

## Context

First working session on SmartOps (the multi-agent SecOps triage/IR system).
Starting point was an architecture sketch: Seed Normalizer → Context Builder →
Analyst/Triage agent → domain subagents (EDR/NDR/VT/SIEM) → Tool Broker →
Aggregator → case file, with a separate Critic to be built later. Stack:
Python, Pydantic v2, asyncio, Strands framework for the agent layer.

Working task-by-task rather than building the whole pipeline at once. This
session covered the first task: **the subtask/mission contract** — the format
handed to a subagent and the format it returns.

## Decisions

- **Top-level layout**: `backend/`, `frontend/`, `contracts/`. `contracts/`
  was carved out separately from `backend/` because the mission/result shapes
  are consumed by more than one side (subagents now, the Critic and possibly
  the frontend case-viewer later) — not backend-internal.
- **Packaging**: a `uv` workspace rooted at the project root, Python 3.13
  pinned (`.python-version`). `contracts` and `backend` are each their own
  installable package (`smartops-contracts`, `smartops-backend`), with
  `backend` depending on `contracts` via `[tool.uv.sources]` workspace
  linkage rather than a path hack.
- **Mission contract deviates from the original draft in one structural way**:
  split the subagent's output into two types instead of one.
  - `SubagentAnswer` — the only shape the LLM is forced into via structured
    output (`status`, `summary`, `citation_ids`, `error`). No `task_id`, no
    raw evidence — the model never authors data it didn't actually observe.
  - `SubtaskResult` — assembled by code via `SubtaskResult.from_answer(...)`,
    adds `task_id` and the `evidence` the subagent's own tool-call loop
    collected. This is the only object that ever leaves a subagent.
  - This resolves a contradiction in the original spec (evidence written by
    subagents vs. the case file only ever written sequentially by the
    aggregator) — evidence now just rides along as data on the returned
    object; nothing shared gets touched until the aggregator runs.
- **Validation added beyond the original spec**: `time_window` must be
  timezone-aware with `start < end`; `status == error` iff `error` is set
  (shared by both `SubagentAnswer` and `SubtaskResult`); every `citation_id`
  on a `SubtaskResult` must resolve to an `Evidence` id actually attached to
  it. All three are enforced as Pydantic validators, not conventions.
- **`SubtaskStatus.rejected`** given an explicit meaning: mission was
  unworkable for that domain, no tool call ever attempted or budget-charged —
  distinct from `error` (attempted, failed, retries exhausted).
- The mission/result contract is **data, not a prompt**. `SubagentMission`
  carries no natural-language template. Each subagent module (`edr_agent.py`
  etc., not yet built) owns its own static system prompt and folds the
  mission's `goal` / `scope` / `context` into it at call time. This is what
  lets the Analyst dispatch an arbitrary number of missions per round
  (`run_round()` fans out via `asyncio.gather`) — missions are cheap,
  stateless data objects, gated only by the one shared `Budget`, not by
  anything in the contract itself.

## What we built

- `contracts/` package: `Scope`, `SubagentMission`, `SubtaskStatus`,
  `Evidence`, `SubagentAnswer`, `SubtaskResult` in `src/contracts/subtask.py`.
- `contracts/tests/test_subtask.py` — 15 passing tests covering valid/invalid
  construction, the status/error validator, and the citation→evidence
  validator.
- `backend/` package scaffolded (`src/smartops/`, `src/smartops/subagents/`)
  and wired into the workspace, depending on `smartops-contracts`. No
  implementation code yet — just the home for the next tasks.
- An interactive diagram (published as a Claude artifact) walking one EDR
  mission end to end: the mission-in/result-out shapes with click-to-expand
  explanations per box, plus a Mermaid sequence diagram showing the same
  round over time (budget charged per attempt, the retry, the structured-
  output boundary).

## Open items / next up

Per the original task breakdown, still to build:

1. `budget.py` — shared `Budget` (asyncio.Lock + counter, atomic `charge()`).
2. `subagents/edr_agent.py`, `ndr_agent.py`, `vt_agent.py` — domain-specific,
   each deriving and repairing its own tool calls; stub the real tool/MCP
   wiring for now.
3. `aggregator.py` — `merge_into_case_file()` (pure, sequential) and
   `run_round()` (concurrent dispatch, no case-file write until the whole
   round returns). **`CaseFile` itself still needs a schema** — referenced
   throughout but not yet defined anywhere.
4. Tests for budget (concurrency safety) and the aggregator write-race
   regression (10+ concurrent results → no evidence dropped).

Explicitly still out of scope: the Critic, real MCP tool wiring, model
selection per domain.
