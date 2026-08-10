---
date: 2026-08-09
title: Subtasks Planner — scope, Task Broker boundary, structured_output correction
---

## Context

Continuing from the 08-06 session (Tool Execution Method). Working through the
next Aug-13 task, **Subtasks Planner** — "breaks the received tasks into
subtasks classified by the capability of each subagent." Most of this session
was resolving what that sentence actually means before writing any code.

## Decisions

- **Task Broker Agent (Mariam's card) vs. Subtasks Planner boundary,
  resolved**: reading Task Broker Agent's and Analyst Agent's actual card
  notes surfaced an apparent conflict with the already-built `SubagentMission`
  contract (subagent self-executes its own tool calls) — Task Broker's notes
  read as "execute the tools ... gather the raw events ... dispatch the
  results to the subagent to analyze," which sounded like *it* calls tools
  and subagents only analyze pre-fetched data. Confirmed with the user: that's
  not the intent. The actual division of labor:
  1. Analyst Agent → `AnalystTask` (tool-agnostic: goal + scope only).
  2. **Subtasks Planner** (this task) → classifies the task into
     `SubagentMission`s, one per relevant `ToolFamily`. Owns *only* this
     decision.
  3. **Task Broker Agent** → for each mission's `ToolFamily`, resolves
     "available tools to use" by querying the MCP gateway live. This is the
     dynamic equivalent of what `tools/registry.py`'s static `FAMILY_REGISTRY`
     does today.
  4. **Subagent** → builds its own `Agent(tools=<resolved tools>)` and
     self-executes, per the existing `SubagentMission` contract and the
     08-06 Tool Execution Method decision. Unchanged.
- **`AnalystTask` added as a new contract** (`contracts/analyst_task.py`) —
  the Analyst's "Task description" (question/goal + entity + time window,
  explicitly no product/index/field names) didn't have a type yet. Modeled as
  `task_id` + `hypothesis_id` + `goal` + `scope: Scope` — reuses `Scope`
  rather than inventing new entity/time-window fields.
- **Classification is LLM-driven, not rule-based** — decided explicitly, not
  defaulted to. A rule table would need typed entities (e.g. `file_hash`,
  `host`, `ip`) to key off, and that depends on Yousef's **Context Contract
  Template**, which doesn't exist yet and has no committed date. Rather than
  block this task on someone else's undelivered schema, `TaskClassification`
  (forced structured output: `tool_families: list[ToolFamily]`, `rationale:
  str`) is classified from the task's `goal` text directly. Revisit if/when
  typed entities land — a rule table would be cheaper and worth swapping in
  then.
- **Empty `tool_families` is a valid classification result**, not an error —
  the task may be unworkable for every domain the system currently knows
  about. Distinct from `SubtaskStatus.rejected`, which is a subagent's verdict
  on a mission it actually received; the Planner just emits zero missions.
- **Correction to the 08-06 session doc**: it said `structured_output()` "has
  its own automatic retry-on-validation-failure loop, independent of
  model-call retries." Checked against the actually-installed
  `strands-agents==1.50.2` source (not just docs, which didn't have this
  detail):
  - `Agent.structured_output()` / `structured_output_async()` are
    **deprecated** as of this version — both raise a `DeprecationWarning`
    pointing at the `structured_output_model` parameter on `Agent.__call__()`
    / the `Agent` constructor instead. `planner.py` uses the current API.
  - Structured output is implemented as a **forced tool call**
    (`StructuredOutputTool`, `tool_choice={"any": {}}`). A validation failure
    doesn't trigger a distinct retry subsystem — it comes back as an ordinary
    tool `status: "error"` result, and **the model's own loop decides whether
    to retry**, same as recovering from any other tool error. No fixed retry
    cap specific to structured output.
  - Token usage lives on `AgentResult.metrics.accumulated_usage`, a dict with
    **camelCase Bedrock/Converse-style keys** (`inputTokens`, `outputTokens`,
    `cacheReadInputTokens`, `cacheWriteInputTokens`) — not the snake_case
    `Usage` shape `Budget` already uses. `accumulated_usage` is cumulative
    over the `Agent` instance's *entire lifetime*, not just the last call, so
    reusing one long-lived planner `Agent` across rounds would leak prior
    calls' usage into every later `Budget.settle()`.

## What we built

- `contracts/src/contracts/analyst_task.py` — `AnalystTask`, `TaskClassification`.
- `contracts/tests/test_analyst_task.py` — valid/invalid construction, empty
  `tool_families` accepted, no-tool-specific-fields regression guard (same
  pattern as the existing `SubagentMission` guard).
- `backend/src/smartops/planner.py` — `plan_missions()`:
  - Reserves budget under `role="planner"` before calling the model; returns
    `[]` immediately (no model call) if the reservation fails.
  - `default_classifier(model)` constructs a **fresh `Agent` per call** —
    the fix for the accumulated-usage lifetime issue above.
  - `_usage_from_accumulated()` is the one place that translates Strands'
    camelCase usage dict into `Budget.Usage`.
  - `classify` is injectable (`Classifier` protocol) so tests never touch the
    real Strands SDK or make a model call.
  - Derives each mission's `task_id` as `f"{task.task_id}:{family}"`, so
    `Budget.spend_by_task()` and `run_round()`'s per-mission `asyncio.gather`
    fan-out both get a unique key per subagent dispatch even though every
    mission traces back to one Analyst task.
- `backend/tests/test_planner.py` — 8 tests: multi-family fan-out, derived
  task_id uniqueness, empty-classification → no missions, budget-exhausted →
  no missions and classifier never called, usage translation + ledger
  correctness, missing `structured_output` raises.
- All 47 tests pass (24 contracts + 23 backend) when run scoped to each
  project's own `pyproject.toml` (`cd backend && uv run pytest tests`, not
  from the workspace root — see gotcha below).

## Gotcha, not caused by this session's changes

Running `pytest` from the workspace root does **not** pick up `backend/
pyproject.toml`'s `[tool.pytest.ini_options]` (`asyncio_mode = "auto"`), so
every `async def` test fails with "async def functions are not natively
supported" when invoked that way — pytest resolves its config/rootdir from
the top-level `pyproject.toml`, which has none. Pre-existing, not introduced
here; just confirmed by running the full suite both ways. Always invoke
scoped to the project directory (`cd backend && uv run pytest tests`, `cd
contracts && uv run pytest tests`) until/unless the workspace root gets its
own `[tool.pytest.ini_options]`.

## Open items / next up

1. **Entity typing** (Context Contract Template, Yousef's) still undefined —
   revisit rule-based classification if/when it lands.
2. **Not yet cross-checked with Mariam directly** — the Task Broker
   boundary above was resolved with the user, not with her; worth confirming
   before her Task Broker Agent build assumes the same split.
3. **No live LLM smoke test run** — confidence here comes from reading the
   installed `strands-agents==1.50.2` source directly (ground truth), not
   from an actual paid model call. Worth one real end-to-end run once an
   `AnalystTask` actually flows from a real Analyst Agent, to confirm
   `accumulated_usage` key names and classification quality empirically.
4. Standing threads, unchanged: `aggregator.py` + `CaseFile` schema still
   undefined; MCP connection-lifecycle/pooling still unresolved; Agent
   Development (the task after this one) needs all of Tool Execution Method,
   Agent Architecture & Config, and Subtasks Planner settled first.

## Later, same day: Task Broker boundary confirmed against a real diagram

The user shared their actual architecture diagram (Seed Normalizer → Context
Builder → Analyst Agent → Tool Broker → subagents → Aggregator, EDR/NDR/VT
behind a **Tools Gateway** reached via MCP). It confirms, rather than just
asserts, the boundary this session had already landed on: Tool Broker sits
between Analyst Agent and the subagents purely as a task-dispatch layer;
**Tools Gateway** is the concrete name for what Mariam's Task Broker Agent
card calls "the MCP gateway," and it's drawn as an external component, not
part of Tool Broker itself.

One wiring detail stayed genuinely ambiguous from the diagram alone: whether
the line into MCP/Tools Gateway comes off the subagent nodes (self-execution,
matching what's built) or off Tool Broker (Broker pre-executing). Not
resolved here — added to `docs/open-questions-for-team.md` as a question for
the actual conversation with Mariam, since it's her card either way.

Also flagged, unrelated to the two tracked questions: the user's own diagram
marks "API Gateway/FE/Integration bus" with a red question mark — a
pre-existing open point on their side, noted but out of scope here.

## Code review — one dispatched agent, not the workflow, then 10 fixes

User explicitly asked for a single `Agent` dispatch (`coderabbit:code-reviewer`
subagent type) instead of the `/code-review` workflow, to control token
spend — the CodeRabbit CLI itself wasn't installed, and this isn't a git
repo yet, so there was no diff to hand it anyway. The agent reviewed
`planner.py`, `registry.py`, `budget.py`, `subtask.py`, `telemetry.py`, and
their tests directly, and verified its most severe findings against the
actually-installed `strands-agents==1.50.2` source rather than guessing.

**10 findings, all fixed same session, all covered by new tests — 60/60
passing (24 contracts + 33 backend, was 47 before this round):**

1. `registry.py::tools_for()` used an `MCPClient` via `list_tools_sync()`
   without ever calling `.start()` — guaranteed crash the moment any family's
   MCP factory returns a real client. **Fixed**: new `_started_clients`
   cache + `_clients_for()` starts and caches one client per family.
2. `planner.py` reserved budget against `max_output_tokens` but nothing on
   the real call enforced it. **Fixed**: `default_classifier()` now passes
   `Limits(output_tokens=...)` — a soft cap per Strands' own semantics, noted
   as such rather than oversold.
3. A raised exception during classification leaked the budget reservation
   permanently. **Fixed**: new `Budget.release()`, wrapped in try/except in
   `plan_missions()`.
4. The classify call blocked the whole event loop for its duration (Strands'
   `Agent.__call__` blocks its calling thread via `run_async()`). **Fixed**:
   wrapped in `asyncio.to_thread(...)`.
5. MCP connections were opened per call, never closed. **Fixed**: same
   `_started_clients` cache as #1 bounds this to one per family, not one per
   mission.
6. Duplicate `tool_families` from the classifier collided on the same
   derived `task_id`. **Fixed**: `dict.fromkeys(...)` dedupes before minting
   missions.
7. `SubtaskResult` had no uniqueness check on `Evidence.id`. **Fixed**: new
   `_evidence_ids_are_unique` validator.
8. `Scope.entities` validated list length, not that each string was
   non-empty. **Fixed**: new `_entities_are_non_empty` field validator.
9. `Budget.estimate_cost()` had no guard against negative token counts
   (would inflate `remaining` instead of consuming it). **Fixed**: explicit
   `ValueError` guard.
10. `telemetry.py::configure_telemetry()`'s idempotency flag wasn't
    thread-safe despite its own docstring's claim. **Fixed**: guarded with a
    `threading.Lock`.

New file: `backend/tests/test_registry.py` (previously zero coverage on that
module). `test_planner.py` and `test_budget.py` extended; `test_subtask.py`
extended.

## Shareable walkthrough artifact — two revisions

First revision read closer to a documentation page (status pills, `<details>`
accordions, one big flow SVG) — user flagged it as noticeably lower quality
than the EDR-mission walkthrough artifact from the 08-05 session. Tracked
down why by pulling the *actual* EDR artifact's HTML (`Artifact` tool's
`action: "list"` + a direct fetch of the real hosted URL — the local file the
user first pointed at turned out to be a browser "Save As" of the claude.ai
viewer chrome, not the artifact itself). The real gap: a concrete worked
example with real field values, genuine click-to-open side panels, a
hand-drawn sequence diagram, one consistent token system — not polish.

Rebuilt to match directly: same tokens (amber accent, same panel/line/text
colors) and same components (stage-flow cards + small SVG arrows + side-panel
drawer + notes grid), reused from the EDR doc, applied to a concrete worked
Subtasks Planner example — one `AnalystTask` about auth activity classified
to `siem`, resolved via `tools_for()`, including the honest detail (checked
against the real `splunk.py` stub) that `tools_for("siem")` still raises
`NotImplementedError` on the actual connection attempt.

Second revision, once the code-review fixes landed: made it dual-audience
per the user's ask ("an engineer or a normal person") —
- a plain-language paragraph up front, before the technical lede
- a one-line plain-English gloss on every stage card, above the existing
  technical fields
- every side panel reordered plain-language-first, technical detail after
- content updated to describe the post-review state, not the pre-fix one
  (registry panel: client-caching fix; planner panel: the three hardening
  facts; notes grid: two more entries for dedup + validation)

Delivered two ways: republished to the same claude.ai artifact URL
(`https://claude.ai/code/artifact/70b540a1-05ce-4db6-801f-5970a73367ec`), and
a fully self-contained standalone copy — complete `<!doctype html>` document,
not an Artifact-tool fragment — saved to
`C:\Users\pcc\Downloads\SmartOps Subtasks Planner Walkthrough.html`, so it
opens correctly by itself with no claude.ai dependency at all.

## Asana

A 2–3 sentence status update was drafted for the Subtasks Planner card
(covering the build + the 10 fixes) — left as text for the user to paste, or
post via `asana_update_task` if asked.

## Flagged for Agent Development: empty classification needs to be visible, not silent

User pushback, correctly: `TaskClassification.tool_families` being empty is
not a *validation* error (Pydantic accepts it, `plan_missions()` won't
raise) — but the original docstring oversold that as "a valid outcome,"
conflating "not a type error" with "nothing to worry about." In practice, an
empty result from a real task almost certainly means the classifier failed
to match a domain, not that the task is genuinely irrelevant to every known
specialist — and right now `plan_missions()` returns `[]` with zero
visibility: no log, no telemetry span, no way to tell "correctly nothing to
do" apart from "the classifier missed." For a SOC tool, a task quietly
evaporating with zero missions and no trace is a real blind spot.

Docstring corrected to say this precisely (no longer "not an error" full
stop). **Not fixed yet, deliberately** — there's nothing to test this
against until real tasks flow through, so the actual fix (most likely:
log/telemetry-tag an empty classification, and/or route it to the Analyst's
"Assessment: replan or stop" step once that exists) is explicitly deferred
to when Agent Development starts wiring real tool execution, not done now
against synthetic test cases.

## Correction: this whole workstream is Task Broker Agent, not adjacent to it

Assumed throughout this doc (and the two 08-06/08-09 conversations) that
Task Broker Agent was Mariam's separate build, with our three tasks merely
feeding into it or resembling part of it. **Checked directly against
Asana's actual parent/assignee data, and that was wrong.**

The real structure: Mariam is the *top-level* assignee on three umbrella
agent cards — Task Broker Agent, Analyst Agent, SubAgents — but the
Architecture & Config and Agent Development subtasks under **all three**
are assigned to Mohammed. She's accountable for each outcome; he's the one
architecting and building all of it. Concretely for Task Broker Agent:

```
Task Broker Agent        (Mariam — top-level, due 2026-08-13)
 ├─ Agent Architecture & Config   (Mohammed)
 │   ├─ Subtasks template/contract   ✅ built, tested
 │   ├─ Tool Execution Method        ✅ built, tested
 │   └─ Subtasks Planner              ✅ built, tested
 └─ Agent Development             (Mohammed) — ⬜ not started
```

So Subtasks template/contract, Tool Execution Method, and Subtasks Planner
*are* the architecture of Task Broker Agent, not a separate thing that feeds
it from outside. "It does not plan" on the Broker's card now reads as
disclaiming the Analyst's kind of investigative/strategic planning, not
domain classification — the card's own "works out which tools can serve it,
and creates subtasks for each subagent" is describing almost exactly what
Subtasks Planner + Tool Execution Method already do.

**Also corrects a repeated mistake this session:** the "Agent Development"
task due 2026-08-13 was described several times as "build a domain subagent
(edr_agent.py etc.)." Wrong — that's a *different* Agent Development task,
due 2026-08-27, under the separate SubAgents card. The one due this week, as
a direct subtask of Task Broker Agent, means: **wire Subtasks Planner and
Tool Execution Method together into one actual running Task Broker Agent.**
That's the next task, and it's a continuation of what's already built, not a
new domain.

Same pattern repeats under Analyst Agent (Aug 27: Mohammed builds its
Architecture & Config *and* its Agent Development — the code that emits
`AnalystTask`, the thing Subtasks Planner consumes) and SubAgents (Aug 27:
Endpoint/Network/Identity Analyst Agent + Data Connector, all Mohammed's).
`docs/open-questions-for-team.md` updated to reflect the corrected framing
for the Mariam conversation.
