---
date: 2026-08-06
title: Asana task audit, Tool Execution Method research (Strands native vs MCP)
---

## Context

Continuing from the previous session (contract + budget work). This session
had two threads: getting oriented in the full Asana board (it's bigger than
it looked), and starting the next Aug-13 task, "Tool Execution Method."

## Asana state

The project ("Smartops SOC App") is a 3-person board, not a solo one:

- **Yousef Salah** — the seed/context ingestion side: Seed Adapter &
  Normalizer, Normalized Seed Template, Context Builder, Context Retrieval
  Adapters, ESCU, Splunk Adapter, OpenCTI, Rule Intent Interpreter, Context
  Contract Template (currently in "Doing").
- **Mariam** — the Analyst/Broker/subagent side: Task Broker Agent, Context
  Service, Analyst Agent, SubAgents. Her Task Broker Agent notes already
  assume an MCP gateway ("queries the MCP gateway for what tools currently
  exist") — relevant to this session's decision, see below.
- **Mohammed (the user)** — 22 cards, everything else: contracts, budget,
  the domain subagents (Network/Endpoint/Identity Analyst Agent), prompt
  engineering (×3, unlabeled), agent development (×3, unlabeled), agent
  architecture & config (×2, unlabeled), planning/hypothesis/findings
  pipeline, evidence store, data connector.

**Two open housekeeping items, not yet resolved:**
- Three "Prompt Engineering" and three "Agent Development" cards (plus two
  "Agent Architecture & Config") have identical names and no distinguishing
  notes. Unclear what separates them — flagged to the user, not resolved.
- **There is no Asana card for the Budget work at all**, despite it being a
  full task in the original spec and now fully built. Flagged; not yet
  created or attached anywhere.

**Aug 13 due-date items for Mohammed** (today is Aug 6, so ~1 week out):
1. Subtasks template/contract — done (see prior session)
2. Subtasks Planner — "breaks received tasks into subtasks classified by
   the capability of each subagent" — not started
3. Tool Execution Method — "either tool definition or MCP server" — **in
   progress this session**
4. Agent Development — "Deliverable: Running code." — not started
5. Agent Architecture & Config — no notes — not started

**Agreed order and why:** Tool Execution Method → Agent Architecture &
Config → Subtasks Planner → Agent Development. The first two are decisions
that shape how subagent code gets written, so they go before any code that
would need redoing if the answer changed. Subtasks Planner only depends on
the already-built `SubagentMission` contract, not on how tools execute, so
it's safe to build before the tool-execution question is fully settled if
we want to parallelize. Agent Development goes last because it needs all
three of the above.

## Tool Execution Method — research findings

Dispatched a Haiku research agent against the Strands Agents SDK docs to
answer: native tool definitions vs. MCP servers, for our subagent design
(each subagent derives and executes its own tool call, retries capped at
2, forces a final answer through structured output; Budget gates spend
across everything).

**The framing on the Asana card ("either...or") is a false binary** — a
single Strands `Agent` can mix native `@tool` functions and MCP-server
tools in the same `tools=[]` list. Key findings:

- **Native tools**: `@tool` decorator, auto-generates JSON schema from type
  hints + docstring. Errors don't crash the loop — they flow back into
  conversation history for the model to react to. No built-in retry.
- **MCP tools**: `MCPClient` implements the same `ToolProvider` interface
  native tools use, so it drops into `Agent(tools=[...])` directly.
  Supports stdio (local) and Streamable HTTP (remote) transports; multiple
  MCP clients can be attached to one agent.
- **Structured output** (`agent.structured_output(SubagentAnswer)`) works
  fine after tool use mid-conversation, and has its own automatic
  retry-on-validation-failure loop, independent of model-call retries.
  Directly validates the `SubagentAnswer`/`SubtaskResult` split from the
  contract task.
- **No built-in tool-call retry** — matches (doesn't fight) our own
  "repair and retry, capped at 2" design; that logic is squarely ours to
  write regardless of native-vs-MCP.
- **"Agents-as-Tools" pattern** matches our Analyst → Subagent shape:
  pass a specialist `Agent` as a tool to a supervisor `Agent`; context
  resets per call by default (good — subagents shouldn't inherit the
  Analyst's history) unless `preserve_context=True`.
- **AWS AgentCore Gateway** is a separate, optional managed MCP-aggregator
  service, not a Strands requirement — standalone `MCPClient` works
  without it. Whether it works with non-Runtime-deployed Strands agents is
  undocumented. Not worth deciding now; revisit only if/when we deploy on
  AgentCore Runtime.

**Two flagged ambiguities in Strands' own docs** (not blockers, just
things to verify empirically once we build against them):
- Whether `structured_output()`'s automatic retry shares a budget with
  model-call retries, or is independent.
- MCPClient retry/backoff configuration on connection failure (open
  upstream issue referenced in the research).

**Shape that falls out of this** (proposed, not yet confirmed by the
user): native `@tool` functions for our own control-plane logic (Budget
`reserve()`/`settle()` calls, bookkeeping), MCP for the actual external
EDR/NDR/VT/SIEM integrations. This also lines up with Mariam's Task Broker
Agent card, which already assumes an MCP gateway on the tool-discovery
side — worth confirming with her rather than deciding in isolation.

## Tool folder structure (confirmed, scaffolded)

User confirmed the native-vs-MCP split. Reuses `SubagentMission.tool_family`
(already in the contract) as the entire "which tools can this subagent use"
signal, rather than inventing a second taxonomy — the Planner sets
`tool_family`, the subagent's `Agent(tools=tools_for(mission.tool_family))`
resolves it.

- `backend/src/smartops/tools/registry.py` — `FAMILY_REGISTRY: dict[ToolFamily,
  ToolFamilyConfig]` + `tools_for(family)`. Deliberately does **not** add a
  second, finer-grained "which tool within the family" selection layer —
  that's the model's own ReAct loop, driven by `mission.goal`. Add a
  per-tool policy (Cedar, on the MCP side) later only if a family's full
  toolset proves too permissive for some mission.
- `backend/src/smartops/tools/native/` — real `@tool`-decorated,
  model-callable functions only. **Correction to this session's earlier
  proposal**: `Budget.reserve()`/`settle()` are not native tools by this
  definition — they wrap the whole LLM/tool-call round from orchestration
  code, before and after; the model never calls them directly.
- `backend/src/smartops/tools/mcp/` — client-side config per external
  server we connect to but don't host: `splunk.py` (siem — official Splunk
  MCP Server, GA on Splunkbase), `crowdstrike.py` (edr — community Falcon
  MCP), `virustotal.py` (vt — community MCP server). All three stubbed with
  `NotImplementedError` pending real auth/transport details. `ndr` has no
  server picked yet.
- **Confirmed placement for any custom MCP server we end up building**
  (i.e. an integration with no existing vendor/community server): a new
  top-level `mcp_servers/<name>/` uv workspace package, sibling to
  `backend/`/`contracts`/`frontend`, not nested inside `backend/`. Same
  reasoning as why `contracts/` was carved out on 08-05 — it's a
  separately-deployable process (own run/lifecycle, possibly own deps), not
  just a different concern. Not created yet — no custom server needed so
  far.
- Added `strands-agents` and `strands-agents-tools` to
  `backend/pyproject.toml` — first time either is an actual dependency
  (not yet installed into `.venv`; needs `uv sync` before any of this runs).

**Open, unresolved:** MCP client connection lifecycle. `run_round()`'s
concurrent `asyncio.gather` fan-out means many missions in flight at once;
`tools_for()` as written opens a fresh client connection per call, which is
wrong for stdio/HTTP sessions that are expensive to open repeatedly.
Needs a pooling/reuse strategy (e.g. clients opened once per investigation
and cached) before `edr_agent.py` etc. actually get written against this.

## Open items for the next session

1. Resolve the MCP connection-lifecycle question above.
2. Pin actual auth/transport details for the three stubbed MCP clients
   (Splunk, Falcon, VirusTotal) and pick an NDR vendor/server.
3. Then: Agent Architecture & Config → Subtasks Planner → Agent
   Development, in that order, per the reasoning above.
4. Resolve the two Asana housekeeping items (duplicate-named cards; no
   Budget card) whenever convenient — not blocking.
5. Longer-running thread, unchanged from the previous session: still need
   `subagents/edr_agent.py` (+ ndr/vt), `aggregator.py`, and a `CaseFile`
   schema (referenced throughout, never defined).
6. **New thread this session**: observability/traceability/cost-tracking
   best practices, requested mid-session — see research findings below.

## Observability/traceability/cost-tracking — research findings

Dispatched a Haiku research agent (web-grounded, not memory) scoped
explicitly as *complementing* the existing `Budget` ledger, not replacing
it. Findings, not a decision — nothing below is adopted yet.

- **Tracing**: OTel's GenAI semantic conventions (`gen_ai.*` span
  attributes) are now stable. **Strands Agents SDK has this built in** —
  auto-emits spans for agent steps, LLM calls, and tool invocations with no
  manual instrumentation, exportable via OTLP to X-Ray/CloudWatch/
  Jaeger/Datadog/etc.
- **Traceability**: attach `task_id`/`hypothesis_id` as root-span
  attributes; `contextvars` propagate automatically through
  `asyncio.gather()`, so subagent fan-out traces correctly for free. Real
  gap: **MCP has no native trace-context propagation** (open upstream
  issue) — needs a community shim (`opentelemetry-instrumentation-mcp`) or
  manual injection via the JSON-RPC `_meta` field to carry a trace across
  an MCP client→server call.
- **Error handling**: no industry-standard error-code enum exists, but the
  converging pattern is a structured object (`error_code`, `error_type`,
  `severity`, `retry_eligible`) instead of a bare string, so retry logic
  can distinguish "malformed args, retry" from "budget exhausted, stop."
  Our `Budget.reserve()` gate already prevents the worst failure mode
  (silent infinite retry on exhaustion); the open suggestion is just to
  give exhaustion its own explicit code rather than a generic one.
- **Cost tracking**: confirms `reserve()`/`settle()` already *is* the
  standard reconciliation pattern (estimate → gate → actual → reconcile).
  The only addition backends layer on: mirror `cost.estimated`/
  `cost.actual` as span attributes so cost shows up inline in a trace, not
  only in the ledger.
- **Backends surveyed**: Langfuse (open-source, OTel-native, low-effort
  self-host), Arize Phoenix (open-source, OTel-first, low-effort
  self-host), AWS CloudWatch GenAI Observability (managed, ~zero-config if
  already on Strands/Bedrock), Datadog LLM Observability (managed, medium
  effort, pulls real invoices for reconciliation). Helicone flagged as a
  risk, not a pick — acquired by Mintlify, in maintenance mode.
- **Complexity ladder proposed** (tiers, not a recommendation):
  1. Structured JSON logs + existing Budget ledger — no new infra.
  2. OTel spans (Strands emits these for free) → self-hosted Langfuse or
     Phoenix — real trace visualization, no vendor lock-in.
  3. Same OTel → managed backend (Datadog/CloudWatch) — adds invoice
     reconciliation + pre-built eval dashboards, real $ cost.
  4. + LLM-judge evaluators over every trace — only worth it at real
     scale; flagged as carrying real technical debt.

**Not yet decided**: which tier to start on. Given the team's "simple is
best" motto, tier 1 or 2 is the obvious starting range, and tier 2 is
cheaper than it sounds since Strands already emits the spans — adopting it
would mean pointing an OTLP exporter at a self-hosted Langfuse/Phoenix
rather than writing instrumentation by hand. Still needs actual team
discussion before committing.

## Observability — implemented (tier 2, Strands-native)

User decided: use Strands' native OTel instrumentation rather than
hand-rolling spans. Built and verified (not just scaffolded):

- `backend/src/smartops/telemetry.py`:
  - `configure_telemetry()` — one-time `StrandsTelemetry()` setup. Console
    exporter always on (zero-config, works with no external service);
    OTLP exporter added only if `OTEL_EXPORTER_OTLP_ENDPOINT` is set, so
    pointing this at Langfuse/Phoenix/CloudWatch/Datadog later is a config
    change, not a code change. Idempotent.
  - `trace_attributes_for(mission)` — builds the `task_id`/`hypothesis_id`/
    `tool_family` dict for `Agent(trace_attributes=...)`, so every span a
    subagent's `Agent` produces carries our business IDs automatically.
    (Confirmed via docs: `trace_attributes` is construction-time only, no
    per-call override — matches our one-`Agent`-per-mission shape fine.)
  - `record_cost(reservation, actual_micro_usd)` — mirrors a settled
    `Budget` charge onto the current span (`cost.role`,
    `cost.estimated_micro_usd`, `cost.actual_micro_usd`). No-op on a
    non-recording span, so it can never be what breaks a subagent call.
  - `record_result_status(result)` — reflects a `SubtaskResult`'s terminal
    `SubtaskStatus` as OTel span status (`ERROR` + description, or a
    `subtask.status` attribute otherwise).
- `backend/tests/test_telemetry.py` — 3 tests, all passing.
- **Verified against the real install, not just unit-tested**: added
  `strands-agents[otel]`, `opentelemetry-api` to `backend/pyproject.toml`;
  ran `uv sync` and smoke-tested `configure_telemetry()` + `record_cost()`
  + `record_result_status()` against actual OTel spans (console exporter
  output confirmed cost attributes and `ERROR` status land correctly).
- **Dependency-pin correction caught by `uv sync`**: initially guessed
  `strands-agents-tools>=1.0` — wrong, that package has only ever reached
  `0.8.5` (no 1.0 release; separate, slower-moving release cadence from
  the core `strands-agents` SDK, which is at 1.50.2). Fixed to `>=0.8`.
- `uv` itself wasn't on PATH in this environment; bootstrapped via
  `python -m pip install --user uv`, then used `python -m uv ...`.

**Not yet wired up**: nothing calls `record_cost`/`record_result_status`
yet — there's no subagent orchestration code to call them from
(`edr_agent.py` etc. still don't exist, per the standing open item below).
These are ready for whoever writes that code next.
