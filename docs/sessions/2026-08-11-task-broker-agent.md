---
date: 2026-08-11
title: Task Broker Agent — Broker-is-an-agent correction, typed entities, first executing integrations
---

## The correction that reshaped this session

The 08-09 entry describes the Broker as resolving tools for missions the
Subtasks Planner has already classified. Mohammed corrected the premise:

> "who said the broker will be deterministic? it's an agent and the subagents
> below it is a multiagent flow."

That was never a design detail to be assumed — it was his call, and an earlier
"direction verdict" asserted the opposite without asking. Worse, the research
backing that verdict had already found that *every* documented Strands
orchestrator is an LLM agent and that no plain-code supervisor pattern exists
anywhere in their docs. That finding was written down as a caveat and worked
around instead of surfacing it as a question.

**Supersedes** the 08-09 entry's Planner/Broker division of labour (points 2 and
3 of its "actual division of labour" list). Points 1 (Analyst → `AnalystTask`)
and 4 (subagent self-executes) still stand.

## Decisions

### The Broker is an LLM agent, and its tool choice *is* the classification

`plan_missions()` is retired rather than kept alongside the Broker. Running a
classification call and then having an agent decide which domains to engage is
two LLM calls making the same decision. The Broker's choice of which tool to
call **is** the classification; `TaskClassification` survives as the audit
record, now emitted by the Broker.

Its tested machinery was ported, not discarded: `_usage_from_accumulated()` (the
one bridge between Strands' camelCase usage keys and our snake_case `Usage`), the
injectable-Protocol test seam, and the reserve/release/settle discipline all
moved into `broker.py`, with their tests.

### Agents-as-Tools, using the `@tool`-wrapper variant

Strands documents three ways to do Agents-as-Tools. We use the third —
a `@tool` function constructing an `Agent` internally — which the docs offer
"for specialized control". The reason is concrete, not stylistic:
`Agent.as_tool()`'s tool spec is a single `input: string` and it returns text,
so `SubagentMission`, `Scope` validation, and `SubtaskResult`'s citation→evidence
checks cannot pass through it. A single `as_tool()` instance also refuses
concurrent invocation, returning a tool *error*.

**Not Swarm.** Read against the installed source rather than the docs summary:
`Swarm._build_node_input()` prepends to every node's prompt the original task,
the full handoff chain, and **every prior agent's shared context inlined
verbatim**. For SOC data that is disqualifying — our `Evidence` contract says raw
tool output is never shown to an LLM directly, and `SharedContext.add_context()`
has no such boundary. It also serialises (handoff transfers control) where we
want concurrent fan-out, and it owns the loop, leaving nowhere to wrap each node
in reserve/settle plus `SubtaskResult` assembly.

**Not Graph.** `GraphBuilder.add_node()` fixes the node set before `build()`, so
a per-task family set means rebuilding the topology every task to reimplement
what `ConcurrentToolExecutor` already does.

**Mid-run discovery needs no new machinery.** Mohammed asked what happens if a
subagent finds mid-run that another domain is needed. An agent calling a second
tool after seeing the first result has already re-dispatched — that is just the
agent loop. Only the signal was ours to build: `gaps: list[ToolFamily]`. It is
hub-and-spoke rather than peer-to-peer, deliberately: the Broker is the only
place holding the budget, the audit record, and the scope boundary.

### Typed entities — and this answers a question we were waiting on

`Scope.entities` was `list[str]`; it is now `list[Entity]` with
`EntityKind = Literal["host","user","ip","file_hash","domain","url","process"]`.

This is the shape the 08-09 entry was waiting on Yousef's Context Contract
Template to define, and the reason it mattered: a family's *dispatchability*
becomes a fact rather than a judgement. VirusTotal cannot be queried without a
hash, IP, domain, or URL, regardless of what any model decides. The mapping
lives in `broker.py`, not `contracts` — that module holds shape only, and
dispatchability is dispatch logic.

It is **not** a second classifier. `plan_missions()` was retired for duplicating
a *judgement*; this is a *precondition*, and it maps onto
`SubtaskStatus.REJECTED`'s documented meaning exactly.

Done now because it was cheapest now: `Scope.entities` was read by zero source
files and no Analyst populates it yet. The blast radius only grows.

### Two contract traps worth remembering

**`gaps` had to land on both models.** `SubtaskResult.from_answer()` splats
`**answer.model_dump()`, and pydantic's default `extra="ignore"` **silently
drops** unknown keys rather than raising. A field on `SubagentAnswer` alone would
have vanished between the subagent and the aggregator with no error. A test pins
it, because nothing else would catch it regressing.

**`REJECTED` must not set `error`.** `_StatusErrorContract` raises if `error` is
set on any non-`ERROR` status, so a rejection reason goes in `summary`. The first
draft of the stub subagent would have crashed on construction.

### The pricing bug that disabled budget gating

`ModelPrice` stored USD per million tokens, leaning on the coincidence that this
equals micro-USD per token. That holds only for whole-dollar rates. Every Claude
tier is $1–$25/Mtok so it never showed — but DeepSeek is sub-dollar and its input
rate truncated to `0`.

The ledger reporting input as free was the lesser problem. `estimate_cost()`
feeds `reserve()`, so a zero input rate made the admission check treat
input-heavy calls as costless and **budget gating silently stopped working** — on
the cheapest provider, which is exactly where a ceiling is most likely to be
relied on.

Rates are now nano-USD per token, which spans $0.014–$25/Mtok exactly, so one
table prices any provider and a cross-provider cost comparison is meaningful
rather than a comparison against zero. The 16 existing budget assertions needed
no changes: they assert on `cost_of()`'s micro-USD result, which did not change.

Cache pricing stays as *multipliers* on the base input rate, which is
Anthropic-shaped — some providers publish an absolute cache-hit price. Recorded
as an approximation rather than modelled, since nothing sets `cache_control` yet.

### MCP servers come from config, not code

Splunk is reached over MCP, which justified adopting `MCPClient.load_servers()`.
It deleted more than it added: credential interpolation, transport detection,
pagination, connection startup, internal caching, and per-server failure
isolation are all Strands'. Gone: `_started_clients`, `_clients_for()`, manual
`.start()` sequencing, and `tools/mcp/splunk.py`'s `NotImplementedError` stub.

What stays ours is the only thing Strands has no concept of: which servers serve
which `ToolFamily`. Clients are built per family by slicing the config rather
than correlating `load_servers()`'s flat, name-less return by position — which
would pair the wrong client to the wrong family whenever a server is skipped.

Every entry sets `continue_on_error`, which makes the no-credentials path work by
construction: an unset `${SPLUNK_TOKEN}` raises inside `load_servers()`, that
server is skipped, and `siem` resolves to zero tools instead of the process
failing.

### Enrichers: families that need no model

Some families need a decision about *what* to ask — which SPL to run, which host
to pivot to — and wait for a real subagent. A reputation lookup does not: the
entity's kind selects the endpoint and its value is the argument.

`ENRICHERS_BY_FAMILY` names that distinction, and it is what lets `vt` return
real `Evidence` with resolving citations **today**, with no model and no
subagent. Status reflects what was found rather than that the call worked: `OK`
when an indicator is flagged, `NO_DATA` when everything is clean or unknown.

VirusTotal is a native `@tool` rather than `strands_tools.http_request`: that
tool's four auth types emit `Authorization: Bearer|token|<raw>` or `X-API-Key`,
and VirusTotal accepts only `x-apikey`. The header *can* be passed as tool input
— but tool input comes from the model, so the key would land in the prompt, the
history, and any span recording tool inputs.

### Provider selection is configuration, not failover

`SMARTOPS_LLM_PROVIDER` → Bedrock (if `AWS_REGION`) → DeepSeek (if
`DEEPSEEK_API_KEY`) → scripted invoker. DeepSeek is wanted for cost; Bedrock is
the primary.

Resolution happens at **startup, from config**. A Bedrock outage does not fall
through to DeepSeek mid-run: retrying a failed call on another provider would
silently change which model, and which price, served a request. `ModelChoice`
carries `provider` because `build()` must return a bare id for Bedrock (Strands
constructs the model) and a constructed `Model` for anything OpenAI-compatible,
where a string would be misread as a Bedrock id.

Selecting DeepSeek currently fails at startup by design — no `PRICING` entry
exists until its rates are known, and a missing rate would reintroduce the
gating bug above by the back door.

## Scope: the plan was cut by ~80% before implementation

The design grew to ~28 new files and directories — a hook provider, an
interventions layer, two skill trees, a prompts registry, a security package, an
evaluation directory, Docker plus compose, a custom `ToolProvider`. Mohammed
called it over-engineered. Three independent reviews cut it to 2 new source
files, 1 test file, and a handful of edits.

Most of it was not *wrong*, it was *early*. The tell, visible in the plan's own
text: `tools_for()` could not succeed for any family and no live model call was
in scope, yet nearly every addition managed the consequences of tool calls
succeeding or a model deciding things.

Two items the reviewers cut were restored, because they were Mohammed's prior
decisions rather than open questions: the typed `gaps` field and
`Limits(turns=6)`. One was cut that I had already built: `FamilyToolbox`, a
custom `ToolProvider` — `Agent(tools=[*native, *clients])` gets the identical
ref-counted lifecycle with no new class, and a hand-written `remove_consumer`
fan-out risks violating the ABC's idempotency requirement for no gain.

## Corrections to earlier claims made this session

- Strands' **span-content redaction is opt-in and off by default**
  (`telemetry/tracer.py:101`). It applies in both attribute modes. Telemetry now
  exports nothing by default, and `.env.example` documents the redaction opt-in.
- I claimed the default `ConversationManager` silently truncates tool results
  and called it a correctness hazard. **Overstated** — content truncation fires
  only on the reactive-overflow path, and reduction only past a 40-message
  window.
- `strands_tools.http_request` looked like it could make VirusTotal work with no
  MCP server. It cannot authenticate to VT cleanly (see above), so
  `strands-agents-tools` was dropped after all.

## What shipped

Five commits on `task-broker-agent`, 124 tests passing, and the first thing in
this repo that runs end to end:

- `backend/src/smartops/broker.py` — the Broker agent, four `@tool(context=True)`
  family wrappers, `_dispatch`, the entity gate, the stub subagent seam.
- `backend/src/smartops/main.py` — `smartops-broker` CLI.
- `backend/src/smartops/tools/native/virustotal.py` — VT v3 lookups.
- `mcp_servers.json`, `.env.example` — config and its template.
- `contracts` — `Entity`/`EntityKind`, `gaps`, `AnalystTask.schema_version`.
- Deleted: `planner.py`, `tools/mcp/` (both superseded).

With no credentials, every family reports honestly why it cannot answer and the
process exits 0. That is the deliverable: the failure path is the only path
available until credentials exist, and it is now the one that is exercised.

## Open items

- **Blocked on Mohammed:** DeepSeek's per-million-token rates (deliberately not
  guessed); `SPLUNK_MCP_URL`/`SPLUNK_TOKEN`; `VT_API_KEY`; and the real Bedrock
  inference-profile id — the shipped one is a labelled `PLACEHOLDER`, since the
  legacy Converse path's ARN carries an unguessable date suffix.
- **For Yousef:** typed entities now exist as `Entity(kind, value)`. The
  `EntityKind` set is ours to propose and his to critique — `process` and `url`
  are the least settled members.
- **Aug-27 subagents.** `run_subagent` is the seam; these integrations make its
  resolved toolsets real, which is what lets that be a body swap.
- **Deferred, with the mechanism named:** `strands-agents-evals` for grading
  dispatch quality and red-teaming the injection surface;
  `vended_interventions/hitl/` for analyst approval before destructive actions
  (no extra dependency); `CedarAuthorization` for declarative tool policy (needs
  `cedarpy`); `strands/session/` and `experimental/checkpoint/` when `Budget`
  needs multi-process safety.
- **Still true:** `Budget` is single-process (`asyncio.Lock` serialises one event
  loop), which is why a FastAPI service stays out of scope; and `PRICING` holds
  Anthropic first-party rates, so on Bedrock the ledger is directionally correct
  rather than an invoice.
