# SmartOps SOC — Agent Architecture

**Status:** current as of 2026-08-15, branch `task-broker-agent`.
**Scope:** how the agent is built and why. Every claim here is checked against the
tree; every measured figure names the artifact it came from.

---

## 1. What this system is

A SOC triage engine that takes an analyst's question about some observables and
returns **typed, code-assembled evidence** — not prose.

One agent decides *which* security domains to engage. Separate domain subagents decide
*what to ask* their domain and run the queries. The split exists so that the raw output
of a Splunk search never enters the deciding agent's context.

```
Analyst
  │  AnalystTask (goal + scope: entities, time window)
  ▼
Task Broker ──────────────────────────────────────────────┐
  │  plan_fetch(steps, rationale)  →  FetchPlan            │  Broker's context holds
  │                                                        │  only digests, never
  │  per step: investigate_<family>(question, step_id)     │  raw tool output
  ▼                                                        │
Domain Subagent  (own model, own context, own toolset)     │
  │  tool calls ─────────► Splunk MCP / VirusTotal REST    │
  │  ◄───────────────────── raw results                    │
  │                                                        │
  │  model authors  SubagentAnswer  (assessment, queries)   │
  │  code assembles Evidence + Findings                    │
  ▼                                                        │
SubtaskResult ─── _digest() ──────────────────────────────┘
  ▼
StepOutcome (CompletionRule evaluated by code)
  ▼
BrokerReport
```

### The load-bearing claim

**`Evidence` is never shown to an LLM.** The contract says so directly
([subtask.py:245](../contracts/src/contracts/subtask.py#L245)), `SubagentAnswer` has no
`evidence` field so a model cannot author one, and `_digest()` bounds what re-enters the
Broker's context when a subagent returns.

This is not a performance optimisation. It is the reason findings can be trusted. On
2026-08-11 a siem subagent reported it could see data in an index called `botsv2`. That
index does not exist on the server — 53 indexes, none of them `botsv2`. A model asked to
summarise what it found will, some of the time, report something that was not there.

So the division is absolute:

| Authored by the model | Assembled by code |
|---|---|
| which domains to engage | every row of every finding |
| what to ask each domain | `Evidence`, with ids and provenance |
| which CIM category a query served | which rows land in which category |
| an `Assessment` of coverage | whether a step is complete |

Neither half can forge the other. A model that never sees the rows cannot invent them;
code that never reads the prompt cannot be argued into re-categorising.

---

## 2. The contracts

All in [`contracts/src/contracts/subtask.py`](../contracts/src/contracts/subtask.py).
These are the spine — every stage is a typed handover, and each one is narrow on purpose.

**`AnalystTask`** — goal, and a `Scope` of `Entity` values plus a time window.
Tool-agnostic: it never names a query, an index, or a product.

**`Entity`** — `kind` (`ip`, `domain`, `url`, `file_hash`, `host`, `user`, `process`)
and `value`. `value` is restricted to **ASCII printable, minus `<` and `>`, max 512
chars**. That allowlist replaced a blocklist after a review measured seven Unicode
classes surviving it — `U+2028` line separator among them, which forges a line break
inside the prompt fence. Punycode (`xn--`) is the canonical ASCII form a SIEM or DNS
query actually uses, so ASCII-only is arguably correct for an observable rather than a
compromise.

**`FetchPlan`** — `steps` (≥1) and a `rationale`, authored through the `plan_fetch` tool
before any dispatch. `step_id` uniqueness is enforced by a validator, because a model
naming steps per-family (`step-1` for siem, `step-1` for vt) previously caused two
failures at once: the shadowed step vanished from the report, and the wrong-family
refusal told the model to retry the exact id it had just used — an unrecoverable loop.

**`FetchStep`** — `step_id`, `family`, `objective`, a `CompletionRule`, and `depends_on`.

**`CompletionRule`** — two structured fields, `requires`
(`rows_or_confirmed_empty` | `rows_required`) and `min_rows`. Deliberately **not** prose:
code cannot evaluate an English sentence, and completion is a code judgement.

**`SubagentMission`** — minted *from a step*: family, objective as goal, scope copied,
`step_id` in the task_id. Carries no pre-authored query — deciding the query is the
subagent's job.

**`SubagentAnswer`** — forced structured output. `queries_run` (each tagged with the CIM
category it served), `assessment`, `status`, `gaps`. Per-family concrete models are built
by `make_answer_model()`, because the bare base has no `assessment` field and forcing the
base would never actually ask for one.

**`SubtaskResult`** — code-assembled. Carries raw `Evidence`, projected `findings`, and
the model's `assessment`. A validator guarantees every citation resolves to a real
evidence id.

**`StepOutcome`** — `completed`, `evaluated`, `dispatches`, `rows_retrieved`,
`confirmed_empty`, `refused_for_budget`. `evaluated` distinguishes *"ran and fell short"*
from *"nobody ever attempted it"*; without it a never-dispatched step reported as a failure.

`confirmed_empty` is a claim about the **data** — we looked, and it is not there — and
`rows_or_confirmed_empty` accepts it as satisfaction, so it decides whether a step closes.
It was previously set by `status == NO_DATA` alone, which is also what a subagent returns
when it is cut off before answering. A run on 2026-08-15 recorded `rows_retrieved=252`,
`confirmed_empty=True` and `completed=True` together, for a host that had in fact resolved
the domain 21 times: an infrastructure failure scored as a security conclusion. Retrieved
rows now refute the claim outright.

---

## 3. The Broker

[`backend/src/smartops/broker.py`](../backend/src/smartops/broker.py)

A single Strands `Agent` with `plan_fetch` plus one `investigate_<family>` tool per
**configured** domain. Calling a specialist's tool **is** the decision that its domain is
relevant — so `DomainSpec.description` is the entire basis for routing and is written to
say what each domain is *not* for, as well as what it is.

**The toolset is gated on what is actually wired up.** `available_broker_tools()` drops
any family with neither native tools nor a built MCP client, read at invoker construction
because `load_mcp_servers()` runs after this module is imported — a module-level constant
would be computed while every family still had zero servers. Both halves of
`family_is_configured()` are load-bearing: `vt` carries `mcp_servers=()` and answers
entirely through native tools, so a `server_count()`-only gate would withhold the one
family that needs no server.

This is the same **precondition, not judgement** line the entity gate draws, applied to
tooling. Withholding a domain that provably cannot answer takes no decision away from the
Broker; what it removes is planner output spent on steps that can only be rejected, and
rejected families landing in `dispatched`, where they made `routing_correctness` read 0%.
A family that *is* configured but cannot answer still dispatches and still gets the
"configured but returning no tools" rejection — that distinction is the point, and
collapsing it would send an analyst to the config file for a network problem.

**Planning is mandatory in code.** Three guards sit before any dispatch is recorded:
no plan, unknown `step_id`, wrong-family `step_id`. All three are *returned as tool
results*, never raised, so the model can correct itself. `MissingStepIdGuard` — a
`BeforeToolCallEvent` hook — intercepts an omitted `step_id` early enough to name the
tool and list the valid ids, because the tool body never runs when a required argument is
missing.

**Dispatch caps** are per-planned-step (`DISPATCHES_PER_PLANNED_STEP = 2`) under a family
ceiling (`MAX_PLANNED_DISPATCHES_PER_FAMILY = 6`), so a three-step siem plan is not
starved by a cap sized for one.

**Turn budget** is `DEFAULT_BROKER_TURNS = 11`: 1 plan + 6 dispatch + 1 report, plus 3
for correction. The headroom is pinned by a test, because every refusal costs a turn the
bare arithmetic never allocated.

`TaskClassification` is the Broker's **trailing** structured output — a report of what was
dispatched, not a decision about what to dispatch. (Diagrams that show it leading have it
backwards.)

---

## 4. Domain subagents

[`backend/src/smartops/subagents/__init__.py`](../backend/src/smartops/subagents/__init__.py)

One body handles all four families, because the differences are already data:

| | `siem` | `vt` | `edr` | `ndr` |
|---|---|---|---|---|
| Entity gate (`required_kinds`) | any | file_hash, ip, domain, url | host, process, user | ip, domain, url |
| Backend | Splunk MCP (10 tools) | VirusTotal REST (4 native tools) | — | — |
| Time-scoped | yes | no | yes | yes |

The entity gate is a **precondition, not a judgement**: it holds regardless of what a
model decides, which is why VirusTotal is refused a `user` observable in code before
anything is dispatched.

`edr` and `ndr` have no vendor picked, so nothing is wired up for them. They are now
withheld from the Broker's toolset entirely (§3) rather than dispatched and rejected —
they are neither planned nor called. The rejection path they used to take still exists and
still distinguishes *"nothing configured"* from *"configured but not answering"*, which is
what a **configured** family reaching zero tools now gets.

### The answer survives the turn cap

Strands ends a capped run with `limit_turns` / `limit_output_tokens` and raises nothing,
so the tool calls are billed, the evidence is collected, and only the model's own answer is
missing. Because no answer means no category tags, every result set then lands in
`uncategorised` — the rows are retrieved and paid for, and arrive untyped.

When the loop returns no structured output, `_build_agent_and_invoke()` makes **one** more
call, bounded to `turns=1` and prompted not to query, purely to convert what was already
retrieved into a typed answer. This is a sanctioned seam rather than a trick: `Limits`
bounds a single `invoke_async`, its counters do not carry across reuses of the same agent,
and a capped run leaves `agent.messages` "in a reinvokable state"
([`strands/types/agent.py:17-23`](../.venv/Lib/site-packages/strands/types/agent.py)).
Tools cannot be unbound after construction, so the prompt is what keeps this from becoming
a second exploration loop and `turns=1` is what bounds it if the model ignores that.

`structured_output_model` is already set on the `Agent`, so the recovery call is forced
into the same family answer model without restating it, and usage keeps accumulating on
`agent.event_loop_metrics` across invocations, so billing needs no change.

### The skill pack

`smartops.skills` can attach a `superman-splunk` reference pack to the `siem` subagent: a
routing table injected into the system prompt plus a `read_reference` tool, both behind one
switch so a run with the table but not the tool is impossible. It is **off unless asked
for** — the pack changes tool counts and token costs, so a run that silently had it on
reports figures no other run can be compared against. `--skills` pins it per run and the
report records which way it ran; an ambient `SMARTOPS_SKILLS_ENABLED` cannot reach the
bench, deliberately.

### Prompt structure

`BUDGET` block (turn ceiling, and **two** stop conditions — running short, and having the
answer), `HOW TO WORK` (batch independent queries into turn 1), per-family specialisation,
a reporting contract, and `SECURITY CONSTRAINTS`.

Untrusted spans — the question and the entities — are fenced and labelled as data.
**Entity values render unescaped and must stay that way**: the subagent retypes them
into SPL, so escaping would change which indicator gets queried. That bargain is the
design's load-bearing claim about the fence, and there is a test on each side of it.

### Guardrails

`IndexScopeGuard` cancels a tool call whose SPL targets an index outside the family's
allowlist, or uses `index=*`. Its own docstring is explicit that this is a **correctness
guardrail, not a security control** — deciding what data an SPL string reaches is not
decidable by inspection, since subsearches, macros, `tstats` and lookups all reach data
by routes it never sees. The strong version costs no code and belongs in deployment:
**scope the Splunk token to the allowed indexes**, enforced server-side. The hook stops a
confused model; the token scope stops an adversary.

---

## 5. Budget

[`backend/src/smartops/budget.py`](../backend/src/smartops/budget.py)

Reserve → run → settle, guarded by an `asyncio.Lock` so concurrent dispatches cannot
corrupt the ledger. A reservation is a **ceiling, not a bill** — `settle()` credits back
the unused part, and reservations have measured ~1.27× above actual spend. Over-estimating
is therefore free, while under-estimating disables the gate.

A step refused for **budget** must not report as unmet **criteria**
(`StepOutcome.refused_for_budget`, set from a shared sentinel). Conflating them is how an
evaluation scores a money problem as a capability result.

**Prompt caching** marks the tool schemas and system prompt as a cacheable prefix — the
part that is byte-identical on every turn. Bedrock has no automatic caching, so both
halves need explicit cache points: `cache_tools` on the model, and a `cachePoint` block
after the system prompt text. One switch (`ModelChoice.cache_prefix`) governs both, since
a run with one cached and the other not is a configuration nobody can name afterwards.

Measured directly, siem toolset attached:

| turn | uncached input | cache write | cache read |
|---|---|---|---|
| 1 | 336 | 3,321 | 0 |
| 2 | 694 | 3,321 | 3,321 |
| 3 | 1,074 | 3,321 | 6,642 |

A write costs ~1.25× input and a read ~0.1×, so two turns already beat paying full price
twice. **The minimum cacheable prefix is real**: the same test without tools attached had
a 973-token prefix, below Sonnet 4.6's 1,024-token floor, and silently cached nothing.
`cache_read_input_tokens == 0` in a report is the tell.

---

## 6. What is deliberately not used

Recorded with reasoning in `PROJECT_DOCS.md` (2026-08-11), against
`strands-agents==1.51.0` pinned exactly:

- **`Swarm`** — inlines shared context verbatim into node prompts, which would defeat the
  context isolation the whole design rests on.
- **`Graph`** — node set fixed before `build()`.
- **`Agent.as_tool()`** — single `input: string`, refuses concurrent invocation.
- **`strands-agents-tools`** — cannot send VirusTotal's `x-apikey` header.

Tool-call concurrency needs no code: `Agent.__init__` defaults to
`ConcurrentToolExecutor`, and none of this codebase's construction sites overrides it, so
several tool calls emitted in one turn already run in parallel.

---

## 7. History worth not re-deriving

- **The flat-broker A/B is over.** A second topology (Arm F) executed steps in the
  Broker's own context as a baseline. It was dropped in favour of the subagent design, and
  with it went two defects that only existed because there were two arms to compare:
  `routing_correctness` compared dispatch *intent* against *realised work*, and the
  significance rule was a hardcoded threshold that called a one-millisecond delta
  "statistically significant" on a single run per arm.
- **Splunk's TLS.** The management port presents the stock
  `CN=SplunkServerDefaultCert`, issued by a CA no public trust store carries and carrying
  **no subjectAltName** — so importing the CA still fails hostname verification against an
  IP. `SMARTOPS_MCP_TLS_NO_VERIFY=splunk` is the named, per-server escape hatch; replacing
  the certificate with one carrying a proper SAN is the durable fix. Unset means every
  server is verified.
- **Two failure modes look identical from `tools_for()`** unless you check
  `server_count()` too: a certificate rejection and "no server configured" both yield zero
  tools. A whole live run once reported success with Splunk entirely absent because
  nothing distinguished them.

---

## 8. Measured on this tree

Three live runs of `botsv3_coinhive`, 2026-08-15, one run each, real Bedrock calls
(`scripted: false`). Artifacts under `.smartops/runs/botsv3_coinhive/`.

| | before the fixes<br>`…T112844145` | after<br>`…T124556942` | after, `--skills`<br>`…T161337647` |
|---|---|---|---|
| Cost | $1.0393 | $0.7293 | **$0.6132** |
| Input tokens (uncached) | 264,343 | 172,897 | **141,692** |
| Cache reads | 78,823 | 59,057 | 45,656 |
| Wall clock | 168.7s | 138.9s | **111.5s** |
| Queries run | 32 | 12 | 14 |
| Findings rows | 252 | 183 | 222 |
| — typed `dns_resolutions` | 0 | 27 | 45 |
| — `uncategorised` | 252 | 135 | 176 |
| Dispatched | vt, siem, ndr, edr | vt, siem | vt, siem |
| Routing correctness | 0% | 100% | 100% |
| siem step status | `no_data` | `ok` | `ok` |

**What these do and do not establish.** The dispatch, routing, `confirmed_empty` and
typing changes are deterministic code paths and are attributable. The cost, token and
wall-clock deltas are **one sample against one sample** on a nondeterministic model, and
the middle run happened to split siem into two steps while the others did not. Treat them
as encouraging, not as a result. A skill-pack verdict needs `--runs 3` on both settings.

Two things the runs surfaced that are not yet fixed:

- **The MCP client tears down under a second dispatch.** When the planner split siem into
  two steps, the second was rejected with "1 MCP server(s) configured but returning no
  tools" while the first had just succeeded. `MCPClient` is a `ToolProvider` with
  ref-counted consumers, so the first subagent's `cleanup()` can drop the count to zero
  and close the connection under the second. Holding a process-level consumer across the
  run is the fix.
- **The plan has no granularity where the cost is.** The Broker plans *across* families,
  but ~85% of a run's spend is inside `siem`, historically as a single step containing
  every query. Nothing can evaluate or stop that loop until it returns.
