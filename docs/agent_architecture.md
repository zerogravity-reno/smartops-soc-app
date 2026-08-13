# SmartOps SOC — Agent Architecture

**Status:** current as of 2026-08-14, branch `task-broker-agent`.
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
`refused_for_budget`. `evaluated` distinguishes *"ran and fell short"* from *"nobody ever
attempted it"*; without it a never-dispatched step reported as a failure.

---

## 3. The Broker

[`backend/src/smartops/broker.py`](../backend/src/smartops/broker.py)

A single Strands `Agent` with five tools: `plan_fetch` plus one
`investigate_<family>` per domain. Calling a specialist's tool **is** the decision that
its domain is relevant — so `DomainSpec.description` is the entire basis for routing and
is written to say what each domain is *not* for, as well as what it is.

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

`edr` and `ndr` are configured but disabled — no vendor picked. They resolve zero tools
and are rejected with a reason that distinguishes *"nothing configured"* from *"configured
but not answering"*. Those need different fixes and would otherwise look identical.

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
