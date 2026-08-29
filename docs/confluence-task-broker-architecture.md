# SmartOps SOC — Task Broker Architecture

> **Audience:** engineers and SOC leads who need to understand how the fetch tier works.
> **Source of truth:** `docs/architecture.md` is the single map of the whole system; this
> page is the fetch half in depth. The *why* behind each decision is in
> `docs/PROJECT_DOCS.md`. **~5 minute read.**

---

## 1. What it does

An analyst asks a question about some observables — a domain, an IP, a file hash, a host —
and the system returns **typed, code-assembled evidence with citations**, not prose.

The **Task Broker** is an LLM agent that decides which security domains are relevant, plans
the fetch work as a machine-checkable plan, and dispatches typed missions to specialised
**domain subagents** that run the actual queries.

The split is the point:

> **One agent decides *which* domains to engage. Separate subagents decide *what to ask*
> each domain and run the queries — so the raw output of a Splunk search never enters the
> deciding agent's context.**

---

## 2. The load-bearing claim

> **`Evidence` is never shown to an LLM.**

Not an optimisation — it is why the findings can be trusted. During development a subagent
confidently reported data in an index called `botsv2`. That index does not exist on the
server. A model asked to summarise what it found will, sometimes, report what was not there.

So the division is absolute:

| Authored by the model | Assembled by code |
|---|---|
| which domains to engage | every row of every finding |
| what to ask each domain | `Evidence`, with ids and provenance |
| which category a query served | which rows land in which category |
| an assessment of coverage | whether a step is complete |

**A model that never sees the rows cannot invent them; code that never reads the prompt
cannot be argued into re-categorising.**

---

## 3. Design principles

| # | Principle | In practice |
|---|---|---|
| 1 | **The Broker is an agent, not an orchestrator** | No separate classifier step. Its **choice of which tool to call *is* the classification**. |
| 2 | **The plan is explicit and code-evaluated** | It must author a `FetchPlan` before anything dispatches, and code decides whether each step is complete. The model never ticks its own boxes. |
| 3 | **Context isolation** | Each subagent runs its own prompt and returns a compact digest. Raw evidence never re-enters a model's context. |
| 4 | **Preconditions are facts, not judgements** | A domain with no entity of the kind it needs, or no tools wired behind it, is refused **before** a model is asked. |
| 5 | **Citations are minted by code** | Never authored by the model. |
| 6 | **Absence is reported honestly** | "We asked and found nothing" is a finding. "We never asked" is a gap. The two are never conflated. |
| 7 | **A step is judged on what it asked for** | Each step declares the categories it owns; completion is evaluated per step. |

---

## 4. Architecture

> 📌 **INSERT IMAGE:** `task-broker-architecture.png`
> *(One LLM agent decides which domains to engage; isolated subagents decide what to ask.
> Raw evidence is assembled by code and never re-enters the Broker's context.)*

- **Analyst Agent** hands down an **`AnalystTask`** — a goal plus a scope of entities and a
  time window. It names no tool.
- **Task Broker** holds a small, purposeful toolset:
  - **`plan_fetch()`** — authors the plan first, so code can validate it before dispatch.
  - **Tool gate** — `available_broker_tools()` withholds any family with no native tools
    *and* no MCP client wired up. A precondition, not a judgement.
  - **`investigate_<family>()`** — one typed tool per *configured* family. **Calling one
    *is* the decision that its domain is relevant.**
  - **`TaskClassification`** — a trailing report of what was dispatched, not a decision
    about what to dispatch.
- **The context isolation boundary** is the heart of it. Above: digests only. Below:
  subagents work with raw data that never crosses back up.
- **Domain Subagent** — one body serving all families, with its own model, context and
  toolset, running a bounded loop. An entity gate refuses a family lacking the observable
  kind it needs, in code, before any model call.
- **Backends** — Splunk over MCP, VirusTotal over REST. `edr` and `ndr` have no vendor
  wired, so they are withheld entirely: neither planned nor dispatched.

---

## 5. The contracts

Every stage is a typed handover, each deliberately narrow so no stage can smuggle in
something it should not.

| Contract | Carries | Shaped this way because |
|---|---|---|
| **`AnalystTask`** | goal + `Scope` | Tool-agnostic: never names a query, index, or product. |
| **`Entity`** | `kind` + `value` | `value` is ASCII-printable only, minus `<` and `>`, max 512 chars — an allowlist blocking characters that could forge a prompt fence. |
| **`FetchPlan`** / **`FetchStep`** | steps, objective, `depends_on` | Authored before any dispatch; `step_id`s validated unique. |
| **`CompletionRule`** | `requires` + `min_rows` | Structured, **not** prose — code decides completion, not English. |
| **`SubagentMission`** | family, objective, scope | Minted from a step. Carries **no pre-authored query** — that is the subagent's job. |
| **`SubagentAnswer`** | queries, assessment, status, gaps | Forced structured output with **no evidence field**, so a model cannot author evidence. |
| **`SubtaskResult`** | raw `Evidence` + projected findings | Code-assembled; a validator guarantees every citation resolves to a real evidence id. |
| **`StepOutcome`** | completed, evaluated, rows_retrieved, confirmed_empty, refused_for_budget | See below. |
| **`BrokerReport`** | the whole run | Written to disk with the evidence. |

Two fields carry more weight than they look:

- **`evaluated`** — so a step nobody dispatched is not reported as a *failure*.
- **`confirmed_empty`** — a claim about the **data**: "we looked, it is not there." Refuted
  outright if rows were in fact retrieved, so an infrastructure failure can never be scored
  as a clean security conclusion.

---

## 6. Guardrails

- **`IndexScopeGuard`** cancels any query whose SPL targets an index outside the family's
  allowlist, or uses `index=*`. Its own docstring is explicit that this is a **correctness
  guardrail, not a security control** — what an arbitrary SPL string ultimately reaches, via
  subsearches, macros and lookups, is not decidable by inspection. **The durable control
  belongs in deployment:** scope the Splunk token to the allowed indexes, server-side. *The
  hook stops a confused model; the token scope stops an adversary.*
- **Planning guards** — no plan, unknown `step_id`, wrong-family `step_id` — are **returned
  as tool results**, never raised, so the model can self-correct.
- **Entity gate** — refuses a family lacking the observable kind it needs, whatever the
  model decided.
- **Prompt fencing** — untrusted spans are fenced and labelled as data. Entity values are
  rendered *unescaped* by design, because the subagent retypes them into queries; a test
  guards each side of that bargain.

## 7. Limits

| Limit | Value | Purpose |
|---|---|---|
| Broker turns | `DEFAULT_BROKER_TURNS = 11` | 1 plan + 6 dispatch + 1 report, plus 3 for correction. |
| Dispatches per planned step | `DISPATCHES_PER_PLANNED_STEP = 2` | A step may be retried once. |
| Dispatches per family | `MAX_PLANNED_DISPATCHES_PER_FAMILY = 6` | So a multi-step plan is not starved. |
| Subagent loop | `DEFAULT_TURNS = 14` — **but the CLI passes 25** | The library default and the `--subagent-turns` default differ; a CLI run gets 25. |
| Broker output tokens | `DEFAULT_BROKER_OUTPUT_TOKENS = 4000` — **CLI passes 16000** | Same split; `--broker-output-tokens` wins. |

---

## Appendix — Module map

| Module | Responsibility |
|---|---|
| `contracts/src/contracts/subtask.py` | The typed handovers listed in §5. |
| `backend/src/smartops/broker.py` | The Broker agent: `plan_fetch`, `investigate_<family>`, tool gating, planning guards. |
| `backend/src/smartops/subagents/__init__.py` | The single subagent body serving all families; entity gates; the turn-cap recovery seam. |
| `backend/src/smartops/domains.py` | `DomainSpec` per family — description, required entity kinds, backends. |
| `backend/src/smartops/projection.py` | Projects captured tool output into typed `SiemFindings` / `VtFindings`. |
| `backend/src/smartops/budget.py` | The reserve → run → settle ledger. |
| `backend/src/smartops/guards.py` | `IndexScopeGuard` and related hooks. |
| `backend/src/smartops/skills/` | The opt-in `superman-splunk` reference pack, off by default. |
| `backend/src/smartops/tools/registry.py` | Resolves MCP + native tools per family. |
| `backend/src/smartops/main.py` | CLI entry point (`smartops-broker`). |

**Deliberately not used** (against `strands-agents==1.51.0`, reasoning in `PROJECT_DOCS.md`):
`Swarm` (inlines shared context verbatim into node prompts, defeating the context isolation
this design rests on), `Graph` (node set fixed before `build()`), `Agent.as_tool()` (single
`input: string`, refuses concurrent invocation), `strands-agents-tools` (cannot send
VirusTotal's `x-apikey`). Tool-call concurrency needs no extra code — `Agent` defaults to a
concurrent executor.

**Known open item:** nothing can evaluate or interrupt a mission *while* it runs. Steps are
independently evaluable *between* missions, which is a smaller, different thing. The only
mid-flight surface is the before-tool-call hook.

---

*Diagram sources: `docs/diagrams/task-broker-architecture.svg`, `-sequence.svg`,
`-decomposition.svg`. PNG renders sit alongside them, untracked — regenerate from the SVG.*
