# SmartOps SOC — Task Broker Architecture

> **Audience:** engineers, SOC leads, and stakeholders who want to understand how the
> Task Broker agent works and why it is built the way it is.
> **Source of truth:** this page is a stakeholder-friendly view of
> `docs/architecture.md` (the single map of the system). Code-level detail is in the
> appendices at the end.

---

## 1. Overview

SmartOps SOC is a **security triage engine**. An analyst asks a question about some
observables — a domain, an IP, a file hash, a host — and the system returns **typed,
code-assembled evidence with citations**, not free-text prose.

At the centre of the system is the **Task Broker**: an LLM *agent* that

1. decides **which security domains** are relevant to the question,
2. **plans** the fetch work as an explicit, machine-checkable plan, and
3. **dispatches** typed missions to specialised **domain subagents** that actually run the
   queries.

The key idea is a deliberate split of responsibility:

> **One agent decides *which* domains to engage. Separate domain subagents decide *what to
> ask* each domain and run the queries — so the raw output of a Splunk search never enters
> the deciding agent's context.**

This split is what makes the findings trustworthy: the agent that reasons about the case
never sees raw tool output it could accidentally paraphrase into something that was not
actually there.

---

## 2. Core design principles

The Task Broker follows seven principles. They explain almost every design decision on this
page.

| # | Principle | What it means in practice |
|---|-----------|---------------------------|
| 1 | **The Broker is an agent, not an orchestrator** | It has no separate "classifier" step. Its **choice of which tool to call *is* the classification** of which domain is relevant. |
| 2 | **The plan is explicit and code-evaluated** | The Broker must author a `FetchPlan` before any work is dispatched, and code — not the model — decides whether each step is complete. The model never ticks its own boxes. |
| 3 | **Context isolation** | Each subagent runs its own prompt and returns a compact **digest**. Raw evidence is assembled by code and never re-enters a model's context. |
| 4 | **Preconditions are facts, not judgements** | A domain with no entity of the kind it needs, or with no tools wired up behind it, is refused **before** a model is asked — without taking the decision away from the Broker. |
| 5 | **Findings are projected by code** | Tool output is captured and projected into typed findings; **citations are minted by code**, never authored by the model. |
| 6 | **Absence is reported honestly** | "We asked and found nothing" is a finding. "We never asked" is a gap. The system distinguishes the two rather than conflating them. |
| 7 | **A step is judged on what it asked for** | Each plan step declares the categories it is responsible for, so completion is evaluated **per step** against exactly what that step set out to retrieve. |

---

## 3. The load-bearing claim: evidence never reaches the deciding model

The single most important property of the design:

> **`Evidence` is never shown to an LLM.**

This is not a performance optimisation — it is the reason findings can be trusted. A real
example from development: on one run a subagent confidently reported it could see data in an
index called `botsv2`. That index does not exist on the server (there are 53 indexes, none
of them `botsv2`). **A model asked to summarise what it found will, some of the time, report
something that was not there.**

So the division of labour is absolute:

| Authored by the model | Assembled by code |
|-----------------------|-------------------|
| which domains to engage | every row of every finding |
| what to ask each domain | `Evidence`, with ids and provenance |
| which category a query served | which rows land in which category |
| an assessment of coverage | whether a step is complete |

Neither half can forge the other. **A model that never sees the rows cannot invent them;
code that never reads the prompt cannot be argued into re-categorising.**

---

## 4. Architecture

> 📌 **INSERT IMAGE HERE:** `task-broker-architecture.png`
> *(Caption: SmartOps SOC — Task Broker Architecture. One LLM agent decides which domains to
> engage; isolated domain subagents decide what to ask. Raw evidence is assembled by code and
> never re-enters the Broker's context.)*

### How to read the diagram

- **Analyst Agent** forms the investigative hypothesis and hands down an **`AnalystTask`** —
  a goal plus a scope of entities and a time window. It names no tool.
- **Task Broker** is a single agent holding a small, purposeful toolset:
  - **`plan_fetch()`** — authors the plan first, so code can validate it before anything is
    dispatched.
  - **Tool gate** — `available_broker_tools()` withholds any domain family that has *no*
    native tools **and** no MCP client wired up. This is a precondition, not a judgement.
  - **`investigate_<family>()`** — one typed tool per **configured** family
    (`investigate_siem`, `investigate_vt`). **Calling one of these tools *is* the decision
    that its domain is relevant.**
  - **`TaskClassification`** — the Broker's **trailing** output: a report of what was
    dispatched, not a decision about what to dispatch.
- The **context isolation boundary** (dashed line) is the heart of the design. Above it, the
  Broker's context holds only **digests**. Below it, subagents work with raw data that never
  crosses back up.
- **Domain Subagent** is one body serving all families. It has its own model, its own
  context, and its own toolset, and runs a bounded loop. An **entity gate** refuses a family
  that lacks the observable kind it needs, in code, before any model call. **Code assembly**
  captures tool output and projects it into typed findings with code-minted citations.
- **Backends** are the real tools: **Splunk** over MCP (SIEM) and **VirusTotal** over REST.
  `edr` and `ndr` have no vendor wired up, so they are withheld entirely — neither planned
  nor dispatched.
- **Budget ledger** and **Guards** are cross-cutting concerns applied throughout (see §9–10).

---

## 5. The contracts — the spine of the system

Every stage of an investigation is a **typed handover**. Each contract is deliberately narrow
so that no stage can smuggle in something it should not.

| Contract | What it carries | Why it is shaped this way |
|----------|-----------------|---------------------------|
| **`AnalystTask`** | goal + `Scope` (entities + time window) | Tool-agnostic: never names a query, index, or product. |
| **`Entity`** | `kind` (ip, domain, url, file_hash, host, user, process) + `value` | `value` is restricted to ASCII printable (minus `<` and `>`, max 512 chars) — an allowlist that blocks characters which could forge a line break inside the prompt. |
| **`FetchPlan`** | `steps` (≥1) + `rationale` | Authored via `plan_fetch` before any dispatch. `step_id`s must be unique (a validator enforces it). |
| **`FetchStep`** | `step_id`, `family`, `objective`, `CompletionRule`, `depends_on` | One unit of planned work. |
| **`CompletionRule`** | `requires` + `min_rows` | Structured, **not** prose — because code, not English, decides completion. |
| **`SubagentMission`** | family, objective, scope (copied) | Minted **from a step**. Carries **no pre-authored query** — deciding the query is the subagent's job. |
| **`SubagentAnswer`** | queries (tagged by category), assessment, status, gaps | **Forced structured output.** Has **no evidence field**, so a model cannot author evidence. |
| **`SubtaskResult`** | raw `Evidence` + projected findings + assessment | **Code-assembled.** A validator guarantees every citation resolves to a real evidence id. |
| **`StepOutcome`** | completed, evaluated, rows_retrieved, confirmed_empty, refused_for_budget | `evaluated` distinguishes *"ran and fell short"* from *"nobody ever attempted it."* |
| **`BrokerReport`** | the assembled result of the whole run | Written to disk with the evidence. |

Two subtle but important fields:

- **`evaluated`** exists so that a step nobody ever dispatched is not reported as a *failure*.
- **`confirmed_empty`** is a claim about the **data** — "we looked, and it is not there." It
  is refuted outright if rows were in fact retrieved, so an infrastructure failure can never
  be scored as a clean security conclusion.

---

## 6. Investigation flow (sequence)

> 📌 **INSERT IMAGE HERE:** `task-broker-sequence.png`
> *(Caption: SmartOps SOC — Task Broker Investigation Sequence. The model authors decisions
> (dashed structured output); code assembles evidence and evaluates completion.)*

Step by step, one investigation from question to report:

1. **`AnalystTask`** arrives — a goal plus a scope of entities and a time window. It names no
   tool.
2. The Broker calls **`plan_fetch(steps, rationale)`**, authoring the plan **before** any
   dispatch.
3. **Code validates the plan** — `step_id`s unique, families known — and returns the result
   as a tool result so the model can correct itself if needed.
4. For **each planned step** (subject to dispatch caps of 2 per step, 6 per family), the
   Broker calls **`investigate_<family>(question, step_id)`**. Calling the tool *is* the
   routing decision.
5. **Code runs the preconditions** — the plan/step/family guards, the entity gate, and the
   tool gate — all in code, before any model call.
6. Code mints a **`SubagentMission`** from the step (with no pre-authored query) and reserves
   budget (a ceiling, not a bill).
7. The **subagent** decides its queries and runs them against the backend, batching
   independent queries into its first turn. It loops up to **14 turns**. Raw result rows
   **stay inside the subagent**; each tool call is captured via a hook so **Evidence is
   assembled by code as it streams**.
8. The subagent returns a **`SubagentAnswer`** — assessment, queries tagged by category, gaps
   — as forced structured output, **with no rows**.
9. Code **projects** the captured output into typed findings, **mints citations** (each must
   resolve to a real evidence id), and settles the budget (crediting back the unused
   reservation).
10. Code **evaluates the step** against its `CompletionRule`, producing a `StepOutcome`.
11. Only a **digest** (`_digest()`) crosses back up to the Broker — **raw Evidence is withheld
    from the Broker's context** (shown in red on the diagram).
12. After all steps, the Broker emits **`TaskClassification`** (its trailing report of what
    was dispatched), and the full **`BrokerReport` + Evidence** is written to
    `report.json` / `evidence.json` under `.smartops/runs/…`.

---

## 7. How the Broker decomposes a goal — a worked example

There is no separate "decomposition algorithm." **The decomposition *is* the `plan_fetch`
tool call the Broker is forced to make before it can dispatch anything.** The diagram below
traces one real run end to end.

> 📌 **INSERT IMAGE HERE:** `task-broker-decomposition.png`
> *(Caption: How the Task Broker decomposes a goal — a real coinhive run: goal → the
> `plan_fetch` call the model was forced to make → three subtasks → three dispatched missions,
> each evaluated by code.)*

### The goal that came in

> **Goal:** *"Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?"*
> **Scope (fixed by the system, not changeable by the model):** entities `domain:coinhive.com`,
> `host:BSTOLL-L`; time window `2018-08-20 → 2018-08-21`.

The goal text is passed to the model **fenced as untrusted data**, and the scope is injected
out-of-band — so the Broker can decide *what to ask*, but can never widen *what is in play*.

### Step 1 — planning is mandatory

The system prompt requires the Broker to call `plan_fetch` before dispatching, and tells it
*how* to break the work up: **one step per question you actually need answered, not one step
per family** — and specifically to split SIEM work so each step owns exactly the data it asks
for.

### Step 2 — the model calls `plan_fetch`, and that call is the decomposition

For this goal the model authored the rationale *"Two domains of evidence are needed:
VirusTotal for external reputation of coinhive.com, and SIEM for logs of host BSTOLL-L
activity with that domain,"* and broke the goal into **three subtasks**:

| step_id | family | objective (the subtask) | completion rule |
|---------|--------|-------------------------|-----------------|
| `vt-coinhive-reputation` | vt | Look up reputation & threat intel for `coinhive.com` | `rows_or_confirmed_empty` |
| `siem-bstoll-coinhive-activity` | siem | Search logs for BSTOLL-L activity involving coinhive.com | `rows_or_confirmed_empty` |
| `siem-bstoll-network-dns` | siem | Search DNS / network connections BSTOLL-L → coinhive.com | `rows_or_confirmed_empty` |

Note it did exactly what the prompt asked: it **split the one SIEM goal into two distinct
questions** (host activity vs. DNS/network) and kept VirusTotal separate.

### Step 3 — each subtask is minted into a mission and dispatched

Calling `investigate_<family>(question, step_id)` for a step **is** the decision that the
domain is relevant. Each dispatch mints a `SubagentMission` — scope copied in, the model's
question as the goal, **no pre-authored query** — and hands it to a subagent, which authors
its own queries (the Broker never writes them):

```
vt_lookup_domain: coinhive.com
index=botsv3 sourcetype="stream:http" host="BSTOLL-L" "coinhive" | stats count, values(method) ...
index=botsv3 sourcetype="WinEventLog" host="BSTOLL-L" EventCode=4688 "coinhive" | table _time, host ...
```

### Step 4 — code evaluates each subtask independently

This is the part that makes the result trustworthy — **the model never marks its own work
complete.** Code applied each step's `CompletionRule` to the result it got back:

| subtask | completed | rows | confirmed_empty | status |
|---------|-----------|------|-----------------|--------|
| `vt-coinhive-reputation` | ✅ true | 1 | false | ok |
| `siem-bstoll-coinhive-activity` | ✅ true | 182 | false | ok |
| `siem-bstoll-network-dns` | ❌ **false** | 0 | **false** | **rejected** |

That third row is the whole design in miniature. The subtask was rejected (a
concurrent-dispatch MCP race, documented in `docs/archive/agent_architecture.md` §8), so it is recorded as
`completed=false` **and** `confirmed_empty=false`. The system refuses to claim "we looked and
found no DNS activity" when the truth is "we never got an answer." Splitting SIEM into two
steps is exactly what makes this possible: **one failing subtask cannot mark the other
complete**, because each is judged only on what it asked for.

---

## 8. Skill packs — optional, measured expertise for a subagent

A domain subagent can be given a **skill pack**: a bundle of specialised reference material
plus a tool to pull it in on demand. Today one pack ships — **`superman-splunk`**, attached to
the `siem` subagent — a production-grade reference for SPL, CIM mapping, BOTSv3 telemetry, and
SOC threat-hunting playbooks.

### How it works: lazy loading, not a bigger prompt

The pack is deliberately **not** dumped into the prompt. Eagerly loading every reference would
add 25,000+ tokens on turn 1, and re-sending that across a 14-turn loop would add ~350,000
input tokens (~$0.85/run) and degrade reasoning. Instead the pack works in two pieces, tied to
a single switch:

1. A concise **routing table** is injected into the `siem` system prompt (< ~1,200 tokens) —
   it lists what's available and when to consult each guide.
2. A **`read_reference(name)` tool** lets the subagent pull *only* the specific guide it needs,
   *when* it needs it.

So the subagent starts light and loads deep expertise on demand.

### What's in the `superman-splunk` pack

| Reference (`read_reference` name) | What it covers | When the subagent consults it |
|-----------------------------------|----------------|-------------------------------|
| `spl_syntax` | SPL commands, functions, aggregations, regex, subsearches | Authoring complex queries or aggregations |
| `cim_data_models` | CIM field mappings & schemas (Authentication, DNS, Traffic, Processes, Web, Malware, Filesystem) | Mapping raw fields to CIM names, projecting findings |
| `botsv3_sourcetypes` | BOTSv3 telemetry: `stream:dns/http/dhcp`, Sysmon IDs, WinEventLog codes, suricata, PAN, AWS | Choosing sourcetypes, filtering by Event ID |
| `investigation_playbooks` | Detection templates: cryptomining, C2 beaconing, Mimikatz, lateral movement, ransomware, exfil | Turning a goal into a structured multi-step retrieval |
| `performance_optimization` | Index/sourcetype pre-filtering, `tstats`, wildcard avoidance, time-window limits | Refactoring slow or unbounded searches |

### One switch, off by default — and why

The routing table and the `read_reference` tool are governed by **one** switch
(`skills_enabled()`), never independently: a run with the table but not the tool (or the
reverse) would be a configuration nobody could name afterwards.

It is **off unless asked for**. The pack changes the subagent's tool count and token costs, so
a run that silently had it on would report figures no clean run could be compared against. The
switch is pinned **per run** (`--skills` on the CLI / bench), and the run artifact records
which way it ran — an ambient environment variable deliberately cannot reach the benchmark.

### Does it help? (measured, with a caveat)

In one live coinhive comparison, the `--skills` run came in **cheaper** ($0.61 vs $0.73) with
**more typed findings** (45 `dns_resolutions` vs 27) than the same case without the pack. That
is genuinely encouraging — but it is **one sample against one sample** on a nondeterministic
model, so it is not yet a verdict. A real answer needs `--runs 3` on both settings. (This is
the same honesty rule the rest of the system applies to its own numbers.)

---

## 9. Budget & prompt caching

**Budget** follows a **reserve → run → settle** cycle, guarded by a lock so concurrent
dispatches cannot corrupt the ledger:

- A reservation is a **ceiling, not a bill** — `settle()` credits back the unused part.
  Over-estimating is therefore free; under-estimating would disable the gate.
- A step refused for **budget** is recorded separately (`refused_for_budget`) so a money
  problem is never mis-scored as a capability result.

**Prompt caching** marks the tool schemas and system prompt — the byte-identical prefix on
every turn — as a cacheable block. Because the target model provider does no automatic
caching, both halves are cached explicitly behind a single switch (so a run can never have one
cached and the other not). In measured runs, a cache write costs ~1.25× a normal input token
and a read ~0.1×, so caching pays for itself within two turns. There is a real minimum
cacheable prefix size; below it, nothing caches.

---

## 10. Guardrails & controls

- **`IndexScopeGuard`** cancels any query whose SPL targets an index outside the family's
  allowlist, or uses `index=*`. Its own docstring is explicit that this is a **correctness
  guardrail, not a security control** — because what data an arbitrary SPL string ultimately
  reaches (via subsearches, macros, lookups) is not decidable by inspection.
  - **The durable control belongs in deployment:** scope the Splunk token to the allowed
    indexes, enforced server-side. *The hook stops a confused model; the token scope stops an
    adversary.*
- **Planning guards** — no plan, unknown `step_id`, wrong-family `step_id` — are all **returned
  as tool results**, never raised, so the model can self-correct.
- **Entity gate** — a precondition that refuses a family lacking the observable kind it needs,
  regardless of what the model decides.
- **Prompt fencing** — untrusted spans (the question and the entities) are fenced and labelled
  as data. Entity values are rendered unescaped **by design**, because the subagent retypes
  them into queries; there is a test guarding each side of that bargain.

---

## 11. Budgets & limits at a glance

| Limit | Value | Purpose |
|-------|-------|---------|
| Broker turn budget | `DEFAULT_BROKER_TURNS = 11` | 1 plan + 6 dispatch + 1 report, plus 3 for correction. |
| Dispatches per planned step | `DISPATCHES_PER_PLANNED_STEP = 2` | A step may be retried once. |
| Dispatches per family | `MAX_PLANNED_DISPATCHES_PER_FAMILY = 6` | Family ceiling so a multi-step plan is not starved. |
| Subagent loop | `DEFAULT_TURNS = 14` | Bounds each domain subagent's own model loop. |

---

## Appendix A — Module map (code-level)

| Module | Responsibility |
|--------|----------------|
| `contracts/src/contracts/subtask.py` | The typed handovers: `AnalystTask`, `FetchPlan`/`FetchStep`/`CompletionRule`, `SubagentMission`, `SubagentAnswer`, `SubtaskResult`, `StepOutcome`, `Evidence`, `Scope`, `Entity`. |
| `backend/src/smartops/broker.py` | The Task Broker agent: `plan_fetch`, `investigate_<family>` tools, tool gating, planning guards. |
| `backend/src/smartops/subagents/__init__.py` | The single domain-subagent body serving all families; entity gates; the turn-cap recovery seam. |
| `backend/src/smartops/domains.py` | `DomainSpec` per family (description, required entity kinds, backends). |
| `backend/src/smartops/projection.py` | Projects captured tool output into typed `SiemFindings` / `VtFindings`. |
| `backend/src/smartops/budget.py` | The reserve → run → settle ledger. |
| `backend/src/smartops/guards.py` | `IndexScopeGuard` and related hooks. |
| `backend/src/smartops/skills/__init__.py` | The opt-in skill pack: routing-table injection, the `read_reference` tool, and the single `skills_enabled()` switch. |
| `backend/src/smartops/skills/vended/superman_splunk/` | The `superman-splunk` reference pack (`spl_syntax`, `cim_data_models`, `botsv3_sourcetypes`, `investigation_playbooks`, `performance_optimization`). |
| `backend/src/smartops/tools/registry.py` | Resolves MCP + native tools per family. |
| `backend/src/smartops/tools/native/virustotal.py` | The four native VirusTotal REST tools. |
| `backend/src/smartops/bench.py` | Benchmark runner over the BOTSv3 cases. |
| `backend/src/smartops/main.py` | CLI entry point (`smartops-broker`). |

## Appendix B — What is deliberately *not* used

Recorded with reasoning in `PROJECT_DOCS.md`, against `strands-agents==1.51.0`:

- **`Swarm`** — inlines shared context verbatim into node prompts, which would defeat the
  context isolation the whole design rests on.
- **`Graph`** — the node set is fixed before `build()`.
- **`Agent.as_tool()`** — single `input: string`, refuses concurrent invocation.
- **`strands-agents-tools`** — cannot send VirusTotal's `x-apikey` header.

Tool-call concurrency needs no extra code: `Agent` defaults to a concurrent tool executor, so
several tool calls emitted in one turn already run in parallel.

## Appendix C — Known open item

Nothing can evaluate or interrupt a mission **while** it runs — there is no mid-flight
checkpoint in the tree. Steps are independently evaluable **between** missions, which is a
smaller, different thing. The only mid-flight surface today is the before-tool-call hook.

---

*Diagrams source (editable): `docs/diagrams/task-broker-architecture.svg` and
`docs/diagrams/task-broker-sequence.svg`. PNG renders sit alongside them.*
