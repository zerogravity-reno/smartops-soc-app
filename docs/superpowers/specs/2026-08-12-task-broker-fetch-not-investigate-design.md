# Task Broker: fetch, not investigate

**Date:** 2026-08-12
**Status:** approved, not yet implemented

## Problem

The live BOTSv3 run on 2026-08-11 worked end to end — $1.03, 137s, 72 spans, real
findings from real 2018 data. It did the **wrong job**.

Asked "is coinhive.com known-malicious, and what did host BSTOLL-L do with it", it
returned an *investigation*: a narrative concluding that `chrome.exe` PID 9752
under `AzureAD\BudStoll` was browser cryptomining. That conclusion belongs to the
Analyst. The Broker takes a contract from the Analyst — entities, a time window, a
goal — fetches what was asked for in an agreed schema, and hands it back.

**The root cause is the contract, not the topology.** `SubagentAnswer.summary: str`
(`contracts/subtask.py:158`) is the only field findings can go in. Prose is the
only shape available, prose becomes narrative, and narrative wants a conclusion.
The subagent prompt asks for precisely that — "summary: what you found, in a few
sentences" (`subagents/__init__.py:119`). Collapsing the subagent layer would not
fix this: the same prompt in the Broker produces the same prose.

Investigating the run surfaced four more defects worth fixing in the same pass:

| Finding | Evidence |
|---|---|
| Adding a domain touches **10 sites across 5 files**, none failing loudly if missed | §1 |
| No `temperature` is ever set — every call runs at Bedrock's default of 1.0 | `budget.py:178-186` |
| Every SPL used `index=*`; attributable by luck, invisible without a raw span dump | §2 |
| No return contract to the Analyst — `BrokerOutcome` is internal, never serialised | `broker.py:173` |
| Nothing defines **task completion**; the subagent used 14/14 turns and stopped because it ran out | §3 |

### Two claims checked and found false

Both came from reading the trace report rather than the trace.

**The subagents did not call each other's tools.** Every `splunk_*` span carries
`tool_family=siem` and the siem mission's `task_id`; the `vt_lookup_domain` span
carries `tool_family=vt`. `tools_for()` (`registry.py:413-418`) builds each
family's toolset from only that family's servers, and `_assert_no_shared_servers()`
refuses to let one server serve two families. The apparent crossover is a rendering
artifact of the uncommitted `build_report.py`, which indents by span depth and
sorts by start time — so two *concurrent sibling* subtrees interleave and read as
one agent's work.

**`FamilyToolbox` was never built.** It was cut in review
(`docs/sessions/2026-08-11-task-broker-agent.md:189-193`).

### Where the time and money went

Summed from the trace. Of the SIEM subagent's 115.2s:

- **~23s** — Splunk answering (24 calls, run in concurrent pairs)
- **~91s** — the model thinking, across 14 sequential `chat` spans

297,225 input tokens against 5,629 output — $0.89 of the $0.976, because every
turn re-sends the conversation. Neither agent approached a context limit: the
Broker used 5,786 tokens of a 1M window, and the subagent's largest single call
was ~40–50k. **Latency and cost are set by the number of sequential model turns**,
not by context size and not by who issues the tool calls.

Strands already runs one turn's tool calls concurrently — all four `investigate_*`
spans start at +5.74s. Parallelism is a property of the event loop, not of
subagents. Subagents overlap the *reasoning chains* of different domains, which on
this run was worth roughly 10%.

## Invariants

Settled and load-bearing. This work does not touch them:

- The `SubagentAnswer`/`SubtaskResult` **envelope**: `_StatusErrorContract`,
  `_evidence_ids_are_unique`, `_citations_resolve_to_evidence`, `gaps` on both.
- **Scope immutability** — `scope` reaches a mission from `invocation_state`,
  never from tool input (`broker.py:464`).
- **The digest boundary** — the Broker sees `_digest()`, never raw `Evidence`.
- **Evidence assembled by code**, never authored by a model
  (`contracts/subtask.py:152-156`).
- **`tools_for()` family isolation.**
- The **enricher path** for `vt` — zero model calls, perfectly reproducible.
- Injection defences: the `SECURITY CONSTRAINTS:` blocks, `_neutralize_delimiter()`,
  and the `<goal>` / `<question>` fencing.

## Design

### 1. `DomainSpec` — adding a domain becomes one entry

Today a new family must be registered at `contracts/subtask.py:15`, `broker.py:102`,
a hand-written `@tool` wrapper, `broker.py:552`, `main.py:46`, `main.py:52`,
`subagents/__init__.py:78`, `registry.py:80`, `registry.py:89`, `registry.py:103`,
and `mcp_servers.json`.

New file `backend/src/smartops/domains.py`:

```python
@dataclass(frozen=True)
class DomainSpec:
    family: ToolFamily
    description: str                     # what the Broker's model reads
    required_kinds: frozenset[EntityKind] | None
    time_scoped: bool
    mcp_servers: tuple[str, ...]
    native_tools: list
    enricher: Callable | None
    assessment_model: type[BaseModel]    # model-authored, small
    findings_model: type[BaseModel]      # code-assembled from Evidence
    skill: SkillPack | None = None       # populated in §9
    turns: int = 14
    max_output_tokens: int = 12_000

DOMAINS = {s.family: s for s in (SIEM, EDR, NDR, VT)}
FAMILY_TOOLS = [make_investigate_tool(s) for s in DOMAINS.values()]
```

`make_investigate_tool()` replaces the four hand-written wrappers. **Reuse:**
Strands' `@tool` accepts explicit `name=` and `description=` rather than reading a
docstring — verified in `vended_tools/file_editor/file_editor.py:57`, which is how
its own `make_file_editor()` factory works.

Callers read from `DOMAINS`: `broker.py` drops `FAMILY_REQUIRED_KINDS`,
`registry.py` drops its three parallel dicts, `subagents/__init__.py` reads
`spec.time_scoped`, `main.py` reads `DOMAINS` for both its maps.

`ToolFamily` stays a hand-edited `Literal` — it is what makes the entity gate
type-check, and it is one line. Adding a domain becomes **three declarative edits**:
a `DomainSpec`, a `ToolFamily` member, an `mcp_servers.json` entry.

Pure refactor. **The existing 209 tests must pass unmodified.**

### 2. Typed payload — two layers, so the model never retypes data

A model forced to emit retrieved rows as structured output would turn them into
*output* tokens, and `Limits(output_tokens=)` is cumulative — the ceiling that
silently truncated two earlier runs. It would also admit hallucinated field values
into evidence, which `contracts/subtask.py:152-156` already forbids.

```
SubagentAnswer[P]     ← forced structured output, MODEL-authored, small
    status, error                 (envelope unchanged)
    queries_run: list[str]        the SPL it chose to run
    assessment:  P                per-family, small
    gaps:        list[ToolFamily] (unchanged)

SubtaskResult[F]      ← aggregator-facing, CODE-assembled
    ...envelope unchanged...
    findings:    F                per-family typed rows, projected from Evidence
    citation_ids, evidence        (unchanged)
```

`summary: str` is removed as the payload. Per-family models live on the
`DomainSpec`. `SiemFindings` holds result sets keyed by the query that produced
them, assembled by code from `_EvidenceCollector`'s captured output — no
per-sourcetype parser, no transcription. `VtFindings` is projected from the known
VirusTotal response shape, which `virustotal.enrich_scope()` already parses.

**Reuse:** `_EvidenceCollector` (`subagents/__init__.py:136-173`) already captures
every tool result via an `AfterToolCallEvent` hook, and `citation_ids` are already
minted in code (`:359-372`). Only the projection is new.

`queries_run` makes `index=*` a visible, checkable fact on every result rather
than something only a raw span dump reveals.

### 3. The fetch plan — the Broker's reasoning, made explicit

The schema says what shape to fill. It does not say how many steps that takes, or
when a step is done. Today nothing defines completion at all.

This is not the retired `plan_missions()`, which chose *which families* — a decision
the tool call already makes. This decomposes the goal into **bounded fetch steps
with completion criteria**, one level below family routing.

```python
class CompletionRule(BaseModel):
    requires: Literal["rows_or_confirmed_empty", "rows_required"]
    min_rows: int = 0

class FetchStep(BaseModel):
    step_id: str
    family: ToolFamily
    objective: str                # what data to retrieve, plain language
    completion: CompletionRule

class FetchPlan(BaseModel):
    steps: list[FetchStep] = Field(min_length=1)
    rationale: str
```

**Authored before dispatch, so it drives rather than narrates.** The Broker calls a
`plan_fetch` tool first; code validates the plan before anything runs — a step
naming a family whose entity gate fails is rejected up front rather than after a
billed dispatch. Each step becomes one `SubagentMission`, so a mission is finally
narrow: "DNS resolutions for coinhive.com" rather than "investigate this".

**The model authors the plan; code marks steps done.** `completion` is typed
precisely so code can evaluate it — rows present, or a confirmed-empty result
backed by a non-empty `queries_run`. `dispatched` is observed ground truth at
`broker.py:468` because a model's self-report can diverge from its behaviour;
letting it tick its own boxes would reintroduce that.

Two consequences:

- **`MAX_DISPATCHES_PER_FAMILY = 2` (`broker.py:60`) collides with this.** Three
  siem fetch steps is legitimate, not the runaway re-dispatch that cap was added to
  stop. The cap moves from per-family to per-plan: one dispatch per planned step,
  plus a bounded number of re-dispatches for steps returning incomplete.
- **`DEFAULT_BROKER_TURNS = 6` must rise** — planning costs a turn, and each step
  is a dispatch.

The subagent still plans its own *queries* within a step. Two levels: the Broker
decides what data is needed and when enough is enough; the subagent decides the SPL
that gets it.

### 4. Fetch-not-investigate prompts

Rewrite `_SYSTEM_PROMPT` in `subagents/__init__.py:94-133`: retrieve the requested
data into the given shape, report absence as a result, draw no conclusions, name no
root cause. Drop "summary: what you found, in a few sentences".

Rewrite `_SYSTEM_PROMPT` in `broker.py:108-130`, which currently says only *"decide
which domain specialists to engage"* — it never mentions fetching or a schema,
which is why the run behaved as it did.

Keep both `SECURITY CONSTRAINTS:` blocks and the delimiter defanging verbatim.

### 5. `BrokerReport` — the return contract to the Analyst

`AnalystTask` is a versioned, validated contract inbound. Nothing equivalent goes
back. Add `BrokerReport` to `contracts/`: `schema_version`, `task_id`,
`hypothesis_id`, the `FetchPlan` with each step's evaluated outcome, per-family
`SubtaskResult`s, `dispatched`, the `TaskClassification` audit record, cost, and
the `queries_run` rollup.

`main.py` prints it and writes it to a per-run directory — which also lands the
first half of evidence persistence, since `SubtaskResult.evidence` currently dies
at process exit.

### 6. `temperature` on `ModelChoice`

`_build_bedrock()` (`budget.py:178-186`) passes neither `temperature` nor `top_p`,
so everything runs at Bedrock's default of 1.0. `BedrockModel` accepts both
(`models/bedrock.py:165-166`, flowing into `inferenceConfig` at `:345-350`). There
is **no seed** — Anthropic on Bedrock offers none, so bit-identical reproduction is
unavailable at any price.

Add both to `ModelChoice` and thread them through. Set explicitly for the A/B so
both arms match.

### 7. Arm F — the flat Broker

One `Agent` holding every domain's tools directly, same `AnalystTask` in, same
schema out. With `DomainSpec` this is roughly thirty lines rather than a parallel
architecture: `Agent(tools=[*every spec's tools], ...)`. Family attribution still
works because the tool name carries it (`splunk_*` → siem, `vt_*` → vt), so code
assembles per-family findings from Evidence exactly as in Arm S.

### 8. Metrics and the bench runner

A separate `smartops-bench` entry point — **never** the default `pytest` run, since
each case costs real money and hits live Splunk.

| Metric | Source |
|---|---|
| Wall clock | root span duration |
| Cost, and cost per role | `Budget.spend_by_role()` |
| Input / output tokens | `accumulated_usage` |
| Sequential model turns | count of `chat` spans on the critical path |
| Queries run, and index scoping | the new `queries_run` field |
| Findings completeness | row counts per category |
| Routing correctness | `dispatched` vs expected families |
| Failure mode | `stop_reason`, missing structured output |

**Method: 3 runs per arm, interleaved (S, F, S, F, S, F)** so provider-side drift
hits both equally. Report median and spread, not a mean of three. If the arms
differ by less than the within-arm spread, the honest result is "no measurable
difference" — which points to the cheaper topology. Budget ~$6.

`temperature=0` is greedy decoding, not determinism — batched inference varies
float reduction order regardless. The real variance lever is fewer decision points:
14 turns of free choice becomes ~2 under fetch semantics.

### 9. After the A/B decides the topology

Sequenced last so neither is built on a layer the experiment might delete.

- **Splunk skill pack.** Vendor `superman-splunk` (MIT, ~1,700 lines across five
  references, `SKILL.md` as a routing table; their benchmark claims 73% → 96%).
  Strands has **no skill concept** — verified, zero hits in the SDK — so the
  lazy-load is ours: routing table in the system prompt, one `read_reference(name)`
  tool. Loading all five references eagerly would add ~20–25k tokens per turn × 14
  turns ≈ 350k input tokens, more than doubling the run's cost.
- **Prompt caching.** $0.89 of $1.03 was re-sent input; `cache_read_input_tokens`
  was 0 on every span. Check `SlidingWindowConversationManager` first — a rewritten
  history breaks the cached prefix.

## Open decisions

1. **SIEM findings taxonomy.** Proposed: `dns_resolutions`, `connections`,
   `processes`, `auth_events`. These fit BOTSv3's Windows + `stream:*` data and may
   be too narrow for a SIEM generally. Alternative: derive the categories from
   `EntityKind`, mirroring `FAMILY_REQUIRED_KINDS`. **Mohammed's call.**
2. **Index scoping.** `queries_run` makes `index=*` *visible*; it does not prevent
   it. Whether `DomainSpec` carries a default index, or `Scope` gains a data-source
   field, remains open and still blocks trustworthy benchmarking.
3. **Where the plan is stored.** §3 keeps it on `BrokerRequest` and serialises it
   into `BrokerReport`. A run-directory file would also work and would pair with
   evidence persistence — but a scratchpad the model *reads back* is an injection
   laundering path: goal-derived text returns to context outside the `<goal>` fence,
   in the agent's own voice. If the plan becomes a file the model re-reads, code
   must write it and re-fence model text on read-back.
4. **Completion vocabulary.** `CompletionRule` starts deliberately small. Whether
   it is sufficient is the kind of thing the A/B will expose.

## Verification

```bash
uv run pytest -q                    # 209+ passing, no credentials, no network
```

- §1 must pass the existing suite **unmodified** — it is a pure refactor.
- Zero-cost path, no model, real VT call:
  ```bash
  uv run smartops-broker --goal "reputation of coinhive.com" \
    --entity domain:coinhive.com --families vt --scripted
  ```
- One live run confirming the contract change, checking `queries_run` is populated
  and shows whether the index was scoped:
  ```bash
  uv run smartops-broker \
    --goal "Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?" \
    --entity host:BSTOLL-L --entity domain:coinhive.com \
    --since 2018-08-20T00:00:00Z --hours 24 --budget-usd 3.00 \
    --console-traces --verbose > run.log
  ```
  Always pass `--since` — all BOTSv3 data is 2018-08-20, and a relative window
  returns zero events, which looks identical to an empty domain. Do **not** pipe
  through `tail`; that is how the first run's trace was lost.
- The fetch plan must appear in `BrokerReport` with each step's evaluated outcome,
  and every dispatched mission must trace back to a planned step.
- The A/B: 3 interleaved runs per arm, compared on the §8 table.
- `python docs/compile_docs.py` must pass. Any new `docs/sessions/` file needs a
  `date` + `title` frontmatter block or it raises.

## Execution notes

- `Limits(output_tokens=)` is **cumulative** across the loop, not per call. Strands
  ends a capped run with a `stop_reason` and raises nothing, so it arrives looking
  like success — read `stop_reason` first when structured output is missing.
- Splunk tool names are `splunk__splunk_*` (the server prefixes its own tools).
- Tool calls within a turn run concurrently; wall clock is the slowest family.
- 16 commits sit unpushed on `task-broker-agent`.
