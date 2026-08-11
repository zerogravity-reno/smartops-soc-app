# Open questions for the team — raised while scoping Subtasks Planner (2026-08-09)

Personal reference for meetings with Mariam / Yousef. Not posted to Asana —
these are checks on assumptions made solo, not decisions to hand down.

## For Mariam — Task Broker Agent

**Correction (checked against Asana directly, not assumed):** Mariam is the
*top-level* assignee on the Task Broker Agent card, but its two subtasks —
Agent Architecture & Config and Agent Development — are both assigned to
Mohammed. She's accountable for the outcome; he's the one deciding the
architecture and writing the code. So the framing below isn't "confirm my
guess at what you meant" so much as "here's what I'm building against your
card — flag it if it's not what you expected."

Her card's notes ("takes a task with no tools attached... executes the tools
for each subtask to gather the raw events... dispatch the subtask and the
results to the corresponding subagent to analyze") read, on a literal
reading, like the Broker calls the tools and hands the subagent pre-fetched
raw data. That would conflict with the already-built `SubagentMission`
contract, where the subagent self-executes its own tool calls.

Resolved as: the Broker doesn't pre-fetch raw data — the "results" it hands
over are the **resolved set of available tools/apps** for a given
`tool_family`, discovered live against the MCP gateway. Subtasks Planner
decides *which* `tool_family`(s) a task needs (the "does not plan" line on
her card means investigative/strategic planning, which stays with Analyst
Agent — not this domain classification); Tool Execution Method's
`tools_for()` is the static, in-process placeholder for what the Broker's
live MCP-gateway resolution will eventually do; the subagent still calls the
tools itself once built.

**Loop her in on:** this reading, since she owns the outcome even though the
build is Mohammed's — and whether Tool Execution Method's static registry
should stay as a permanent fallback once the real Broker exists, or gets
fully superseded by it.

**Update 2026-08-11 — the registry question resolved itself.** There is no
longer a static registry to keep or discard: `tools_for()` is now the live
resolution, reading an `mcpServers` config and resolving tools against the
server at dispatch time via `MCPClient.load_servers()` / `load_tools()`. The
hand-written client factories and the in-process placeholder are deleted. So
"static placeholder vs live Broker resolution" is moot — they are the same code
path now, and what remains ours is only the mapping of which server serves which
`ToolFamily`.

Her card's reading is unchanged and still holds: the Broker does not pre-fetch
raw events. One thing to flag to her, though, since it *is* a change from the
08-09 framing: the Broker is now an **LLM agent**, and its choice of which
domain tool to call *is* the classification — so `plan_missions()` is retired
rather than feeding it. Her "does not plan" line still reads correctly
(investigative planning stays with Analyst Agent); what moved is that domain
classification is no longer a separate deterministic step ahead of the Broker.

One genuinely open item for her: `vt` currently runs with **no subagent and no
model** — a reputation lookup needs no reasoning about what to ask, so it
executes directly and returns real evidence. Worth confirming she is happy that
some domains resolve without a subagent at all, rather than every domain waiting
for the Aug-27 subagent work.

## For Yousef — Context Contract Template

**Updated 2026-08-11: this stopped being a question and became a proposal.**

The original ask was whether entities would arrive typed (`{type: "ip", value:
"1.2.3.4"}`) or as plain strings, since the Planner had nothing to classify on
and was reading free text via an LLM call.

Rather than stay blocked on an undelivered schema, we defined the typed shape
ourselves — `Scope.entities` is now `list[Entity]` with:

```python
EntityKind = Literal["host", "user", "ip", "file_hash", "domain", "url", "process"]

class Entity(BaseModel):
    kind: EntityKind
    value: str
```

Done now because it was cheapest now: `Scope.entities` was read by zero source
files and nothing produces an `AnalystTask` yet except the CLI. The blast radius
only grows once a real Analyst populates it.

**What it bought.** A domain's *dispatchability* is now a fact rather than a
judgement — VirusTotal cannot be queried without a hash, IP, domain, or URL,
whatever a model decides. That turns the demo from four identical shrugs into
two genuinely different answers, and it discharged the dependency that was
blocking a cheaper rule-based classifier (we don't need one now, since the
Broker's tool choice *is* the classification — but the blocker is gone rather
than inherited).

**Ask him:**
1. Does this `EntityKind` set match what the Context Contract Template will
   emit? It is ours to propose and his to critique — `process` and `url` are the
   least settled members, and a mismatch is cheap to fix now and expensive
   later.
2. Anything the Analyst will want to pass that `AnalystTask` doesn't carry?
   It is deliberately minimal — `task_id`, `hypothesis_id`, `goal`, `scope` —
   and `schema_version` is on it so extension is a normal event rather than a
   break. Hypothesis prose, prior findings, and round/priority were all
   considered and left out as guesses about an Analyst that doesn't exist.
3. Still worth knowing: rough timing on the Context Contract Template, so we
   know whether to expect it to replace or extend this.
