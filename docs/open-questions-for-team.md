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

**Open 2026-08-24 — who owns the Aggregator?** Parked deliberately, not decided.

The hypothesis-blind redesign
(`docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md`) splits
the domain analysts from the thing that decides SUPPORTS/REFUTES. Tier 1 landed
additively and is deliberately dark: `gather_finding()` returns a stance-free
`DomainFinding` and has zero production callers, because the component that
would consume it does not exist. Tier 2 is that component — an Aggregator that
takes the three domain findings plus the hypothesis and emits the
`HypothesisAssessment` directly, **deleting `combine()`**.

The question is that deletion. `combine()` is already a thin roll-up of
per-domain stances, which is the Aggregator's job description, and the Analyst
Agent epic is Mariam's. So Tier 2 is either the natural completion of a spec we
own, or a build into her epic — and it is not ours to assume which.

Three ways it could go, in the order they were considered: raise it with her
before building; build it and reconcile with her epic afterwards; or stop at
Tier 1 and leave Tier 2 entirely to the Analyst Agent epic.

**Resolved 2026-08-25 — none of the three, because the question was framed
wrong.** It assumed Tier 2 was one component that someone had to own. It is two,
and the boundary between them is exactly the ownership line:

- **The Analyst Agent** decides whether the findings support or refute the
  hypothesis. Not ours, not built here, and `combine()` is a local stand-in for
  it rather than a competitor to it.
- **The contract fed into it** is ours: the three domain judgements, each formed
  without sight of the hypothesis, attached to that hypothesis and handed up.

That is `HypothesisFindings`, landed additively alongside `HypothesisAssessment`.
It carries no `overall_stance` and has no combiner, and that absence is the
contract rather than an omission.

So Tier 2 as originally written — "an Aggregator that emits the
`HypothesisAssessment` directly, deleting `combine()`" — is not ours to build,
and the deletion question does not arise. `combine()` stays until the real
Analyst Agent replaces it.

**Still to raise with Mariam,** now that there is something concrete to show:
does `HypothesisFindings` carry what her Analyst Agent needs? Specifically the
`Disposition` vocabulary (`benign`/`suspicious`/`malicious`/`inconclusive`), and
whether she wants the evidence rows inline or is content resolving
`citation_evidence` against the evidence store herself.

**The anchoring premise below is separately dead** (re-measured 2026-08-25, see
that handover), but it turns out not to matter for this: blindness is worth
keeping on its own terms — an analyst told "20 auth events means malicious" and
shown 20 auth events reports malicious, and that is the prompt talking. The
re-measurement showed no *arm-level* effect between blind and shown; it did not
show that feeding a model its expected answer is safe.

**Also worth flagging when this is raised:** Tier 2's empirical case is
currently unproven. The anchoring-bias demo that justified the redesign turned
out to rest on a projector bug (`_format_auth_event` dropping
`EventCode`/`Logon_Type`), fixed since in `8512f28`/`9576a8f` and never
re-tested. That comparison is now cheap to re-run offline -- all 24 saved runs
under `.smartops/runs/` load again as of `1e893ea` -- and it should happen
before anyone commits effort to Tier 2 on either side.

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
