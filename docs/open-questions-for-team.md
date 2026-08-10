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

## For Yousef — Context Contract Template

The Planner's classification step (task → which `tool_family`s are
relevant) needs *something* to classify on. Ideally that's typed entities
(`host`, `ip`, `file_hash`, `user`, ...) coming through from his Context
Contract Template / Normalized Seed Template — that doesn't exist yet, so
the Planner currently classifies from the task's free-text goal via an LLM
call instead of a cheap deterministic rule table.

**Ask him:**
1. Rough timing on the Context Contract Template — is it weeks out or
   further?
2. When it lands, will entities be typed (e.g. `{type: "ip", value:
   "1.2.3.4"}`) or plain strings? Typed entities would let the Planner switch
   to a cheaper, deterministic rule-based classifier instead of an LLM call.
