---
date: 2026-08-12
title: Plan B begins — the typed payload replaces prose, and SDD takes over execution
---

# Handover — fourth session of 2026-08-12

## Where things stand

Plan B is **started, not finished**. Its first two work items are done: findings
are now typed rows assembled by code, and `summary` — the field that made prose
the only possible shape — is gone from both contract models.

- Branch `task-broker-agent`, **37 commits ahead of origin, still nothing pushed.**
- Tests **265 → 294**, green from the repo root.
- Execution has switched to **subagent-driven development**; the ledger is at
  `.superpowers/sdd/validated-jumping-sunbeam/progress.md` (gitignored, survives
  on disk). **Read it before doing anything** — it is the recovery map.

Plans B and C are numbered as Tasks 1–9 in
`C:\Users\pcc\.claude\plans\validated-jumping-sunbeam.md`. Tasks 1 and 2 are
complete. **Task 3 is next and has not been started.**

## What shipped

| Commit | What |
|---|---|
| `77fe40f` | Tasks 1+2 — typed payload, CIM findings, projection |
| `689eaee` | Task 1 gap — `DomainSpec.assessment_model`/`findings_model`, factory wired |
| `219fc47` | Task 1 gap — assessment propagated onto `SubtaskResult` |

## The contract change

`SubagentAnswer.summary` was the only field findings could go in, so prose was
the only available shape — and prose became narrative, which became a conclusion
that belongs to the Analyst. That is why the 2026-08-11 run named `chrome.exe`
PID 9752 as cryptomining.

Two layers now. The model authors `queries_run` and a small `assessment`; **code**
assembles `findings` from what the tools actually returned. Neither half can forge
the other: a model that never sees the rows cannot invent them, and code that
never reads the prompt cannot be talked into re-categorising.

SIEM findings adopt **Splunk CIM names** — Network Resolution, Network Traffic,
Endpoint→Processes, Authentication. The bucket comes from the category the model
tagged its *own query* with, which it knows without inspecting a row, so there is
no per-sourcetype parser to drift from Splunk's field semantics.

## Four traps found, all verified against installed 1.51.0

Each would have failed later and more expensively than it did.

1. **A parameterized pydantic generic cannot be handed to
   `structured_output_model`.** Strands names the structured-output tool from
   `model.__name__` with no sanitisation, so `SubagentAnswer[SiemAssessment]`
   produces a tool name containing brackets — and Bedrock requires
   `^[a-zA-Z0-9_-]{1,64}$`. This fails at the provider, not in tests.
   `make_answer_model()` builds a concrete per-family model instead
   (`SiemAnswer`, `VtAnswer`, …), mirroring `make_investigate_tool()`.
2. **`findings` and `assessment` both need `SerializeAsAny`.** With a plain base-class
   annotation, pydantic dumps only the base's fields — verified: a populated
   subclass serialises to `{}`. Silently. Every row would have vanished on the way
   to `BrokerReport`, and the A/B would have compared empty payloads.
3. **`from_answer()` could not keep splatting `**answer.model_dump()`.** That worked
   only while both models carried identical field names; with `assessment` on one
   and `findings` on the other, `extra="ignore"` drops the mismatch silently — the
   same failure the `gaps` docstring has warned about since the contract was
   written. It now maps fields explicitly.
4. **`summary` was doing two jobs and only one was the problem.** Exactly one call
   site was model-authored; the other fifteen were code-authored status reasons
   like "no vt-queryable observable in scope". Those moved to `reason`, which is
   code-only and **required for `REJECTED`** — an unexplained rejection is
   indistinguishable from a bug.

## Two deliberate additions beyond the spec

Both are honesty mechanisms, and both are worth keeping or arguing with explicitly:

- **`SiemFindings.uncategorised`.** Not a fifth CIM category. When the model's
  reported query stops matching the one it actually ran, the rows land here rather
  than being dropped — they were retrieved and paid for, and a full bucket is a
  signal that reporting has drifted from behaviour.
- **The digest sends counts, not content.** `_digest()` now renders row counts per
  category plus the code-authored `reason`. Putting retrieved rows back into a
  model's context is exactly what the two layers exist to prevent, and there is a
  test asserting no row reaches it.

## The pre-flight scan caught a half-wired task

Task 1 had been marked complete before subagent-driven development was invoked.
The SDD setup scan found it was not: `make_answer_model()` was built and exported
but **never called**, `DomainSpec` never gained `assessment_model`/`findings_model`,
and the subagent still forced the bare `SubagentAnswer` base — which has no
`assessment` field at all. The model was never actually being asked for one.

That is now closed. It is recorded because the lesson generalises: a factory that
exists, is exported, and is tested still does nothing until something calls it,
and a green suite does not notice.

The implementer then flagged that the assessment reached structured output and was
discarded, because `SubtaskResult` had no field for it. Correct, and fixed —
forcing a model to author a field that reaches nobody costs output tokens on every
call and is load-bearing for Task 3's completion rules.

## ⚠️ Outstanding before Task 3

**The formal task review for Task 1 was never run.** The owner asked to stop after
Task 1 finished, so only controller-side mechanical verification happened: 294
green, factory wired at `subagents/__init__.py:485`, all four families producing
Bedrock-valid tool names, ruff 72 against a 71 baseline. That is **not** a review.

Run the task review over `BASE=77fe40f HEAD=219fc47` before or alongside Task 3,
using the SDD skill's `task-reviewer-prompt.md`.

## Controller rulings recorded during setup

A batched pre-flight question went unanswered, so these were decided by the
controller and are open to being overridden:

- **Task 4 contradicts itself** — "keep the delimiter defanging **verbatim**"
  versus "strengthen `_neutralize_delimiter()`". Ruling: "verbatim" scopes the
  prompt rewrite (do not *lose* the `SECURITY CONSTRAINTS:` blocks or the defanging
  while rewriting), and strengthening the function is separately mandated by the
  same task. Both get done.
- **The plan's Task 1 text says `queries_run: list[str]`.** Stale. The owner later
  chose per-query CIM tagging, so the shipped shape is `list[QueryRun]`. The
  owner's decision governs.

## What remains

| Task | Work |
|---|---|
| 3 | **B3** — `FetchPlan`/`FetchStep`/`CompletionRule`, `plan_fetch` tool, code-evaluated completion |
| 4 | **B4** — both prompts to fetch semantics; entity escaping **and** moving entities out of the system-vouched block. See the scope note below: this is far more lopsided than it reads. |
| 5 | **B5** — `BrokerReport`, written to a per-run directory |
| 6 | **B6** — `temperature=0.3`, `top_p` unset |
| 7 | **C1** — Arm F, the flat Broker |
| 8 | **C2** — `smartops-bench`, never the default pytest run |
| 9 | **C3** — the live A/B: 3 runs per arm, interleaved, ~$6 |

Task 3 is the highest-leverage item in the whole plan: **nothing in the system
defines completion today**, which is why the SIEM subagent used 14 of 14 turns and
stopped because it ran out rather than because it was done. It also collides with
`MAX_DISPATCHES_PER_FAMILY = 2`, which must move from per-family to per-plan, and
requires raising `DEFAULT_BROKER_TURNS = 6` since planning costs a turn.

## Notes for whoever runs the A/B

- Credentials are present in this environment: provider resolves to `bedrock`,
  `SPLUNK_MCP_URL` / `SPLUNK_TOKEN` / `VT_API_KEY` all set, and
  `SMARTOPS_MCP_TLS_NO_VERIFY` is on.
- The owner asked for the running project docs to be refreshed **after** Plans B
  and C land *and* the A/B has actually been run — not before, so the docs describe
  the topology the experiment settled on rather than the one that existed while it
  was undecided.
- Report **median and spread, not a mean of three**. If the arms differ by less
  than the within-arm spread, "no measurable difference" is the honest answer and
  points at the cheaper topology.

## Added by a state-review pass over the branch

Three things verified directly against the tree at `ac03a64` (38 commits, 294
green), none of them recorded elsewhere.

### `CLAUDE.md` is stale on the Strands pin — fix this first

`CLAUDE.md:20` still reads *"Pinned to `strands-agents==1.50.2` exactly"*, while
`backend/pyproject.toml:18` and the installed dist-info are both **1.51.0**. That
file is the first thing an agent reads for ground truth, and it now names a
version that is neither pinned nor installed. Anything reasoning from it will
verify APIs against the wrong tree. One-line fix, disproportionate cost if missed.

### Task 4's two halves are not the same size

The **subagent** prompt has already been converted to fetch semantics as a side
effect of Tasks 1–2. `subagents/__init__.py` now asks for `queries_run` and
`assessment` and states *"Do NOT restate the rows — they are captured for you."*
No `summary` request remains.

The **Broker** prompt is untouched. `broker.py` still opens *"You are the Task
Broker… decide which domain specialists to engage by calling their tools"* and
never mentions fetching, a schema, or what it returns to the Analyst. That prompt
is the reason the 2026-08-11 run behaved as it did — the contract made prose
possible, but the prompt is what asked for an investigation.

So Task 4 is mostly a Broker-side job plus the entity-sanitization work, not a
symmetric rewrite of two prompts.

### Budget the review policy for Tasks 3–9 before starting

Plan A ran under subagent-driven development at **13 subagents / ~694k tokens for
7 tasks**, because the skill mandates one implementer *plus* one reviewer per
task — roughly double the naive cost. One task cost triple the rest on its own,
from a fix round caused by a defect in the plan text rather than the code.

Tasks 3–9 are seven more tasks. The owner interrupted Plan A over exactly this,
so decide the policy up front rather than mid-run: full reviews throughout, or
reviews only for the tasks where a green suite is not the real gate. Task 3
(`FetchPlan`) and Task 9 (the live A/B) are the two where a review earns its cost;
Task 6 (`temperature=0.3`) is a two-line change that does not.

Related, and cheap to apply when authoring the remaining tasks: **before mandating
that a symbol be deleted, grep the tests for it.** Plan A carried three defects of
one shape — asserting a property after checking the specific thing I had thought
of rather than the thing that was actually true (an import cycle traced through
one file but not the package `__init__`; two deletions mandated while test edits
were forbidden, where the tests monkeypatched the very symbols). Two of the three
cost a fix round; the third was caught pre-dispatch by one grep.

## Gotchas carried forward

- A parameterized pydantic generic is **not** usable as a Strands structured-output
  model. Build a concrete named model.
- Any polymorphic pydantic field needs `SerializeAsAny`, or subclass fields
  serialise to `{}` with no error.
- All BOTSv3 data is **2018-08-20**. Always pass `--since`.
- Splunk tool names are `splunk__splunk_*`.
- A cancelled tool call is a `ToolResult` with `status="error"`, not an exception.
- Strands warns with **mixed categories** and `stacklevel=2` — the suite's
  `filterwarnings` covers `UserWarning` too, deliberately, and is unscoped.
- Any new `docs/sessions/` file needs `date` + `title` frontmatter, and
  `python docs/compile_docs.py` must be re-run.
