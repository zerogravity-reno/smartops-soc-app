---
date: 2026-08-12
title: Fetch not investigate — reading the BOTSv3 run properly, and the DomainSpec refactor
---

# Handover — end of 2026-08-12

## Where things stand

The 2026-08-11 live run was re-examined against its surviving trace, three
claims about it were corrected, and the conclusion changed: the Broker's problem
is its **contract**, not its topology. A design spec and a three-plan
decomposition now exist, and the first plan is 6 of 7 tasks done.

- Branch `task-broker-agent`, **27 commits ahead of origin, nothing pushed.**
- Tests **209 → 234**, green, no credentials or network needed.
- `uv run pytest -q` from the repo root is the correct command.

> ⚠️ **A second session ran against this repo at the same time** — the one that
> produced `docs/sessions/2026-08-12-strands-advisor-and-broker-review.md`, the
> `strands-advisor` agent and the `strands-api-ground-truth` skill. Read that
> entry alongside this one; the two overlap and one of its findings is now stale
> because of work recorded here. See "Collision with the parallel session" below.

## What the trace actually said

Three things the previous handover asserted were checked against the surviving
span dump and are **false**:

1. **The subagents did not call each other's tools.** Every `splunk_*` span
   carries `tool_family=siem`; the `vt_lookup_domain` span carries
   `tool_family=vt`. `tools_for()` builds each family's toolset from only that
   family's servers, and `_assert_no_shared_servers()` forbids sharing. The
   apparent crossover was a **rendering artifact of the uncommitted
   `build_report.py`**, which indents by span depth and sorts by start time — so
   two *concurrent sibling* subtrees interleave and read as one agent's work.
   Both subagent `invoke_agent` spans also render as the same unlabelled string.
2. **`FamilyToolbox` was never built.** It was cut in review on 08-11.
3. **The mission contract *is* used.** `SubagentMission` is built per dispatch
   and `SubtaskResult` collected; the span ids prove it. What is missing is any
   *rendering* of it — `_print_outcome` shows status, summary, gaps and error
   and nothing else, so per-mission detail exists in memory and dies at exit.

### Where the 137 seconds went

Of the SIEM subagent's 115.2s: **~23s** was Splunk answering, **~91s** was the
model thinking across 14 sequential `chat` spans. Neither agent came close to a
context limit — the Broker used 5,786 tokens of a 1M window; the subagent's
largest single call was ~40–50k. **Latency and cost are set by the number of
sequential model turns**, not by context size and not by who issues the tool
calls.

Strands already runs one turn's tool calls concurrently, so **parallelism is a
property of the event loop, not of subagents**. Subagents overlap the *reasoning
chains* of different domains, worth ~10% here.

## Decisions taken (Mohammed's)

| Decision | Note |
|---|---|
| The Broker **fetches**, it does not investigate | It returned a narrative naming `chrome.exe` PID 9752 as cryptomining. That conclusion is the Analyst's. |
| Root cause is the **contract**, not the topology | `SubagentAnswer.summary: str` is the only place findings can go, so prose was the only possible shape. |
| **Keep the subagents**, but prove it | Decided by an A/B against a flat Broker, not by argument. |
| Payload typed **per family**, two layers | Model authors `queries_run` + a small assessment; **code** assembles the rows from `Evidence`. The model never retypes data it already retrieved. |
| The **fetch plan comes back** — as a tool, not deterministic code | The Broker plans how many steps and what marks a step complete. Overruled my "the schema is the plan" argument; see below. |
| Findings taxonomy adopts **Splunk CIM** names | Network Resolution, Network Traffic, Endpoint→Processes, Authentication. Not invented, not derived from `EntityKind` (they are orthogonal, not hierarchical). |
| Index scoping lives on **`DomainSpec`**, enforced by a hook | Not on `Scope` — which index holds data is a deployment fact, and `Scope` is the authorization boundary. |
| **`temperature=0.3`**, `top_p` unset | 1.0 (the current silent default) is far too creative for retrieval. |

**On the planner.** I argued it was YAGNI because "under fetch semantics the
schema is the plan". That was wrong and was overruled. A schema says what shape
to fill; it does not say how many steps that takes or when a step is done — and
**nothing in the system defines completion at all today**. The SIEM subagent used
14 of 14 turns and stopped because it ran out, not because it had what was asked
for. This is *not* the retired `plan_missions()`, which chose *which families* —
a decision the tool call already makes.

## Documents

- **Design spec:** `docs/superpowers/specs/2026-08-12-task-broker-fetch-not-investigate-design.md`
  (commits `fd0304f`, `e6f5945`). Nine work items plus a tuning section.
- **Plan A (in progress):** `docs/superpowers/plans/2026-08-12-domainspec-refactor.md`
  (commit `a4eaa7a`, since amended — **amendments are uncommitted**).
- **Plans B and C: not written yet.** B covers spec §2–§6 (typed payload, fetch
  plan, prompts, `BrokerReport`, temperature); C covers §7–§8 (flat arm, bench
  runner, the A/B). They were deliberately deferred until Plan A lands, because
  B's task boundaries depend on the final shape of `DomainSpec`.

## Plan A status — 6 of 7 tasks

Goal: collapse ten per-family registration sites across five files into one
`DomainSpec`, so adding a domain is three declarative edits.

| Commit | Task |
|---|---|
| `548e099` | 1 — `domains.py`: `DomainSpec` + `DOMAINS` registry, 19 parity tests |
| `970213b` | 2 — `make_investigate_tool()` factory; old names kept as derived aliases |
| `3ed9796` | 3 — `registry.py` reads `DOMAINS` (⚠ also swept in `CLAUDE.md`) |
| `d769560` | 4 — subagents take time-scoping from the spec |
| `06356e3` | 5 — CLI takes the family list and tool map from the registry |
| `8481f61` | 6 — migration aliases deleted, test references retargeted |

**Tasks 1–5 reviewed clean. Task 6 is committed and self-reported but NOT
independently reviewed — that is the first thing to do.** Task 7 (a test proving
"adding a domain is one entry") is not started.

Task 6's own report claims: 234 passing, `git diff backend/tests/` is
reference-only with no assertion changed, and `ruff` clean of *new* issues (62
pre-existing findings remain, all outside the four edited files). Treat that as
the implementer's claim, not as a review — it has not been checked by anything
other than the implementer that wrote it.

The SDD ledger with every finding and ruling is at
`.superpowers/sdd/2026-08-12-domainspec-refactor/progress.md` (gitignored,
survives on disk).

### Three plan defects, all mine

Recorded because they are the same mistake three times — verifying the specific
thing I thought of rather than the thing that was actually true:

1. **Claimed no import cycle.** I checked `virustotal.py`'s imports but not
   `smartops/tools/__init__.py`, which eagerly re-exported `tools_for` and made
   `registry → domains → tools.native.virustotal` re-enter `registry`. Fixed by
   gutting that re-export — nothing imported it.
2. **Mandated deleting the three registry dicts while forbidding test edits.**
   `test_registry.py` and `test_broker.py` monkeypatch them. Fixed by keeping
   them as eagerly-derived views until Task 6, matching Task 2's pattern.
3. **Would have made `time_scoped` a required argument**, breaking three
   `_system_prompt_for(family, turns=N)` calls. Caught pre-dispatch; it is now an
   optional override defaulting to the registry lookup.

## Open items

1. **Review Task 6** (`8481f61`). It is the only task allowed to touch existing
   tests, and only their imports, symbol references and monkeypatch targets — **no
   assertion may have changed**. Verify with `git diff a4eaa7a..HEAD -- backend/tests/`.
   The trap it had to avoid: modules do `from smartops.domains import DOMAINS`,
   so `monkeypatch.setattr(domains, "DOMAINS", ...)` silently does nothing —
   only `setitem` on the shared dict works, with `dataclasses.replace` because
   `DomainSpec` is frozen.
2. **Task 7** — append `TestAddingADomainIsOneEntry` to `test_domains.py`. It is
   one test class and a suite run; it does not need a subagent.
3. **`CLAUDE.md` was swept into `3ed9796` by a subagent** — scope creep the Task 3
   review missed, because I asked it to check for test edits but not for
   unrelated files. Worth adding "no files outside the task's list" to future
   review prompts. Its stale test-command section has since been corrected and
   committed separately; the correction is verified (234 passing from the repo
   root, and root `pyproject.toml:13-15` does carry `[tool.pytest.ini_options]`).
4. **Stale docstrings referencing deleted names** in `subagents/__init__.py` and
   `test_domains.py` — flagged by Task 6's implementer but left alone, correctly,
   as outside that task's permitted edit scope. Worth a sweep before the final
   review: `git grep -n "FAMILY_REQUIRED_KINDS\|_BY_FAMILY\|_TIME_SCOPED_FAMILIES"`
   should now return only prose.
5. **Two deferred cosmetic minors:** a stray blank line at `registry.py:71-72`
   and a duplicate blank line at `subagents/__init__.py:73-74`.
6. **Final whole-branch review** once Task 7 lands, then
   `superpowers:finishing-a-development-branch`.

## Collision with the parallel session

Both sessions edited this repo concurrently. Reconciling them:

- **`CLAUDE.md` was created by the *other* session**, not this one. My Task 3
  subagent then swept it into `3ed9796` unintentionally. Its uncommitted
  test-command correction — which that session's open item 5 asks someone to
  review — **is now committed** as `7533338`, independently verified here (234
  passing from the repo root; root `pyproject.toml:13-15` does carry
  `[tool.pytest.ini_options]`). That item is closed.
- **Its `broker.py` line numbers are now stale.** It cites `broker.py:519-522`,
  `:522`, `:527-528`, `:530`, `:633-638`. Tasks 2 and 6 here rewrote that file —
  the four hand-written `investigate_*` functions and `FAMILY_REQUIRED_KINDS` are
  gone. **Re-locate its findings by content, not by line number.**
- Its note that the module-level aliases are "temporary pending the DomainSpec
  migration" is resolved: Task 6 deleted them.
- **Its four `broker.py` findings still stand and are not fixed here.** Two
  matter:
  - `invoke_async` passes `smartops=request` through the **deprecating `**kwargs`
    channel**; `invocation_state={"smartops": request}` is the supported form.
    This fires a warning on every Broker invocation and nothing surfaces it.
  - **Entity values reach the model unsanitized**, rendered raw inside the block
    headed "fixed by the system, not modifiable" — so an injected instruction in
    an entity value lands in the part of the prompt the system prompt vouches
    for. `EntityKind` includes `url`, `domain` and `process`. The same shape is
    in `subagents/__init__.py`.
- It reports the Strands org restructured: `sdk-python` no longer exists (it is
  `harness-sdk`, tags `python/vX.Y.Z`), the `docs` repo is **archived**, and
  **1.51.0 is published** while we are pinned to 1.50.2. That supersedes the
  cruder version of this finding in the next section.

## Before writing Plans B and C — check what already ships

I used the installed SDK source at `.venv/Lib/site-packages/strands/` as ground
truth, which is correct for *"does this API exist in 1.50.2"* and those answers
stand. But I used it for a question it cannot answer — *"has this already been
built?"* The `strands-agents` GitHub org has repos that are **not** in the pip
package, two of which land on work the spec has us hand-rolling:

- **`evals`** — an evaluation framework for agents. Spec §8 builds
  `smartops-bench` from scratch. Evaluate this first.
- **`agent-sop`** — "natural language workflows for complex, multi-step tasks
  with consistency and reliability". Close to §3's `FetchPlan`/`CompletionRule`.
- **`samples`** — the idiomatic-patterns reference.
- **`tools`** — confirms `strands_tools` is a separate, uninstalled package.

Plan A is unaffected (it refactors our own code). **Plans B and C should not be
written until both `evals` and `agent-sop` have been read.**

## The toolbox

Not dropped, but nothing in Plans A–C needs it, and the reason it was cut still
holds — `Agent(tools=[*native, *clients])` already gets the ref-counted
lifecycle. What changed is that a real job for it now exists: `mcp_clients()`
documents that each mission reconnects instead of sharing one MCP session. That
is a better justification than tool grouping, which `tools_for()` already does.
Hold it until the A/B says whether the subagent layer survives.

## Cost

This session ran 13 subagents totalling **~694,000 tokens**, plus the main
conversation. Task 3 cost roughly triple the others because of a fix round caused
by defect (1) above. Mohammed asked for token economy and I still ran one
implementer *plus* one reviewer per task; the cheaper structure for mechanical
tasks is inline execution, and Task 7 in particular does not warrant an agent.

## Gotchas carried forward

- `Limits(output_tokens=)` is **cumulative** across the loop, not per call.
  Strands ends a capped run with a `stop_reason` and raises nothing, so it
  arrives looking like success — read `stop_reason` first.
- All BOTSv3 data is **2018-08-20**. Always pass `--since`; a relative window
  returns zero events and looks identical to an empty domain.
- Splunk tool names are `splunk__splunk_*`.
- Tool calls within a turn run concurrently; wall clock is the slowest family.
- Do **not** pipe a trace run through `tail` — that is how the first run's trace
  was lost. The surviving one is at
  `…/97164914-21d6-4547-b8ad-54d54781625d/scratchpad/trace-run.log` with
  `timeline.txt` alongside it.
- Any new `docs/sessions/` file needs `date` + `title` frontmatter or
  `docs/compile_docs.py` raises.
