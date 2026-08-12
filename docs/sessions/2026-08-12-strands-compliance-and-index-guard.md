---
date: 2026-08-12
title: Strands compliance, the index guard, and closing Plan A
---

# Handover — third session of 2026-08-12

## Where things stand

Plan A is **closed at 7 of 7**. The Strands layer was audited, corrected, guarded
and upgraded, on the principle that Plans B and C should be built on a dependency
whose usage is known-correct rather than assumed-correct.

- Branch `task-broker-agent`, **33 commits ahead of origin, still nothing pushed.**
- Tests **234 → 265**, green, no credentials or network needed.
- `strands-agents` moved **1.50.2 → 1.51.0**.

Two earlier entries from today cover the audit tooling
(`2026-08-12-strands-advisor-and-broker-review.md`) and the fetch-not-investigate
design (`2026-08-12-fetch-not-investigate-and-domainspec.md`). This one is what
was actually built.

## What shipped

| Commit | What |
|---|---|
| `9a0cebc` | Task 7 — `TestAddingADomainIsOneEntry`, closing Plan A |
| `9da52a2` | Evidence-collector fix + `invocation_state` |
| `3673fa0` | Deprecation guard + private-API pin |
| `72f80ea` | `IndexScopeGuard` + two comment corrections |
| `5104f82` | strands-agents 1.51.0 |

## The evidence collector was recording failures as findings

`_EvidenceCollector._record` guarded with `isinstance(event.result, BaseException)`.
That branch is **dead code**. `AfterToolCallEvent.result` is always a `ToolResult`;
failure travels on a separate `exception` field. Every failed tool call was
therefore recorded as `Evidence`, contradicting the method's own docstring.

Checking `exception` alone — the obvious fix, and the one first proposed — would
still have missed the case that matters here. An MCP tool failure maps `isError`
to `status="error"` and **raises nothing**, which is what every failed Splunk or
VT call looks like. Both are now checked, and the MCP case has its own test
precisely because it is the one a plausible fix gets wrong.

This mattered more than hygiene: Plan B §2 projects `findings` from `Evidence`,
so the defect would have been baked into the new contract.

**The tests had encoded the bug.** `test_a_failed_tool_call_is_not_recorded_as_evidence`
built an event carrying an exception *as its result* — a shape the SDK never
produces — so the test proved the code matched a fiction. `_Event` now mirrors the
real event and the case is split three ways.

## The deprecation guard, and why the obvious version would not have worked

The `invocation_state` defect was easy to fix and hard to *notice*: Strands warns
on every Broker invocation and no `filterwarnings` was configured anywhere.

The obvious guard — `error::DeprecationWarning` scoped to the `strands` module —
**would have caught nothing**, for two independent reasons found by reading the
installed source:

1. Strands is inconsistent about categories. Most calls pass `DeprecationWarning`,
   `models/bedrock.py` passes `UserWarning`, and the two `**kwargs` deprecations
   pass **no category at all**, defaulting to `UserWarning`. The exact warning
   that motivated the guard was in the missed set.
2. Strands warns with `stacklevel=2`, so the warning is attributed to *our*
   calling module. A `:strands.*` module filter matches nothing.

The config covers both categories and is deliberately unscoped, with that
reasoning recorded in `pyproject.toml`. Baseline was zero warnings, so nothing is
being suppressed.

**The guard is asserted, not assumed.** `TestDeprecationGuardIsArmed` fails when
the filter is overridden with `-W ignore::UserWarning -W ignore::DeprecationWarning`.
A filter that matches nothing reads as protection while providing none, which is
the failure mode worth testing for.

## The index guard

The 2026-08-11 run issued every SPL as `index=*`. The design spec had already
settled the fix as a `BeforeToolCallEvent` hook rather than prompt text, on the
principle that a precondition is not a judgement. Nothing had been built.

`smartops/guards.py:IndexScopeGuard` cancels a call whose search targets a
non-allowlisted index, and cancels a search that pins **no** index at all — an
unpinned search runs against whatever the token's defaults are. `cancel_tool`
carries the reason back as the tool result, which is the SDK's own idiom and
gives the model a chance to reissue rather than simply fail.

`index_allowlist` lives on `DomainSpec` because which index holds the data is a
deployment fact; `Scope` is the authorization boundary. `None` means the domain
has no index concept, distinct from an empty tuple forbidding everything. Only
`siem` declares one.

**Stated plainly, at the definition site: this is a correctness guardrail, not a
security control.** Deciding that an SPL targets only allowed indexes by string
inspection is not decidable in general — subsearches, macros and `tstats` reach
data by routes it never sees. It catches the observed failure and raises the cost
of an injected instruction; it does not stop an adversary who controls the query
string.

**The strong version costs no code and is not yet done: scope the Splunk token to
`botsv3`.** Then `index=*` returns only `botsv3` server-side regardless of what
any model writes. The hook stops a confused model; the token scope stops an
adversary. Worth doing independently.

Two properties are pinned by test rather than assumed:
- The guard is driven through a **real `HookRegistry`** with the real event type,
  so a change to the hook protocol fails the suite instead of silently disarming it.
- A cancelled call arrives as `status="error"`, so the corrected collector will
  not record a blocked query as `Evidence`. The two changes were made for
  unrelated reasons; their composition is tested, not hoped for.

No path bypasses it. `--scripted` replaces the *Broker's* model only; the subagent
still builds an `Agent` with hooks, and with no model configured the stub subagent
makes no tool calls at all.

## The 1.51.0 upgrade — the documented breaking change was not the risk

1.51.0 renames the vended `bash` tool to `shell`. **It does not touch this
codebase**: nothing here imports `vended_tools`.

The real hazard was found by scanning our own imports, not the release notes.
`tools/registry.py` imports **`_interpolate_env_vars`**, a *private* Strands
helper. Keeping it is right — reimplementing `${VAR}` interpolation would be a
second dialect that drifts — but a private symbol carries no stability guarantee,
and it is reached only on the TLS-no-verify branch, so a break would surface late
and somewhere unusual. It is now pinned by test, including that it still *raises*
on an unset variable, because `continue_on_error` depends on that and a silent
change to returning the literal would send `${VAR}` to a live MCP server.

Verified against the installed 1.51.0 tree rather than inferred from a green
suite, since the tests patch `strands.Agent` and would not notice a changed
constructor. Every `Agent` kwarg, `invoke_async`'s `invocation_state`/`limits`,
`AfterToolCallEvent.result`+`exception`, `BeforeToolCallEvent.cancel_tool` and
`HookOrder.SDK_FIRST` all survive. `Limits` gains `total_tokens` — additive, not
adopted.

## How agentic is this, actually

Graded against a rubric, justified from our own code:

| Dimension | Score |
|---|---|
| Autonomy of decision | 3/5 |
| Planning | 1/5 |
| **Completion criteria** | **0/5** |
| Adaptivity | 3/5 |
| Self-correction | 2/5 |
| Delegation | 4/5 (live path) |
| State / memory | 0/5 |
| Human-in-the-loop | 0/5 |

**A workflow with two genuinely agentic components, not yet an agent.** It stops
when it runs out of turns, not when it is done. Delegation scores honestly —
`SubagentMission` carries only goal and scope, never a pre-authored query.

Highest-leverage fix is **Plan B §3** (`FetchPlan`/`CompletionRule`): the only
change that lifts the two lowest dimensions at once, and already designed.

## Nothing was reimplemented that the SDK ships

Checked against installed source, each with a cited reason:

- **`virustotal.py` KEEP** — `make_http_request` raises on every status ≥ 400 with
  a formatted string and no structured status, and returns raw `str`, never parsed
  JSON. Recovering "was that a 404" would mean regex-parsing an exception message.
  This also **retires the old premise properly**: the decision used to rest on
  `strands-agents-tools` auth types, which is the wrong package entirely.
- **`make_investigate_tool()` KEEP** — `Agent.as_tool()` exists but has no
  `tool_context` channel, does not forward `invocation_state` into the wrapped
  agent at all, and fixes its schema to a single `input: string`. Also: the
  official samples hand-write `@tool` wrappers, so this is the idiomatic shape.
- **`budget.py` KEEP** — nothing composes reserve-then-settle admission control
  against a pool spanning multiple `Agent` instances. Corroborated from a second
  direction: neither the samples nor `evals` address cost tracking at all.

## Both research gates on Plans B and C are closed — both say "still build it"

- **`agent-sop` does not replace `FetchPlan`/`CompletionRule`.** It is a spec plus
  CLI for authoring markdown SOPs, published to agents as prompts. It standardises
  *instructions*, not code-evaluated completion.
- **`evals` does not replace `smartops-bench`.** It has `Case`/`Experiment` and
  trajectory/trace evaluators, but no A/B between two configurations and no
  repeated-run variance. Plan C §8's core requirement is exactly what it lacks. It
  may still be worth adopting for the *evaluator* half.

## Corrections to earlier entries

- The fetch-not-investigate entry says Plan A's amendments are uncommitted. They
  are not — they landed in `906f0a6`, whose subject line mentions only the
  handover. Same shape as the `CLAUDE.md` creep in `3ed9796`: a commit carrying
  more than it advertises. Worth watching as a habit.
- Its open item 4 (stale docstrings) is closed. The last real one named
  `broker.FAMILY_REQUIRED_KINDS` and now names `DomainSpec.required_kinds`.
- The strands-advisor entry's claim that "Strands ships no input-sanitisation
  helper" was corrected in code to "no *public* helper" —
  `_escape_xml_text`/`_escape_xml_attr` exist at `strands/injection/_xml.py`,
  still present in 1.51.0.

## Whole-branch review

Run before `finishing-a-development-branch`, looking for what per-task reviews miss:

- **No secrets.** `.env.example` is placeholders only, `mcp_servers.json` uses
  `${VAR}`, `.gitignore` gained `.env`, `*.pem`, `mcp_servers.local.json`.
- **`PROJECT_DOCS.md` is in sync** — regenerating produces no diff.
- **No orphaned references** to the deleted `planner.py` or `tools/mcp/`. The one
  `smartops.planner` mention is a deliberate note explaining its retirement.
- **ruff:** `backend/` is 61, down one from the 62 baseline; `contracts/` has 10
  and was never in that baseline. No new findings; the three new files are clean.
- The stray `blank` file inherited from origin is deleted.

## Open items

1. **Task 6 review is done** and passed — only two assertions changed, both pure
   symbol substitution. One undeclared change: `enricher_for`/`tools_for` moved
   from `.get(family, default)` to `DOMAINS[family]`, so an unknown family now
   raises `KeyError`. Unreachable — `ToolFamily` is a validated `Literal` and
   `test_every_tool_family_has_exactly_one_spec` pins parity — and it is the
   better behaviour for a refactor whose point is failing loudly.
2. **Scope the Splunk token to `botsv3`.** The real index control, no code.
3. **Plans B and C are unblocked.** Entity sanitization is folded into §4, where
   Mohammed's call is **both** — escape the entity values *and* move them out of
   the block headed "fixed by the system, not modifiable".
4. **Deferred, decided, and worth re-deciding against 1.51.0:** `ContextOffloader`
   for subagents (their tool results are unbounded live MCP output with only a
   prompt as mitigation), session/state persistence — 1.51.0 now ships a snapshot
   session manager with `FileSessionManager`/`S3SessionManager` and `storage` as a
   top-level `Agent` parameter, which lands directly on Plan B §5 — and
   interventions/HITL.
5. **After Plans B and C land *and* the A/B has actually been run**, Mohammed
   asked for a full refresh of the running docs across the project. Deliberately
   after the run, not before: the docs should describe the topology the experiment
   settled on, not the one that existed while it was undecided.
6. `superpowers:finishing-a-development-branch` once the above is agreed.

## Gotchas carried forward

- Strands warns with **mixed categories** and `stacklevel=2`. Any future warning
  filter must not be module-scoped and must cover `UserWarning`.
- A cancelled tool call is a `ToolResult` with `status="error"`, not an exception.
- `AfterToolCallEvent.result` is **always** a `ToolResult`; failure is on
  `exception`, and MCP failures set neither — they set `status="error"`.
- Plugins register *after* `hooks=[...]` and `AfterToolCallEvent` reverses
  callbacks, so a result-rewriting plugin runs **first**. Priority still applies
  lowest-first for reversed events, which is why the collector claims
  `HookOrder.SDK_FIRST`.
- All BOTSv3 data is **2018-08-20**. Always pass `--since`.
- Any new `docs/sessions/` file needs `date` + `title` frontmatter, and
  `python docs/compile_docs.py` must be re-run.
