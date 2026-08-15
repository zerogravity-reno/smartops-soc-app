---
date: 2026-08-15
title: The MCP failure was a race, not a teardown — and steps are judged per category
---

# Five fixes, and one diagnosis that was wrong

Branch `task-broker-agent`. **513 tests green** from the workspace root.
`strands-agents==1.51.0`.

Two issues were carried forward from the three live `botsv3_coinhive` runs of
2026-08-15, recorded in `agent_architecture.md` §8. A `/code-review` pass over
the branch found three more. All five are fixed here.

---

## The MCP diagnosis was wrong, and the wrong version was written down

**What was recorded:** `MCPClient` is a `ToolProvider` with ref-counted
consumers, so the first subagent's `Agent.cleanup()` drops the count to zero and
closes the connection under a second dispatch. Fix: hold a process-level
consumer across the run.

**Why it is wrong:** `add_consumer` and `remove_consumer` have exactly one call
site each in the whole SDK — `strands/tools/registry.py:133`, inside the
`isinstance(tool, ToolProvider)` branch of `ToolRegistry.process_tools`, and
`:700`, iterating `_tool_providers` from `ToolRegistry.cleanup()`. `tools_for()`
resolves the client itself and hands `Agent` a list of `MCPAgentTool`s, which
match the earlier `AgentTool` branch at `:121`. The client never enters
`_tool_providers`. No consumer is ever taken, so none is ever released, and the
zero-consumer teardown at `mcp_client.py:476-484` is unreachable. **A
process-level consumer would have fixed nothing** — nothing was releasing one.

**What the artifact says.** In
`.smartops/runs/botsv3_coinhive/20260815T124556942/report.json`, `results` holds
three entries in this order:

| # | task_id | status | queries | evidence |
|---|---|---|---|---|
| 0 | `…:siem:tooluse_Jrl1MJte…` | rejected | 0 | 0 |
| 1 | `…:vt:tooluse_xPjf91Yj…` | ok | 1 | 2 |
| 2 | `…:siem:tooluse_obxSwKkI…` | ok | 11 | 24 |

The rejected siem dispatch finished **first** and did nothing. A teardown under
the second dispatch predicts the opposite order, and the sticky
`_connection_failed` flag (`mcp_client.py:401-403`) would have failed the second
one too.

**What it actually was.** Strands runs a turn's tool calls under
`ConcurrentToolExecutor` by default, so a plan with two `siem` steps sends both
into `tools_for("siem")` at once — each on its own thread, since
`_load_tools_off_loop` uses `asyncio.to_thread`. `MCPClient.load_tools()` checks
`_tool_provider_started` and only then calls `start()`
(`mcp_client.py:405-409`), with a network handshake in between and no lock
across the two; `_is_session_active()` goes true as soon as `Thread.start()`
returns, before the handshake completes. The loser called `start()` on a
starting client, got `MCPClientInitializationError("the client session is
currently running")` (`mcp_client.py:334-336`), and `continue_on_error: true`
converted that into `_connection_failed = True` and `[]`
(`mcp_client.py:411-417`).

Reproduced deterministically before fixing, against unmodified code: first
caller `['splunk_search']`, second caller `[]`, sticky failure set.

**Fix.** `warm_mcp_clients()` resolves every built client once at startup, called
from `main._run()` and `bench._run()`, so no dispatch ever reaches the racy
branch. `_load_tools_off_loop` also takes a per-client lock, so the property
holds for a caller that never warmed — forgetting to warm is exactly how this
failed the first time, and warming being the *only* defence would leave a third
entry point free to reintroduce it. `PROCESS_CONSUMER` is claimed on each client
as well; it does not fix this, and says so in its own docstring, but it closes
the teardown path before someone passes a client straight into
`Agent(tools=[...])`.

**Ruling:** a mechanism that has been read in the SDK beats a mechanism that
merely explains the symptom. The wrong version had been written into a docstring
(`registry.py`), the architecture document, and the issue list, from where it
would have been re-derived indefinitely. Both now carry the correction and the
reason it was believable.

---

## A step is judged against the category it asked for

`CompletionRule` gains `categories: list[CimCategory]`. When set, `evaluate_step`
counts only those buckets from `_finding_counts()`. Empty — the default — counts
everything, which is the only sensible rule for `vt`, whose findings are not
bucketed this way.

This needed no new machinery: `CimCategory` is already exactly the field names of
the `SiemFindings` buckets (`contracts/findings.py:21`), which is what
`_finding_counts` already yields.

Two decisions inside it:

- **`uncategorised` never satisfies a named category.** It is the honesty bucket
  for rows the subagent never tagged. Letting it stand in for a category would
  rebuild the false-completion bug one layer up.
- **A category nobody retrieved into is not confirmed-empty.** `_finding_counts`
  reports a bucket that ran and returned nothing (it holds a zero-row
  `ResultSet`) and omits a bucket nobody touched, so presence is the code-side
  evidence that the question was asked. Without this, a step scoped to
  `dns_resolutions` whose subagent only returned process events would score as
  "we looked for DNS and it is not there" — the same false negative in a new
  place. "We queried DNS and found nothing" is a finding; "we never queried DNS"
  is a gap.

The Broker prompt now tells the planner to split `siem` by CIM category and set
`completion.categories` per step. The contracts already permitted this —
`DISPATCHES_PER_PLANNED_STEP = 2` under `MAX_PLANNED_DISPATCHES_PER_FAMILY = 6`,
and `DEFAULT_BROKER_TURNS = 11` was already sized for three siem steps. What was
missing was a reason to split and a way for code to judge the result.

**Unmeasured, deliberately.** Each step is its own mission, so its own system
prompt and tool schemas. `report.json` persists only `total_spend_micro_usd`, not
the ledger, so prompt-cache engagement could not be read back from the three
existing runs. If caching is not engaged this raises input cost. Needs `--runs 3`
before and after; the trade is evidence-first, not assumed.

---

## The index-scoping metric could not fail

`bench.check_index_scoping()` scored correctness by calling
`IndexScopeGuard._reject_reason` — the guard's own predicate — over
`queries_run`. Every query that actually executed passed that predicate by
construction, and `_EvidenceCollector._record` drops failed calls, so a
guard-cancelled query never reached `queries_run` either.
`index_scoping_correct_pct` was therefore ~always 100%, while the entire reason
it exists is the 2026-08-11 run in which every SPL was `index=*`.

Both halves fixed:

- **It scores attempts, not successes.** `IndexScopeGuard` now records what it
  cancelled, `SubtaskResult.blocked_queries` carries it, and the metric counts
  it. A blocked query was previously invisible to everyone, including an analyst
  reading the report.
- **It no longer consults the guard.** The rule is implemented in `bench.py` so
  the two can disagree — which is the only condition under which measuring is
  worth anything. Pinned by a test that makes `_reject_reason` raise.

Also: the `IndexScopeGuard` docstring still claimed the rule was "require a
literal allowlisted `index=` on anything that is a search". The code had been
relaxed to accept a CIM predicate instead, and since `_LOOKS_LIKE_SEARCH` matches
`sourcetype=`, the guard trips and immediately waves through the exact query
shape the siem prompt tells the model to write. The docstring now states the
three real rules and says plainly what rule 2 concedes. `_CIM_PREDICATES` moved
to module level, where every other pattern in that file lives.

---

## Two smaller repairs

**`replay.py` was broken against the current layout.** `load_evidence_from_run()`
resolved `<base>/<run_id>/evidence.json`, but `save_run_artifacts()` has written
`<base>/<task_id>/<stamp>/` since `cfeae8a`, so every call for a real case raised
`FileNotFoundError`. It also hardcoded `.smartops/runs` while the writer honours
`SMARTOPS_RUNS_DIR`, so with that set, reader and writer looked in different
trees. Now resolves a case id through `latest.txt` (falling back to the highest
stamp, which sorts correctly because stamps are zero-padded `%Y%m%dT%H%M%S%f`)
and defaults `base_dir` through the same env var as the writer. Verified against
the real artifacts on disk.

**The recovery turn was unbudgeted and hid its own cause.** The bounded "report
what you have" call added in `f081ec8` was issued with a second full
`max_output_tokens` that the reservation never estimated, and `settle()` debits
the shortfall unconditionally — so a run that turn-capped on every family could
drive the shared budget negative and refuse *unrelated* later families with
`BUDGET_REFUSAL_ERROR`, surfacing a cost overrun as a spurious domain failure. It
is now capped at `RECOVERY_OUTPUT_TOKENS = 4000` and included in the reservation
up front. It also overwrote `stop_reason` with its own `turns=1` cap, so the
branch that exists to distinguish `limit_turns` from `limit_output_tokens` from
"the model never answered" reported `limit_turns` almost every time. The first
call's reason is now what gets reported.

---

## Not done

- **Mid-flight evaluation.** There is no checkpoint, no interrupt and no
  mid-flight assessment anywhere in the tree; the only surface is
  `BeforeToolCallEvent` + `event.cancel_tool`. Steps are now independently
  evaluable *between* missions, which is a smaller and different thing.
  Interrupting a running loop needs the mission boundary restructured.
- **`depends_on` scheduling.** The field is on `FetchStep` and nothing walks it —
  the only code that did was the deleted `broker_flat.py`, which is why
  `BrokerReport.plan_repairs` is always 0. Noted so it is not mistaken for live
  machinery.
- **The duplicated rejection message.** "configured but returning no tools" is
  verbatim in both `broker.py` and `subagents/__init__.py`. The cause is fixed,
  the duplication is not.
- **Bench CLI tests build real `MCPClient`s** from the on-disk config, which is
  where the pre-existing `_set_close_event was never awaited` warning comes from.
  Present before this work and unrelated to it.
