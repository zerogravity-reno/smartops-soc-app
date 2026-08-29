---
date: 2026-08-30
title: The planner never worked, and the first live trace is what found it
---

Continues `2026-08-30-docs-back-in-step.md`. Six commits, `48cc35f..1be9b5a`,
**826 tests passing**, 31 doc anchors verified, 0 stale.

The session started as "add OTel spans to the analyst tier" and turned into a bug
hunt, because the first end-to-end trace this system has ever produced showed the
Broker's planning tool failing six times in a row.

## THE HEADLINE: `plan_fetch` had never succeeded on the live path

Every real call failed with:

    AttributeError: 'dict' object has no attribute 'step_id'

Strands validates the model's JSON against the generated schema and passes what
that produces. For a `list[FetchStep]` parameter, what arrives is a list of plain
**dicts**. `FetchPlan(steps=steps, ...)` is what coerces them — so `plan.steps`
are typed and the `steps` argument is not. Two sites read the argument: the
`step_outcomes` loop and the `minted` summary string.

The comment two lines below the loop already said the step definition should come
from the new plan. The code didn't do it.

**What it cost, every run:** the model planned, got a framework error tool result,
re-planned, failed identically — six of eleven turns gone — and then `broker_task`
fell back to a *synthesized* plan built from the families the model **claimed**
rather than any it planned. The whole planning subsystem was therefore dead in
production: per-step `CompletionRule`s, `StepOutcome.evaluated`,
`DISPATCHES_PER_PLANNED_STEP`, `MAX_PLANNED_DISPATCHES_PER_FAMILY`. It also
explains duplicate `investigate_siem` dispatches against an unreachable Splunk.

Measured on the same command, before and after:

| | before | after |
| :--- | :--- | :--- |
| `plan_fetch` calls | **6, all ERROR** | **1, OK** |
| spans | 50 | 38 |
| step outcomes | `step_id: None` ×4 | 4 real steps, rules evaluated |

```
vt_domain_rep        completed      rows=2  dispatches=1
vt_ip_rep            completed      rows=2  dispatches=1
siem_dns_coinhive    NOT completed  rows=0  dispatches=1
siem_connections_ip  NOT completed  rows=0  dispatches=1
```

The siem pair is *correct*: Splunk was unavailable, and "evaluated but not
completed" is precisely the state the `evaluated` field exists to distinguish from
"nobody tried".

**Why 826 tests missed it.** Every test called `plan_fetch` directly with
already-built `FetchStep` objects, where the attribute access works. **Nothing
crossed the boundary the model's input crosses.** That is the real gap.
`test_broker_tools_through_strands.py` now invokes through
`DecoratedFunctionTool.stream()` with the raw dict payload taken verbatim from the
failing run — and it earned its keep immediately, catching that the first one-line
fix was incomplete.

**Why it hid so well.** Runs still produced a report and honest-looking outcomes.
The only tell was `step_id: None` in `report.json`, which reads as a schema quirk.
`--verbose` would have shown it on day one; at the default log level the refusal
warnings are suppressed.

## `note` had guidance on one class out of four

Chasing two `VtAnswer` structured-output rejections in the now-clean trace. Same
class of problem, opposite cause — not our code misreading the model, our schema
failing to tell it anything.

`note` was declared four times, once per family subclass, with `Assessment` itself
having no such field. Only `SiemAssessment`'s copy had a description. The other
three were `Field(default="", max_length=400)`: identical in every *enforced*
respect, missing the only part that does any work.

So the vt subagent, shown a bare capped string, wrote a 500-character analysis of
what the reputation data *meant*, was rejected twice, and truncated on the third
try. The rule it broke — *"NOT a summary of findings: strictly a remark about
retrieval. Do not describe what the data means."* — was written down the whole
time, on a sibling class it does not inherit from.

Declared once on `Assessment` now. A test asserts `note: str` appears exactly once
in the source, because four identical copies is *how* three of them lost the
description, and a redeclaration is invisible in review.

## Tracing: the analyst tier had none

The Broker and fetch subagents are Strands `Agent`s and get spans free. The three
analysts drive a Bedrock custom-imported model through raw `invoke_model`, so a
trace covered the fetch half and went dark where the judgement is formed.

Added `telemetry.analysis_span` (the analyze root) and `analyst_span(domain)`,
with disposition, confidence, counts and tokens under OTel's GenAI convention
names. **`reasoning_trace` deliberately not on a span** — span content goes to
whatever collector is configured and Strands' redaction is opt-in and OFF.

**Two roots per run, not one, and that is the design.** `investigation_span` opens
inside `broker_task()` and closes before `gather()` runs; unifying would mean
hoisting it into the CLI, putting a tracing concern in the entry point and leaving
`broker_task` untraced when called as a library by bench and replay. Confirmed
live — the two traces join on `task_id`, `hypothesis_id` **and `run_id`**.

`run_id` was the gap. Both roots carried the first two, and **neither identifies a
run**: `botsv3_coinhive` has four runs under one `task_id`. `record_run_id()` now
stamps the fetch root after `save_run_artifacts()` mints the directory — a late
stamp, because nothing upstream can know the name yet.

## The reasoning trace was being discarded

`DomainFinding.reasoning_trace` said "Persisted for audit, never re-fed". The
second half was true; the first had quietly stopped being true. `_as_judgement`
drops it, `gather()` never returned the findings, nothing wrote it. The claim
*had* been accurate — the one `findings.json` on disk carries traces because it
predates `HypothesisFindings` and is a raw `list[DomainFinding]` dump. The wire
projection removed the only writer and nothing replaced it.

Now `traces.json`, beside the other artifacts, via `gather(trace_sink=...)`. Three
destinations, three answers, kept different on purpose: **auditable locally, never
on the wire to another model, never on a span leaving the process.** `.smartops/`
is gitignored, so it cannot reach a remote.

## AWS_PROFILE stopped being a manual step

"Clear any shell `AWS_PROFILE` before a live probe" appeared three times across
the handovers. A workaround documented three times is a defect with good manners,
and it bit again: the first verification run died on `The config profile () could
not be found`, which reads as "your Bedrock setup is wrong".

`_neutralise_aws_profile()` handles two unambiguous cases — an empty value (never
a valid profile name), and a named profile alongside explicit
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`. Botocore resolves the profile for
*config* before reaching the credential chain the keys would win, so a stale
profile breaks the run rather than losing to it. A profile with no keys beside it
survives — then it *is* the credential. Logged, never silent.

## The verification run itself

`--families vt --console-traces`, no MCP needed — which is the point. **With
Splunk down, the native VirusTotal path was the only reason an end-to-end run was
possible at all.** Degradation is clean: siem reports 0 servers and is withheld
from the toolset entirely.

Strands' own spans confirmed nesting correctly under `investigation_span`:

```
smartops.investigation  run_id=…  task_id=…
  invoke_agent Strands Agents
    execute_event_loop_cycle → chat → execute_tool plan_fetch
    execute_event_loop_cycle → chat → execute_tool investigate_vt
      invoke_agent Strands Agents   task_id=…:vt:tooluse_…  family=vt
        execute_tool vt_lookup_domain / vt_lookup_ip / VtAnswer
    execute_event_loop_cycle → chat → execute_tool TaskClassification
```

Cost: `cost.actual_micro_usd: 138443` (~$0.14) for the broker. First run ever to
write all four artifacts — `report.json`, `evidence.json`, `findings.json`,
`traces.json`.

## Open

- **No answer key.** Still the highest-leverage next work. Verdicts are consistent;
  nothing shows them correct.
- **`SMARTOPS_ANALYST_CMU_COUNT` unset**, so the cost line prints "cost unknown".
  Needs `aws bedrock get-imported-model`.
- **VirusTotal behind an MCP server.** Raised and deliberately deferred:
  consistency is the right long-term argument (all backends one pattern, the
  `enricher_for` native special case goes away), but today is the counterweight —
  moving VT behind MCP would have made this whole session's verification
  impossible. Do it when things are stable.
- **A dead MCP server costs 30s before it gives up** (`startup_timeout` in
  `mcp_servers.json`). Correct but slow; every run against unavailable Splunk pays
  it up front.
- **Cold-start determinism unproven.** 8 warm draws identical, 1 cold draw
  differed. Needs a deliberate >5-minute idle wait.
- **The eval harness is not built.** `blind_compare.ArmStats` still lacks
  disposition agreement and confidence spread. The probe scripts in `scratchpad/`
  remain **untracked**.

## Process note

Two of the three bugs this session were found by *reading one trace of one real
run*, and neither was reachable from the test suite as it stood. The planner bug
in particular had survived every review, 800+ tests, and a benchmark runner,
because the failure produced a plausible report.

The generalisable lesson is narrower than "test more": **at least one path per
tool has to cross the boundary the model's input crosses.** Direct calls with
hand-built contract objects test the branch logic and cannot test the coercion —
and coercion is where a model-facing tool actually fails.
