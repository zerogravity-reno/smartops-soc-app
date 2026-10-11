"""CLI entry point: runs the Task Broker over one or more investigative tasks.

This is the first thing in the repo that runs end to end. It is deliberately
thin -- argument parsing, a `Budget`, and printing -- because everything
interesting belongs in `smartops.broker`.

**Two ways a task arrives, one execution path.** `--task-file` reads the JSON
contract the Analyst side produces (`contracts.TaskInputFile`, one entry per
hypothesis); the older `--goal`/`--entity`/`--since` flags build a single task
by hand. Both are normalised to a list of `(AnalystTask, hypothesis)` pairs by
`_tasks_from_args()`, so nothing downstream has two cases to handle -- the flag
path is simply a list of one.

**Fetch is sequential, analysis is one parallel burst.** With several tasks the
Brokers run one at a time and every analyst call is deferred to the end. Both
halves of that are deliberate; see `_run` for the reasoning, which is about
Splunk's search quotas on one side and the analyst model's 5-minute billing
windows on the other.

**When this calls a model, and when it does not.** `broker.default_broker_invoker()`
builds a real Strands `Agent`, and `broker_task()` uses it whenever
`model_choices_from_env()` resolves a configured provider. Only when none is
configured (or `--scripted` is passed) does this CLI fall back to
`_scripted_invoker()` instead: a deterministic stand-in that dispatches exactly
the families named by `--families` -- a flag that does nothing on the model
path, where the tool gate (`available_broker_tools()`) decides what is
available instead. Everything downstream of the dispatch decision -- mission
construction, the entity gate, tool resolution, result collection, budget
settlement -- is the real code path either way.

Splunk is configured and returns real rows for `siem`; whether a family is
accepted or rejected depends on which MCP servers `--mcp-config` (or its
defaults) resolve, not on a blanket "nothing is configured yet".
"""

from __future__ import annotations

import argparse
import asyncio
import contextvars
import json
import logging
import os
import sys

# --- Boto3 Monkeypatch for custom FS8B_API_KEY bearer token ---
import boto3
from botocore.tokens import ScopedEnvTokenProvider
from botocore.config import Config

_orig_client = boto3.Session.client
def _patched_client(self, service_name, *args, **kwargs):
    if service_name == "bedrock-runtime":
        if "config" not in kwargs or kwargs["config"] is None:
            kwargs["config"] = Config(auth_scheme_preference="httpBearerAuth")
        else:
            kwargs["config"] = kwargs["config"].merge(Config(auth_scheme_preference="httpBearerAuth"))
        api_key = os.environ.get("FS8B_API_KEY", "")
        if api_key:
            self._session.register_component(
                "token_provider",
                ScopedEnvTokenProvider(self._session, environ={"AWS_BEARER_TOKEN_BEDROCK": api_key}),
            )
    return _orig_client(self, service_name, *args, **kwargs)

boto3.Session.client = _patched_client
# -------------------------------------------------------------
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args

from pydantic import ValidationError

from contracts import (
    AnalystPayloadBatch,
    AnalystTask,
    Entity,
    EntityKind,
    FetchStep,
    DomainFinding,
    HypothesisFindings,
    InvestigationContext,
    Scope,
    SubtaskResult,
    TaskClassification,
    TaskInputFile,
    ToolFamily,
    mission_family,
    pack_for_analyst,
)
from smartops.broker import (
    DEFAULT_RUNS_DIR,
    OUT_DIR_ENV_VAR,
    RUNS_DIR_ENV_VAR,
    TOOL_BY_FAMILY,
    DEFAULT_BROKER_TURNS,
    BrokerRequest,
    broker_task,
    plan_fetch,
)
from smartops.budget import (
    PROVIDER_ENV_VAR,
    Budget,
    ModelChoice,
    loop_output_tokens,
    model_choices_from_env,
)
from smartops.domains import ALL_FAMILIES
from smartops.subagent_analysts.analyze import gather
from smartops.subagent_analysts.packing import HANDOFF_CHAR_BUDGET
from smartops.subagent_analysts.model import analyst_model_from_env
from smartops.subagents import domain_runner
from smartops.telemetry import analysis_span, configure_telemetry, round_span
from smartops.tools.registry import (
    family_is_configured,
    load_mcp_servers,
    mcp_clients,
    warm_mcp_clients,
)

_ENTITY_KINDS = get_args(EntityKind)

AWS_PROFILE_ENV_VAR = "AWS_PROFILE"
"""Botocore's profile selector. Named here because `_neutralise_aws_profile`
UNSETS it, and a variable this code writes to deserves to be as visible as one
it merely reads."""

DEFAULT_BUDGET_USD_PER_TASK = 10.0
"""Default investigation budget, **per task**, when `--budget-usd` is not given.

1.0 was below the cost of a single run and guaranteed a confusing failure: one
siem subagent reserves a measured $1.2431, so a default-budget run reserved the
Broker's hold and was then declined on siem -- the one domain most cases are
about -- reporting "budget exhausted" without naming the number. A realistic plan
(3 siem steps plus one each edr/vt/ndr) holds ~$7.67 concurrently, and both arms
reserve per step, so 10.0 clears it with headroom. A ceiling is not a bill:
reservations settle to actual, measured ~1.27x lower.

**Multiplied by the task count**, because a `Budget` is one cumulative pot and a
task file holds several investigations. Fetch runs sequentially so only one task
ever *holds* at a time, but each one settles into the same pot -- so a 3-task
file against a flat $10 would exhaust it partway through the second
investigation, and a budget refusal reads as a data gap (that is what
`StepOutcome.refused_for_budget` exists to disambiguate) rather than as the cost
problem it is. An explicitly passed `--budget-usd` is honoured verbatim as a
whole-run ceiling, on the grounds that someone naming a number means it.
"""

DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK = 200_000
"""Default hard ceiling on total output tokens, **per task**.

Orthogonal to `--budget-usd`. The USD hold is sized from an optimistic input
estimate (~8 expected turns, not the 25-turn worst case), so real settlement can
carry spend past the USD ceiling when long subagents overlap. Output is the
dominant cost and already per-call capped, so one investigation-wide output
ceiling restores a genuine upper bound. Sized generously -- a full run reserves
well under this -- so it bites only on a runaway, not a normal case. Scaled by
task count for the same reason as the USD pot above.
"""

# Used only on the scripted path, where nothing reaches a provider: `Budget`
# still needs a `pricing_key` to bill against, and `ModelChoice` still validates
# the pairing at construction. Never built into a real model.
_PLACEHOLDER_MODEL = ModelChoice(
    model_id="scripted-no-model-call",
    pricing_key="claude-sonnet-4-6",
)


@dataclass
class _ScriptedMetrics:
    accumulated_usage: dict


@dataclass
class _ScriptedResult:
    structured_output: TaskClassification | None
    metrics: _ScriptedMetrics


def _scripted_invoker(families: list[ToolFamily]):
    """Stands in for the Broker's model until credentials exist.

    Authors a one-step-per-family fetch plan through the real `plan_fetch` tool,
    then dispatches exactly `families`, in order, by calling the real `@tool`
    wrappers -- a decorated tool stays directly callable, so this exercises the
    genuine dispatch path rather than a parallel copy of it. The plan is not
    decoration: a dispatch that names no planned step is refused now, so a
    scripted run that skipped planning would fetch nothing at all. Then reports
    the same families as its classification, so a normal run shows no divergence;
    `test_broker.py` covers the case where the two disagree.
    """
    # `dict.fromkeys` first: keying by family collapses a repeated family onto one
    # entry while `enumerate(families)` keeps counting, which would mint the same
    # step-N id twice -- a plan `FetchPlan` now rejects outright, and for good
    # reason. `_parse_families` de-dupes today, so this is a guard rather than a
    # live bug; the test helper in `test_broker.py` has always had it.
    step_ids = {
        family: f"step-{index + 1}" for index, family in enumerate(dict.fromkeys(families))
    }

    async def invoke(prompt: str, request: BrokerRequest) -> _ScriptedResult:
        if families:
            # `FetchPlan` requires at least one step, and `--families ""` asks for
            # no dispatch at all -- there is nothing to plan, so skip it.
            await plan_fetch(
                steps=[
                    FetchStep(
                        step_id=step_ids[family],
                        family=family,
                        objective=f"Retrieve {family} evidence for the goal",
                    )
                    for family in families
                ],
                rationale="scripted fetch plan, one step per requested family (no model call)",
                tool_context=_ScriptedToolContext(
                    tool_use={"toolUseId": "cli-plan"},
                    invocation_state={"smartops": request},
                ),
            )
        for index, family in enumerate(families):
            context = _ScriptedToolContext(
                tool_use={"toolUseId": f"cli-{index}"},
                invocation_state={"smartops": request},
            )
            await TOOL_BY_FAMILY[family](
                question=request.task.goal, step_id=step_ids[family], tool_context=context
            )
        return _ScriptedResult(
            structured_output=TaskClassification(
                tool_families=list(families),
                rationale=f"scripted dispatch of {', '.join(families)} (no model call)",
            ),
            metrics=_ScriptedMetrics(accumulated_usage={"inputTokens": 0, "outputTokens": 0}),
        )

    return invoke


@dataclass
class _ScriptedToolContext:
    """The two `ToolContext` attributes `_dispatch()` actually reads. Strands
    builds the real one when a live `Agent` invokes a tool."""

    tool_use: dict
    invocation_state: dict


def _result_line(result: SubtaskResult) -> str:
    """One line describing a result, composed entirely by code.

    There is no `summary` to print any more, deliberately -- it was the field
    that made prose the only shape a finding could take. What an operator needs
    at a glance is how much came back and why, so this renders row counts per
    category plus the code-authored `reason`.
    """
    parts: list[str] = []

    if result.findings is not None:
        # Not every `Findings` list holds `ResultSet`. `SiemFindings` does, and a
        # ResultSet knows how many rows it stands for -- but `VtFindings.verdicts`
        # holds `VtVerdict`, which has no `row_count` because one verdict IS one
        # indicator. Reading `.row_count` unconditionally raised AttributeError on
        # every run that returned VT findings, after the investigation had already
        # finished: no data lost, but the operator saw a traceback instead of their
        # results. Anything without its own row count contributes itself.
        counts = [
            f"{name}:{sum(getattr(item, 'row_count', 1) for item in value)}"
            for name, value in result.findings
            if isinstance(value, list) and value
        ]
        if counts:
            parts.append(" ".join(counts))

    if result.queries_run:
        parts.append(f"({len(result.queries_run)} quer{'y' if len(result.queries_run) == 1 else 'ies'})")

    if result.reason:
        parts.append(result.reason)

    return " ".join(parts) if parts else "no rows"


def _parse_entity(raw: str) -> Entity:
    """Parse a `kind:value` argument.

    Splits on the *first* colon only, so values containing colons -- IPv6
    addresses, URLs -- survive intact.
    """
    kind, separator, value = raw.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError(
            f"entity {raw!r} must be in kind:value form, e.g. ip:10.2.4.9 or host:web01"
        )
    if kind not in _ENTITY_KINDS:
        raise argparse.ArgumentTypeError(
            f"unknown entity kind {kind!r} -- expected one of {', '.join(sorted(_ENTITY_KINDS))}"
        )
    if not value.strip():
        raise argparse.ArgumentTypeError(f"entity {raw!r} has an empty value")
    return Entity(kind=kind, value=value)


def _parse_instant(raw: str) -> datetime:
    """Parse an ISO 8601 instant, treating a naive value as UTC.

    `Scope` requires timezone-aware datetimes, so a naive string would otherwise
    fail validation with a message about tzinfo rather than about the argument.
    `Z` is accepted because it is what people paste, and `fromisoformat` only
    learned it in 3.11.
    """
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{raw!r} is not an ISO 8601 instant (e.g. 2018-08-20T00:00:00Z): {exc}"
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _resolve_window(args) -> tuple[datetime, datetime]:
    """The investigation's time window, from either absolute or relative args.

    `--since` wins over `--hours` because it is the more specific statement. With
    only `--since`, the window runs forward by `--hours` rather than to `now`:
    for historical data "from 2018-08-20 for 24 hours" is almost always what is
    meant, and running to now would sweep eight years of empty index.
    """
    now = datetime.now(UTC)
    span = timedelta(hours=args.hours)

    if args.since is not None:
        return args.since, args.until if args.until is not None else args.since + span
    end = args.until if args.until is not None else now
    return end - span, end


def _load_task_file(path: str, task_ids: list[str] | None) -> list[tuple[AnalystTask, str]]:
    """Read a task file and return its `(task, hypothesis)` pairs in file order.

    Every error is raised as a `ValueError` naming the path, because all three
    failure modes here look identical to an operator holding a file that "doesn't
    work" -- unreadable, not JSON, or well-formed JSON that is not a task file --
    and the distinction is exactly what they need to know.

    The hypothesis returned for each task is its `question`. That is the same
    string as `AnalystTask.goal`, and both destinations are deliberate: as `goal`
    it tells the Broker and its subagents what to retrieve, and as the hypothesis
    it is recorded on `HypothesisFindings` as the claim the analysts formed their
    judgements *without* seeing. It is returned separately rather than read back
    off the task at the point of use, so that the analysis call site keeps taking
    the hypothesis as its own argument and cannot quietly start sourcing it from
    the task object -- see `_analyse_one`.
    """
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not read task file {path!r}: {exc}") from exc
    try:
        parsed = TaskInputFile.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"{path!r} is not a valid task file: {exc}") from exc

    selected = parsed.select(task_ids)
    return [(task.to_analyst_task(), task.question) for task in selected]


def _tasks_from_args(args) -> list[tuple[AnalystTask, str | None]]:
    """Every task to investigate, from whichever input mode was used.

    Returns `(task, hypothesis)` pairs so that the rest of the CLI has one shape
    to handle: the flag path is a list of one, and its hypothesis is optional
    because `--hypothesis` always was. A task file's hypothesis is never None --
    `TaskInput.question` is required by the contract -- which is why file input
    runs the analysis tier unconditionally.

    Refuses the two input modes together rather than picking a winner. A run
    given both a file and a `--goal` has been asked for two different
    investigations, and silently honouring one of them is how someone spends a
    live run on the task they did not mean.
    """
    flag_args = {
        "--goal": args.goal,
        "--entity": args.entities,
        "--hypothesis": args.hypothesis,
        "--since": args.since,
        "--until": args.until,
    }
    supplied = sorted(name for name, value in flag_args.items() if value is not None)

    if args.task_file:
        if supplied:
            raise ValueError(
                f"--task-file cannot be combined with {', '.join(supplied)} -- the file "
                "already carries the goal, hypothesis, entities and time window for "
                "every task. Drop the flags, or drop --task-file and pass the whole "
                "task on the command line"
            )
        return _load_task_file(args.task_file, args.task_ids)

    if args.task_ids:
        raise ValueError("--task-id selects a task from --task-file, which was not given")
    if not args.goal and not args.entities:
        raise ValueError(
            "nothing to investigate -- pass either --task-file PATH (a task file from "
            "the Analyst side) or both --goal and at least one --entity KIND:VALUE"
        )
    # Named separately from the nothing-at-all case above: someone who supplied
    # one of the pair has chosen the flag path and needs to know which half is
    # missing, not to be told again that there are two input modes.
    if not args.goal:
        raise ValueError("--goal is required when not using --task-file")
    if not args.entities:
        raise ValueError(
            "at least one --entity KIND:VALUE is required when not using --task-file"
        )

    # `_resolve_window` reads `--hours` too, so the window is always resolvable
    # here even with neither --since nor --until.
    try:
        scope = Scope(entities=args.entities, time_window=_resolve_window(args))
    except ValidationError as exc:
        # Most likely `--hours 0`, or `--until` at or before `--since`, either of
        # which makes start >= end. Re-raised as a ValueError so that every way
        # of failing to produce a task list reaches the caller as one type.
        raise ValueError(f"invalid scope: {exc.errors()[0]['msg']}") from exc
    now = datetime.now(UTC)
    return [(
        AnalystTask(
            task_id=f"cli-{now:%Y%m%dT%H%M%S}",
            # The stub the task file replaces. Kept for the flag path, which has
            # nowhere else to get one: a hypothesis id is the join key between a
            # task and the findings produced for it, and inventing a literal is
            # honest only because this path has no upstream Analyst to supply it.
            hypothesis_id="cli-hypothesis",
            goal=args.goal,
            scope=scope,
        ),
        args.hypothesis,
    )]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartops-broker",
        description="Run the Task Broker over one investigative task.",
        epilog=(
            "A real model runs whenever a provider is configured (see "
            "model_choices_from_env()); --families only drives the scripted path "
            "(--scripted, or no provider configured) -- on the model path the "
            "tool gate decides what's available instead. Splunk is configured, "
            "so siem dispatches return real rows."
        ),
    )
    parser.add_argument(
        "--task-file",
        default=None,
        metavar="PATH",
        help=(
            "path to a JSON task file from the Analyst side (contracts.TaskInputFile: "
            '{"tasks": [{task_id, hypothesis_id, question, entity, time_window}, ...]}). '
            "Each task is investigated in turn and every one carries its own hypothesis, "
            "so --goal/--hypothesis/--entity/--since are neither needed nor accepted with it"
        ),
    )
    parser.add_argument(
        "--task-id",
        action="append",
        dest="task_ids",
        default=None,
        metavar="ID",
        help=(
            "run only this task from --task-file, repeatable. Selected tasks are "
            "always reported in file order. Useful for proving a task file end to "
            "end on one hypothesis before paying for all of them"
        ),
    )
    parser.add_argument(
        "--batch-id",
        default=None,
        metavar="ID",
        help=(
            "name for the batch payload directory (<runs>/<ID>/analyst-payload.json) "
            "written for --task-file runs. Defaults to batch-<timestamp>; a caller "
            "that needs to find the payload again passes its own id"
        ),
    )
    # Not `required=True` any more: a task file supplies both, and argparse
    # cannot express "required unless --task-file". `_tasks_from_args()` enforces
    # exactly-one-of, and names both forms when neither is given -- which is a
    # better message than argparse's for a CLI that now has two input modes.
    parser.add_argument("--goal", help="what to find out, in plain language (without --task-file)")
    parser.add_argument(
        "--hypothesis",
        default=None,
        metavar="TEXT",
        help=(
            "the hypothesis to test, in plain language. When given AND "
            "SMARTOPS_ANALYST_MODEL_ARN is configured, the identity/network/endpoint "
            "subagent-analysts translate the fetched evidence into a plain-English "
            "narrative with cited observations. They are never shown this hypothesis "
            "and take no position on it -- whether the evidence supports or refutes "
            "it is the upstream Analyst agent's call. Stub for that agent"
        ),
    )
    parser.add_argument(
        "--entity",
        action="append",
        dest="entities",
        type=_parse_entity,
        metavar="KIND:VALUE",
        help=(
            "an observable in scope, repeatable (without --task-file). KIND is one of: "
            f"{', '.join(sorted(_ENTITY_KINDS))}"
        ),
    )
    parser.add_argument(
        "--hours", type=int, default=24, help="how far back the time window reaches (default: 24)"
    )
    parser.add_argument(
        "--since",
        type=_parse_instant,
        metavar="ISO8601",
        help=(
            "absolute window start, e.g. 2018-08-20T00:00:00Z (naive values are read as UTC). "
            "Overrides --hours. Needed for any dataset that is not recent: a relative window "
            "over historical data returns nothing and looks exactly like an empty domain"
        ),
    )
    parser.add_argument(
        "--until",
        type=_parse_instant,
        metavar="ISO8601",
        help="absolute window end (default: now, or --since plus --hours when --since is given)",
    )
    parser.add_argument(
        "--families",
        default=None,
        help=(
            f"comma-separated families to dispatch, --scripted only (default: the "
            f"configured ones among {','.join(ALL_FAMILIES)}). On the model path this "
            "does nothing -- the tool gate (available_broker_tools()) decides what is "
            "available instead"
        ),
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help=(
            f"investigation budget in USD. Default: ${DEFAULT_BUDGET_USD_PER_TASK:.2f} per "
            "task, so a 3-task file gets $30.00. Passed explicitly, the value is a "
            "ceiling for the WHOLE run however many tasks it holds"
        ),
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help=(
            f"hard ceiling on total output tokens. Default: "
            f"{DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK} per task; passed explicitly, it "
            "covers the whole run"
        ),
    )
    parser.add_argument(
        # The Broker's cumulative output-token ceiling for one run. Unset, it follows
        # the planner's effort (`budget.loop_output_tokens`, K4), else 16000: the
        # library default (4000) ran out on Sonnet 4.6 while authoring the fetch
        # plan, before a single dispatch.
        "--broker-output-tokens",
        type=int,
        default=None,
        help="cumulative output-token ceiling for the Broker's run "
        "(default: turns x the planner effort's allowance, else 16000)",
    )
    parser.add_argument(
        "--subagent-turns",
        type=int,
        default=25,
        help="turn ceiling for domain subagents (default: 25)",
    )
    parser.add_argument(
        "--mcp-config",
        default=None,
        metavar="PATH",
        help=(
            "path to an mcpServers JSON config (default: $SMARTOPS_MCP_CONFIG, "
            "else mcp_servers.json in the working directory, else no MCP servers)"
        ),
    )
    parser.add_argument(
        "--scripted",
        action="store_true",
        help=(
            "force the scripted invoker even when a provider is configured, so "
            "--families drives dispatch and NO MODEL is called. Note this governs "
            "the model only -- domain lookups still run, so a configured VT_API_KEY "
            "means real VirusTotal requests"
        ),
    )
    parser.add_argument(
        "--skills",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable the reference skill pack (superman-splunk) for siem (default: $SMARTOPS_SKILLS_ENABLED)",
    )
    parser.add_argument(
        "--console-traces",
        action="store_true",
        help="export OpenTelemetry spans to stdout (off by default: spans can carry SOC data)",
    )
    parser.add_argument("--verbose", action="store_true", help="show INFO/WARNING logs")
    return parser


def _parse_families(raw: str) -> list[ToolFamily]:
    families = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [f for f in families if f not in ALL_FAMILIES]
    if unknown:
        raise SystemExit(
            f"error: unknown tool famil{'y' if len(unknown) == 1 else 'ies'} "
            f"{', '.join(unknown)} -- expected from {','.join(ALL_FAMILIES)}"
        )
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(families))


def _print_outcome(outcome, budget: Budget) -> None:
    if outcome.plan:
        print(f"\nfetch plan ({len(outcome.plan.steps)} step(s)): {outcome.plan.rationale}")
        for step in outcome.plan.steps:
            print(f"  [{step.step_id}] {step.family}: {step.objective}")

    print(f"\nclassification: {outcome.classification.rationale}")
    print(f"dispatched:     {', '.join(outcome.dispatched) or '(nothing)'}")

    if set(outcome.dispatched) != set(outcome.classification.tool_families):
        # Surfaced rather than hidden: `dispatched` is observed, the
        # classification is self-reported, and a gap means the Broker's account
        # of its own reasoning disagrees with what ran.
        print(
            f"  ! divergence: classification claims "
            f"{', '.join(outcome.classification.tool_families) or '(nothing)'}"
        )

    print(f"\n{len(outcome.results)} result(s):")
    for result in outcome.results:
        family = mission_family(result.task_id) or "?"
        print(f"  [{result.status.value:<8}] {family:<5} {_result_line(result)}")
        if result.gaps:
            print(f"             gaps: {', '.join(result.gaps)}")
        if result.error:
            print(f"             error: {result.error}")

    spend = budget.spend_by_role()
    print("\nspend by role (micro-USD):", spend or "(nothing spent)")
    for role, t in budget.usage_by_role().items():
        print(f"usage {role}: " + " ".join(f"{k}={v}" for k, v in t.items()))
    print(f"budget remaining: {budget.remaining} micro-USD")


def _print_findings(findings: HypothesisFindings) -> None:
    """Operator view of the blind path.

    Deliberately prints no verdict of any kind: there isn't one. Each domain
    translated its own evidence into plain English without seeing the
    hypothesis and without judging it, and rolling that into SUPPORTS/REFUTES
    is the Analyst Agent's job. Printing a stance or disposition here would be
    inventing the very thing this path exists to keep separate.

    `rows=N` per citation is shown because it is the cheapest way to see the
    failure the exhibits exposed: a narrative resting on a cited block that
    returned nothing.
    """
    print(f"\ndomain findings for hypothesis {findings.hypothesis_id} (analysts were blind):")
    for judgement in findings.findings:
        print(f"  [{judgement.domain:<8}]")
        if judgement.narrative:
            print(f"             {judgement.narrative}")
        for observation in judgement.observations:
            print(f"               - {observation}")
        for exhibit in judgement.exhibits:
            flag = "  <- EMPTY" if exhibit.row_count == 0 else ""
            print(f"             cited: {exhibit.citation} (rows={exhibit.row_count}){flag}")

    # The retrieval side, because an `inconclusive` above is unreadable without
    # it: a domain reports it both when the rows decide nothing and when nothing
    # was ever retrieved for it. `not evaluated` is called out separately from
    # `incomplete` for the reason `StepOutcome.evaluated` exists.
    if findings.retrieval is not None:
        retrieval = findings.retrieval
        print(f"\nretrieval (dispatched: {', '.join(retrieval.dispatched) or 'nothing'}):")
        # Widened to the longest id rather than a fixed column: real step ids are
        # model-authored ("siem-connections") and overran a hardcoded width,
        # leaving the states unaligned in exactly the readout meant to be scanned.
        id_width = max((len(s.step_id) for s in retrieval.steps), default=0)
        for step in retrieval.steps:
            if not step.evaluated:
                state = "not evaluated"
            elif step.completed:
                state = "complete"
            elif step.confirmed_empty:
                state = "empty (confirmed)"
            else:
                state = "incomplete"
            print(
                f"  [{step.family:<5}] {step.step_id:<{id_width}} {state:<17} "
                f"rows={step.rows_retrieved}"
            )
        if retrieval.covered:
            print(f"  covered:     {', '.join(retrieval.covered)}")
        if retrieval.not_covered:
            print(f"  not covered: {', '.join(retrieval.not_covered)}")

    print(
        "\nno overall stance and no disposition: deciding whether this supports "
        "or refutes the hypothesis, or what it means at all, is the Analyst "
        "Agent's call, not this layer's."
    )


def _resolve_run_dir(task_id: str, run_dir: Path | str | None) -> Path | None:
    """The directory a run's artifacts belong in, or `None` if it cannot be found.

    A passed `run_dir` wins; otherwise `SMARTOPS_RUNS_DIR` (or the default) plus
    the task's `latest.txt` pointer. `None` rather than a raise: a missing run
    directory means the broker never wrote one, and a completed analysis should
    still print its findings.

    Extracted because `_persist_findings` and `_persist_reasoning_traces` must
    resolve to the SAME directory. Two copies of these rules would drift, and the
    failure would be a trace file landing beside a different run's findings --
    silently, since both files would look well-formed.
    """
    if run_dir is not None:
        return Path(run_dir)
    base = os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR
    latest = Path(base) / task_id / "latest.txt"
    if not latest.exists():
        return None
    return latest.parent / latest.read_text(encoding="utf-8").strip()


def _persist_reasoning_traces(
    task_id: str,
    hypothesis_id: str,
    findings: list[DomainFinding],
    run_dir: Path | str | None = None,
) -> None:
    """Write `traces.json` beside the run's other artifacts.

    **Local audit only, and deliberately a separate file from `findings.json`.**
    The trace is the model's `<think>` chain: it must never reach another model
    (that is re-feeding a private chain of thought) and must never leave the
    process on a span (OTel span content goes to whatever collector is
    configured, and Strands' redaction is opt-in and OFF). Keeping it in its own
    file on the run directory is what makes it auditable without making it
    shippable -- `.smartops/` is gitignored, so it never reaches a remote either.

    `DomainRecord` therefore has no field for it and `findings.json` correctly
    lacks it. This is the other half of that decision: without this writer the
    trace was simply discarded, while `DomainFinding.reasoning_trace` still
    described itself as "persisted for audit". It had been, by an older artifact
    format that dumped `DomainFinding` directly; the wire projection removed the
    only writer and nothing replaced it.

    Same run-directory resolution as `_persist_findings`, and silently does
    nothing when there is no directory to write to -- an audit artifact must not
    be the thing that fails a completed analysis.
    """
    target_dir = _resolve_run_dir(task_id, run_dir)
    if target_dir is None:
        return

    payload = {
        # The same join keys every other artifact carries, so a trace file found
        # on its own is still resolvable back to the run and the claim.
        "task_id": task_id,
        "hypothesis_id": hypothesis_id,
        "run_id": target_dir.name,
        "traces": [
            {
                "domain": finding.domain,
                "prompt_tokens": finding.prompt_tokens,
                "generation_tokens": finding.generation_tokens,
                "reasoning_trace": finding.reasoning_trace,
            }
            for finding in findings
        ],
    }
    (target_dir / "traces.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def _persist_findings(
    task_id: str,
    findings: HypothesisFindings,
    run_dir: Path | str | None = None,
    max_chars: int | None = None,
) -> None:
    """Write findings.json and analyst-payload.json beside the broker's artifacts.

    `run_dir` wins over `SMARTOPS_RUNS_DIR` over the default. Named
    `findings.json`, not `assessment.json`: `HypothesisAssessment` is the shape
    that carries a decided stance, and `HypothesisFindings` deliberately does not
    -- deciding for or against the hypothesis is the Analyst Agent's call, on the
    far side of this contract. The writer for `assessment.json` was deleted with
    the rest of the shown path; see `subagent_analysts/shown.py`.

    **Two files, because the record and the message are not the same shape.**
    `findings.json` is the durable audit trail: citations, exhibits, retrieval
    summary, every row the analyst read. `analyst-payload.json` is
    `HypothesisFindings.for_analyst()` -- prose and observations only, and what
    actually crosses the boundary. On the 2026-09-01 live run that is 5,684
    characters against 42,200, because 73% of the record is the raw rows this
    tier exists to compress into prose; shipping them on would undo the
    compression that justifies the tier.
    """
    target_dir = _resolve_run_dir(task_id, run_dir)
    if target_dir is None:
        return

    if target_dir.is_dir():
        # `gather()` already set run_id where the caller knew it; fill it in when
        # it did not, so the artifact still names its own directory.
        stamped = (
            findings if findings.run_id else findings.model_copy(update={"run_id": target_dir.name})
        )
        (target_dir / "findings.json").write_text(
            stamped.model_dump_json(indent=2), encoding="utf-8"
        )
        # The record is written above; the message is written here. Same call, so
        # the two cannot drift apart on disk -- an artifact directory holding one
        # without the other would leave a reader unable to tell which the Analyst
        # Agent actually received.
        (target_dir / "analyst-payload.json").write_text(
            stamped.for_analyst(max_chars).model_dump_json(indent=2), encoding="utf-8"
        )


def _neutralise_aws_profile() -> str | None:
    """Drop `AWS_PROFILE` when explicit credentials make it irrelevant.

    Returns the value dropped, or `None`. Call AFTER `_load_env_file()` so that
    credentials from `.env` count, and before anything constructs a boto3 client.

    **Why this is code and not a note in the README.** It was a note in the
    README -- three of them, across the handovers: "clear any shell `AWS_PROFILE`
    before a live probe". A workaround documented three times is a defect with
    good manners. The failure it prevents is also badly disguised: an unusable
    profile surfaces as `The config profile (...) could not be found` from deep
    inside botocore, at model-construction time, which reads as "your Bedrock
    setup is wrong" rather than "an unrelated shell variable is set".

    Two cases, both unambiguous:

    - **Empty.** `AWS_PROFILE=""` is what `env AWS_PROFILE= ...` produces, and
      botocore takes it literally -- it looks for a profile *named* empty string
      and fails. An empty profile name is never valid, so it can only mean unset.
    - **Set, with explicit keys also present.** `AWS_ACCESS_KEY_ID` +
      `AWS_SECRET_ACCESS_KEY` in the environment are a direct statement of which
      credentials to use. A profile named alongside them is the ambient leftover,
      not the intent -- and it does not merely lose the race, it can break the run
      outright, because botocore resolves the profile for *config* before it ever
      reaches the credential chain the keys would win.

    Logged at WARNING, never silent: overriding an operator's environment
    variable without saying so is its own confusing failure.
    """
    profile = os.environ.get(AWS_PROFILE_ENV_VAR)
    if profile is None:
        return None

    if not profile.strip():
        del os.environ[AWS_PROFILE_ENV_VAR]
        logging.getLogger(__name__).warning(
            "%s was set to an empty value and has been unset -- botocore reads "
            "that as a profile literally named '', which never exists",
            AWS_PROFILE_ENV_VAR,
        )
        return profile

    has_explicit_keys = all(
        os.environ.get(name, "").strip()
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    )
    if not has_explicit_keys:
        # Nothing else to authenticate with, so the profile is the intent.
        return None

    del os.environ[AWS_PROFILE_ENV_VAR]
    logging.getLogger(__name__).warning(
        "%s=%s ignored: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are set and are "
        "what this run will authenticate with. Unset the keys if you meant to use "
        "the profile.",
        AWS_PROFILE_ENV_VAR,
        profile,
    )
    return profile


def _load_env_file() -> str | None:
    """Load `.env` into the environment, if there is one. Returns its path.

    Every setting in this project is read from `os.environ`, so without this a
    `.env` file is inert and `cp .env.example .env` -- what the template tells
    you to do -- would appear to do nothing.

    `override=False` on purpose: a variable already set in the shell, CI, or a
    container's environment wins over the file. A stale local `.env` silently
    overriding a deployment's real credentials is the worse failure.

    Searches upward from the working directory, so it works whether you run from
    the repo root or from `backend/`.
    """
    from dotenv import find_dotenv, load_dotenv

    path = find_dotenv(usecwd=True)
    if not path:
        return None
    load_dotenv(path, override=False)
    return path


def _force_utf8_output() -> None:
    """Make stdout/stderr able to carry any answer a model produces.

    Windows consoles default to cp1252, which cannot encode a great deal of what
    an LLM writes -- arrows, dashes, box drawing. Printing such an answer raised
    `UnicodeEncodeError` from `_print_outcome`, *after* the investigation had run
    and been billed: the work succeeded and the report threw it away, with a
    stack trace instead of findings.

    `errors="replace"` as well as UTF-8, because a terminal that still cannot
    represent a character must degrade it to `?` rather than lose the report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                # A redirected or already-detached stream. Not worth failing the
                # run over -- worst case we are back to the old behaviour.
                logging.getLogger(__name__).debug("could not reconfigure %r", stream)


async def _analyse_one(
    task: AnalystTask,
    hypothesis: str,
    outcome,
    *,
    analyst_model,
    max_chars: int | None = None,
) -> HypothesisFindings:
    """The BLIND analysis path for one fetched task: three domain judgements.

    **Returns the findings rather than printing them, and that is what lets the
    caller run several of these concurrently.** Three tasks' worth of
    `_print_findings` interleaved on one stdout is unreadable, so the caller
    gathers the results and prints them in file order afterwards. Persisting is
    still done here, because a file write per run directory cannot interleave
    with anything.

    The analysts never receive `hypothesis` -- `gather` takes no
    `InvestigationContext` and `build_facts_user_turn` has no hypothesis
    parameter, so it cannot reach them. It is carried on the result only, as the
    attachment point where three independent judgements are joined to the claim
    they were formed without. Note that for task-file input this string is also
    `task.goal`, which the *fetch* tier did see; that is a different tier and a
    deliberate difference, and the one-way property holds because nothing on the
    analyst path reads a goal at all.

    `analyze()`/`combine()` used to sit here and roll the three shown verdicts
    into one decided stance; both were DELETED once nothing called them (see
    `analyze.py`'s own module docstring and `docs/architecture.md`). A stance
    formed by an analyst that was shown the hypothesis is the anchoring this path
    exists to remove.
    """
    _current_task.set(task.task_id)  # this coroutine's own context: one per task under gather
    run_dir = getattr(outcome, "run_dir", None)
    run_id = Path(run_dir).name if run_dir else None
    # The analyze tier's root span. A second root beside the fetch tier's
    # `investigation_span`, which opened inside `broker_task()` and closed when
    # it returned -- see `telemetry.analysis_span`. The two join on
    # task_id/hypothesis_id, and on the fetch trace id recorded here.
    with analysis_span(
        task.task_id,
        task.hypothesis_id,
        run_id=run_id,
        fetch_trace_id=outcome.report.trace_id,
    ):
        findings = await gather(
            outcome.report,
            task.scope,
            analyst_model,
            run_id=run_id,
            hypothesis=hypothesis,
            # The only hook that can reach `reasoning_trace`: `_as_record`
            # drops it before `gather` returns.
            trace_sink=lambda domain_findings: _persist_reasoning_traces(
                task.task_id,
                task.hypothesis_id,
                domain_findings,
                run_dir=run_dir,
            ),
        )
    _persist_findings(task.task_id, findings, run_dir=run_dir, max_chars=max_chars)
    return findings


def _runs_root() -> Path:
    """The directory run artifacts are written under.

    Same resolution `_resolve_run_dir` uses, minus the per-task part, because a
    batch belongs to the whole invocation rather than to any one task.
    """
    return Path(os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR)


def _persist_payload_batch(
    findings: list[HypothesisFindings],
    batch_id: str | None = None,
    max_chars: int | None = None,
) -> Path | None:
    """Write one `analyst-payload.json` carrying every hypothesis in the file.

    **The unit of handover is the task file, not the hypothesis.** A file arrives
    with several hypotheses about one alert and the Analyst Agent has to weigh
    them against each other; three separate payload files leave that grouping for
    the recipient to infer from nothing. See `contracts.AnalystPayloadBatch`.

    Written to `<runs_dir>/<batch_id>/`, a sibling of the per-task run
    directories rather than inside one of them: it belongs to no single task, and
    putting it under one task's id would make it look like that task's artifact.
    Nothing scans the runs root for task directories -- `replay` is handed a case
    directory and lists stamps *inside* it -- so a differently-shaped sibling is
    safe there.

    The per-task `analyst-payload.json` files are still written beside each run's
    own report and evidence. They are not redundant: that is the per-run-dir
    record, joined by `run_id`, and it is what lets a reader of one run directory
    see what that investigation produced. This is the message.

    Returns the path written, or `None` when there is no runs directory to write
    to -- the same trade `_persist_findings` makes, since an artifact must not be
    the thing that fails a completed run.
    """
    root = _runs_root()
    if not root.is_dir() and not os.environ.get(OUT_DIR_ENV_VAR, "").strip():
        # Every task's own run dir is created by the broker under this root, so a
        # missing root means nothing was persisted at all and there is no place
        # this belongs. Silent for the same reason `_resolve_run_dir` is.
        logging.getLogger(__name__).debug("no runs directory at %s, batch not written", root)
        return None

    batch = AnalystPayloadBatch(
        batch_id=batch_id or f"batch-{datetime.now(UTC):%Y%m%dT%H%M%S}",
        payloads=pack_for_analyst(findings, max_chars),
    )
    # Beside the tasks in the round's own folder when the webapp names one (O5).
    out = os.environ.get(OUT_DIR_ENV_VAR, "").strip()
    target = Path(out) if out else root / batch.batch_id
    target.mkdir(parents=True, exist_ok=True)
    path = target / "analyst-payload.json"
    path.write_text(batch.model_dump_json(indent=2), encoding="utf-8")

    print(
        f"\nanalyst payload: {len(batch.payloads)} hypothes"
        f"{'is' if len(batch.payloads) == 1 else 'es'} in one message -> {path}"
    )
    return path


async def _analyse_all(
    fetched: list[tuple[AnalystTask, str | None, object]],
    *,
    analyst_model,
    task_count: int,
) -> tuple[int, list[HypothesisFindings]]:
    """PHASE B -- analyse every fetched task at once.

    Returns `(failure_count, findings_in_task_order)`. The findings come back
    rather than being consumed here because the caller assembles them into one
    `AnalystPayloadBatch` -- see `_persist_payload_batch`.

    **One burst, deliberately, and it is where the parallelism in this CLI
    actually is.** The analyst model bills in 5-minute windows starting at its
    first successful invocation, and an idle five minutes closes one (see
    `smartops.analyst_cost`). Deferring every task's analysis to a single burst
    puts all of it inside one or two windows; analysing each task as soon as its
    own fetch finished would instead scatter the calls across however long the
    fetch loop took, opening a fresh window each time the gap ran over five
    minutes. Three tasks x three domains is nine concurrent calls through one
    shared `AnalystModel`, which is exactly what that sharing is for.

    `return_exceptions=True` because one hypothesis failing to analyse must not
    discard the findings of the others -- they have already been fetched and
    paid for. Results are printed here, in the caller's task order, rather than
    inside `_analyse_one`: nine concurrent calls printing as they finished would
    interleave three reports into an unreadable stream.
    """
    analysable = [
        (task, hypothesis, outcome)
        for task, hypothesis, outcome in fetched
        # A missing hypothesis is only possible on the flag path -- a task file
        # always carries one, which is why file input needs no branch here.
        if hypothesis and outcome.report is not None
    ]
    skipped = [
        task for task, hypothesis, outcome in fetched
        if hypothesis and outcome.report is None
    ]
    for task in skipped:
        print(f"\nanalysis: skipped for {task.task_id} (the broker produced no report)")

    if analyst_model is None or not analysable:
        return 0, []

    if task_count > 1:
        print(f"\n{'=' * 70}")
        print(
            f"analysing {len(analysable)} task(s) concurrently "
            f"({len(analysable) * 3} analyst calls in one billing window)"
        )
        print("=" * 70)

    results = await asyncio.gather(
        *(
            _analyse_one(
                task,
                hypothesis,
                outcome,
                analyst_model=analyst_model,
                # One round's handoff budget, split across the file's tasks.
                max_chars=HANDOFF_CHAR_BUDGET // max(task_count, 1),
            )
            for task, hypothesis, outcome in analysable
        ),
        return_exceptions=True,
    )

    failures = 0
    findings: list[HypothesisFindings] = []
    for (task, _, _), result in zip(analysable, results):
        if isinstance(result, BaseException):
            print(
                f"\nanalysis failed for {task.task_id}: "
                f"{type(result).__name__}: {result}",
                file=sys.stderr,
            )
            logging.getLogger(__name__).debug(
                "gather failed for %s", task.task_id, exc_info=result
            )
            failures += 1
            continue
        if task_count > 1:
            print(f"\n--- {task.task_id} / {task.hypothesis_id} ---")
        _print_findings(result)
        # Task order, not completion order: the batch below is handed over as a
        # single message, and the order the producer wrote the hypotheses in is
        # the only order that means anything to whoever reads it.
        findings.append(result)

    # The analyst model is billed per CMU-minute, not per token, so its spend is
    # not in `Budget` and `_print_outcome` cannot show it. Printed ONCE for the
    # whole run rather than per task, because one shared `AnalystModel` means one
    # `AnalystSpend` -- printing it per task would repeat the same cumulative
    # window count and make the batching look more expensive than it was.
    #
    # `getattr`, because the analyst model here is duck-typed -- tests inject
    # fakes, and a bench harness may too. A cost READOUT must never be the thing
    # that sinks a completed investigation, and the findings are already printed.
    spend = getattr(analyst_model, "spend", None)
    if spend is not None:
        print()
        print(spend.summary())

    return failures, findings


# The task a log line belongs to (O6): 874ab334 lost endpoint three times and the
# log could not say in which task. A contextvar, so `asyncio.to_thread` in
# `gather` carries it into every sub-analyst call.
_current_task: contextvars.ContextVar[str] = contextvars.ContextVar("smartops_task", default="")


def _name_the_task(record: logging.LogRecord) -> bool:
    task = _current_task.get()
    record.task = f"task={task} | " if task else ""
    return True


async def _run(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    args = _build_parser().parse_args(argv)

    # Before anything reads os.environ.
    env_file = _load_env_file()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.ERROR,
        format="%(levelname)s %(name)s: %(task)s%(message)s",
    )
    for handler in logging.getLogger().handlers:
        handler.addFilter(_name_the_task)
    if not args.verbose:
        # The analyst gates log every sentence, figure and domain they drop as a
        # warning; at ERROR the run's log never showed what the Analyst lost (N3).
        # `contracts` too: its packer's over-budget warning was invisible (O6).
        logging.getLogger("smartops.subagent_analysts").setLevel(logging.WARNING)
        logging.getLogger("contracts").setLevel(logging.WARNING)
    # After logging is configured, so its warning is visible, and after the .env
    # load, so credentials from the file count as explicit.
    _neutralise_aws_profile()
    configure_telemetry(console=args.console_traces)
    with round_span(args.batch_id):
        return await _run_round(args, env_file)


async def _run_round(args: argparse.Namespace, env_file) -> int:
    # Build MCP clients once, before any dispatch. A missing config or an unset
    # ${VAR} credential leaves a family with no server rather than failing --
    # which is how this runs with no credentials at all.
    try:
        load_mcp_servers(args.mcp_config)
    except Exception as exc:
        # A malformed config is a deployment error, distinct from an absent one.
        print(f"error: could not load MCP config: {exc}", file=sys.stderr)
        return 2
    # Resolve every client's tools now, so two concurrent dispatches in one
    # Broker turn cannot race each other's connection start-up.
    await warm_mcp_clients()
    if args.verbose:
        # Which file supplied the settings is the first thing you want when a
        # credential "isn't being picked up".
        print(f"env file:    {env_file or '(none found)'}")
        print(f"mcp servers: {len(mcp_clients())} built")

    # Defaulting to every family dispatched nothing: plan_fetch refuses a plan
    # naming an unconfigured one. Read after load_mcp_servers, which decides that.
    families = (
        _parse_families(args.families)
        if args.families
        else [f for f in ALL_FAMILIES if family_is_configured(f)]
    )

    try:
        tasks = _tasks_from_args(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if len(tasks) > 1:
        print(f"tasks:    {len(tasks)} ({', '.join(t.task_id for t, _ in tasks)})")

    # The three-state ladder: a configured provider drives a real Broker agent;
    # no provider falls back to the scripted invoker, which is a supported state
    # rather than an error. `--scripted` forces the floor even when credentials
    # exist, for testing the dispatch path without spending anything.
    try:
        # One choice per Broker role (K4): the planner, siem and vt can each run their own model.
        choices = None if args.scripted else model_choices_from_env()
        choice = choices["broker"] if choices else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    broker_output_tokens = args.broker_output_tokens or (
        loop_output_tokens(choice, DEFAULT_BROKER_TURNS, 16_000) if choice else 16_000
    )

    if choice is None:
        model = _PLACEHOLDER_MODEL
        invoke = _scripted_invoker(families)
        print(f"model:    (none -- scripted dispatch of {', '.join(families)})")
    else:
        # Build eagerly: a Bedrock model resolves AWS credentials at
        # construction, so a bad region or absent credentials fails here rather
        # than mid-investigation, after budget has been reserved.
        try:
            for role_choice in choices.values():
                role_choice.build()
        except Exception as exc:
            print(
                f"error: provider {choice.provider.value!r} is selected but not usable: {exc}",
                file=sys.stderr,
            )
            hint = ""
            if os.environ.get(AWS_PROFILE_ENV_VAR):
                hint = (
                    f"\n       {AWS_PROFILE_ENV_VAR}="
                    f"{os.environ[AWS_PROFILE_ENV_VAR]} is set and boto3 will use it; "
                    "unset it to fall back to AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY."
                )
            print(
                f"       set {PROVIDER_ENV_VAR} to another provider, fix its credentials, "
                f"or pass --scripted to run without a model.{hint}",
                file=sys.stderr,
            )
            return 2
        model = choice
        invoke = None  # broker_task builds default_broker_invoker itself
        tier = os.environ.get("SMARTOPS_BROKER_TIERS", "").strip().upper() or "-"
        print(f"model:    {choice.provider.value} tier={tier} "
              + " ".join(f"{role}={c.model_id}" + (f"/{c.effort}" if c.effort else "") for role, c in choices.items())
              + f" broker_output_tokens={broker_output_tokens}")

    # Per task, then multiplied: see `DEFAULT_BUDGET_USD_PER_TASK`. An explicit
    # value is a whole-run ceiling and is not scaled.
    budget_usd = (
        args.budget_usd if args.budget_usd is not None
        else DEFAULT_BUDGET_USD_PER_TASK * len(tasks)
    )
    max_output_tokens = (
        args.max_output_tokens if args.max_output_tokens is not None
        else DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK * len(tasks)
    )
    budget = Budget.from_usd(budget_usd, max_output_tokens_total=max_output_tokens)
    if len(tasks) > 1:
        per_task = budget_usd / len(tasks)
        print(f"budget:   ${budget_usd:.2f} across {len(tasks)} tasks (${per_task:.2f} each)")

    # ONE analyst model for every task, and that is load-bearing rather than
    # tidy. The imported model bills in 5-minute windows from its first
    # successful invocation (see `smartops.analyst_cost`), and a shared
    # `AnalystModel` is what makes concurrent calls collapse into one window
    # instead of one per caller. Built before the fetch loop so that a missing
    # SMARTOPS_ANALYST_MODEL_ARN is reported once, up front, rather than after
    # every task has already been fetched and paid for.
    #
    # Only when something actually wants analysing. A task file always does --
    # `question` is required -- but the flag path without `--hypothesis` does
    # not, and warning about an unset ARN there would name the wrong reason for
    # a skip whose real cause is that no hypothesis was given.
    analyst_model = None
    if any(hypothesis for _, hypothesis in tasks):
        analyst_model = None if args.scripted else analyst_model_from_env()
        if analyst_model is None:
            print(
                "\nanalysis: will be skipped (set SMARTOPS_ANALYST_MODEL_ARN to enable, "
                "and do not pass --scripted)"
            )

    if args.skills is not None:
        from smartops.skills import pinned_skills_enabled
        skills_ctx = pinned_skills_enabled(args.skills)
    else:
        import contextlib
        skills_ctx = contextlib.nullcontext()

    # PHASE A -- fetch, one task at a time.
    #
    # Sequential on purpose. A single investigation already issues several
    # concurrent Splunk searches (a realistic plan is 3 siem steps plus one each
    # edr/vt/ndr, per `DEFAULT_BUDGET_USD_PER_TASK`), and Strands runs a turn's
    # tool calls concurrently by default. Running the Brokers one at a time keeps
    # the peak at what a single run already does rather than multiplying it by
    # the task count against Splunk's per-user search quotas -- where a queued or
    # rejected search returns as a subagent `error`/`no_data` and reads as a data
    # gap rather than as the capacity problem it is. The model tier says the same
    # thing: the subagents' `max_attempts=2` was chosen because "concurrent
    # subagents would stampede in lockstep", sized for ONE investigation's
    # concurrency.
    #
    # Nothing about this is expensive to revisit -- the loop below becomes
    # `asyncio.gather` over the same awaitables -- but it should be revisited on
    # measurements from a live run, not on the assumption that Splunk has the
    # headroom.
    fetched: list[tuple[AnalystTask, str | None, object]] = []
    failures = 0
    with skills_ctx:
        # With a real model, domains get a real subagent; without one there is
        # nothing to drive a tool loop, so the Broker's stub stands in and reports
        # what each family *could* have used. `vt` answers either way -- its lookup
        # needs no model at all.
        run_subagent = (
            domain_runner(model=choices, budget=budget, turns=args.subagent_turns)
            if choice is not None
            else None
        )

        for position, (task, hypothesis) in enumerate(tasks, start=1):
            if len(tasks) > 1:
                print(f"\n{'=' * 70}")
                print(f"fetching {position}/{len(tasks)}: {task.task_id} / {task.hypothesis_id}")
                print("=" * 70)

            _current_task.set(task.task_id)
            try:
                outcome = await broker_task(
                    task,
                    budget,
                    model=model,
                    invoke=invoke,
                    run_subagent=run_subagent,
                    max_output_tokens=broker_output_tokens,
                )
            except Exception as exc:
                # An investigation failing must not look like the tool crashing.
                # Report it, and report the ledger too: the call may already have
                # been billed, and that is worth seeing. With several tasks the
                # others still run -- one failed hypothesis is not a reason to
                # abandon the ones that would have succeeded.
                print(
                    f"\nerror: the investigation failed: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                logging.getLogger(__name__).debug("broker_task failed", exc_info=True)
                print(f"spend by role (micro-USD): {budget.spend_by_role() or '(nothing spent)'}")
                failures += 1
                continue

            print(f"task:     {task.task_id}")
            print(f"goal:     {task.goal}")
            print(
                "scope:    "
                + ", ".join(f"{e.kind}={e.value}" for e in task.scope.entities)
            )
            print(
                f"window:   {task.scope.time_window[0].isoformat()}"
                f" .. {task.scope.time_window[1].isoformat()}"
            )
            _print_outcome(outcome, budget)
            if len(tasks) > 1:
                # `_print_outcome`'s ledger lines are a running total across every
                # task so far, which inside one task's block reads as this task's
                # own spend.
                print(f"this task: {budget.spend_for_task(task.task_id)} micro-USD")
            fetched.append((task, hypothesis, outcome))

    analysis_failures, findings = await _analyse_all(
        fetched, analyst_model=analyst_model, task_count=len(tasks)
    )
    failures += analysis_failures

    # One message per task FILE, not per hypothesis. Only for file input: the
    # legacy flag path investigates one hand-written task and has no file whose
    # grouping a batch could represent.
    if args.task_file and findings:
        _persist_payload_batch(
            findings,
            batch_id=args.batch_id,
            # The batch is one message: one budget, water-filled across its tasks.
            max_chars=HANDOFF_CHAR_BUDGET,
        )

    if len(tasks) > 1:
        print(f"\n{'=' * 70}")
        print(f"{len(fetched)}/{len(tasks)} task(s) fetched, {failures} failure(s)")
        print(f"spend by task (micro-USD): {budget.spend_by_task() or '(nothing spent)'}")
        print(f"budget remaining: {budget.remaining} micro-USD")

    return 1 if failures else 0


def run() -> None:
    """Console-script entry point."""
    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    run()
