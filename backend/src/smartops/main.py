"""CLI entry point: runs the Task Broker over one task built from arguments.

This is the first thing in the repo that runs end to end. It is deliberately
thin -- argument parsing, a `Budget`, and printing -- because everything
interesting belongs in `smartops.broker`.

**Why this does not call a model.** `broker.default_broker_invoker()` builds a
real Strands `Agent`, but no Bedrock credentials or region are configured yet, so
this CLI injects `_scripted_invoker()` instead: a deterministic stand-in that
dispatches exactly the families named by `--families`. Everything downstream of
the dispatch decision -- mission construction, the entity gate, tool resolution,
result collection, budget settlement -- is the real code path. Swapping in a live
model is a one-line change to which invoker is passed.

Expect every family to be REJECTED today. No MCP server is configured for any
domain, so that is the honest state of the system, and the two *different*
rejection reasons are what this run demonstrates.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import get_args

from contracts import (
    AnalystTask,
    Entity,
    EntityKind,
    Scope,
    SubtaskResult,
    TaskClassification,
    ToolFamily,
)
from pydantic import ValidationError

from smartops.broker import TOOL_BY_FAMILY, BrokerRequest, broker_task
from smartops.budget import PROVIDER_ENV_VAR, Budget, ModelChoice, model_choice_from_env
from smartops.domains import ALL_FAMILIES
from smartops.subagents import domain_runner
from smartops.telemetry import configure_telemetry
from smartops.tools.registry import load_mcp_servers, mcp_clients

_ENTITY_KINDS = get_args(EntityKind)

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

    Dispatches exactly `families`, in order, by calling the real `@tool`
    wrappers -- a decorated tool stays directly callable, so this exercises the
    genuine dispatch path rather than a parallel copy of it. Then reports the
    same families as its classification, so a normal run shows no divergence;
    `test_broker.py` covers the case where the two disagree.
    """

    async def invoke(prompt: str, request: BrokerRequest) -> _ScriptedResult:
        for index, family in enumerate(families):
            context = _ScriptedToolContext(
                tool_use={"toolUseId": f"cli-{index}"},
                invocation_state={"smartops": request},
            )
            await TOOL_BY_FAMILY[family](question=request.task.goal, tool_context=context)
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
        counts = [
            f"{name}:{sum(rs.row_count for rs in value)}"
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
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _resolve_window(args) -> tuple[datetime, datetime]:
    """The investigation's time window, from either absolute or relative args.

    `--since` wins over `--hours` because it is the more specific statement. With
    only `--since`, the window runs forward by `--hours` rather than to `now`:
    for historical data "from 2018-08-20 for 24 hours" is almost always what is
    meant, and running to now would sweep eight years of empty index.
    """
    now = datetime.now(timezone.utc)
    span = timedelta(hours=args.hours)

    if args.since is not None:
        return args.since, args.until if args.until is not None else args.since + span
    end = args.until if args.until is not None else now
    return end - span, end


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartops-broker",
        description="Run the Task Broker over one investigative task.",
        epilog=(
            "No model is called yet: --families drives dispatch directly. "
            "Expect every family to be REJECTED until MCP servers are configured."
        ),
    )
    parser.add_argument("--goal", required=True, help="what to find out, in plain language")
    parser.add_argument(
        "--entity",
        required=True,
        action="append",
        dest="entities",
        type=_parse_entity,
        metavar="KIND:VALUE",
        help=(
            "an observable in scope, repeatable. KIND is one of: "
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
        default=",".join(ALL_FAMILIES),
        help=f"comma-separated families to dispatch (default: all of {','.join(ALL_FAMILIES)})",
    )
    parser.add_argument(
        "--budget-usd", type=float, default=1.0, help="investigation budget in USD (default: 1.0)"
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
        family = result.task_id.split(":")[1] if ":" in result.task_id else "?"
        print(f"  [{result.status.value:<8}] {family:<5} {_result_line(result)}")
        if result.gaps:
            print(f"             gaps: {', '.join(result.gaps)}")
        if result.error:
            print(f"             error: {result.error}")

    spend = budget.spend_by_role()
    print("\nspend by role (micro-USD):", spend or "(nothing spent)")
    print(f"budget remaining: {budget.remaining} micro-USD")


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


async def _run(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    args = _build_parser().parse_args(argv)

    # Before anything reads os.environ.
    env_file = _load_env_file()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.ERROR,
        format="%(levelname)s %(name)s: %(message)s",
    )
    configure_telemetry(console=args.console_traces)

    # Build MCP clients once, before any dispatch. A missing config or an unset
    # ${VAR} credential leaves a family with no server rather than failing --
    # which is how this runs with no credentials at all.
    try:
        load_mcp_servers(args.mcp_config)
    except Exception as exc:
        # A malformed config is a deployment error, distinct from an absent one.
        print(f"error: could not load MCP config: {exc}", file=sys.stderr)
        return 2
    if args.verbose:
        # Which file supplied the settings is the first thing you want when a
        # credential "isn't being picked up".
        print(f"env file:    {env_file or '(none found)'}")
        print(f"mcp servers: {len(mcp_clients())} connected")

    families = _parse_families(args.families)

    now = datetime.now(timezone.utc)
    try:
        scope = Scope(entities=args.entities, time_window=_resolve_window(args))
    except ValidationError as exc:
        # Most likely `--hours 0`, or `--until` at or before `--since`, either of
        # which makes start >= end.
        print(f"error: invalid scope: {exc.errors()[0]['msg']}", file=sys.stderr)
        return 2

    task = AnalystTask(
        task_id=f"cli-{now:%Y%m%dT%H%M%S}",
        hypothesis_id="cli-hypothesis",
        goal=args.goal,
        scope=scope,
    )

    # The three-state ladder: a configured provider drives a real Broker agent;
    # no provider falls back to the scripted invoker, which is a supported state
    # rather than an error. `--scripted` forces the floor even when credentials
    # exist, for testing the dispatch path without spending anything.
    try:
        choice = None if args.scripted else model_choice_from_env()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if choice is None:
        model = _PLACEHOLDER_MODEL
        invoke = _scripted_invoker(families)
        print(f"model:    (none -- scripted dispatch of {', '.join(families)})")
    else:
        # Build eagerly: a Bedrock model resolves AWS credentials at
        # construction, so a bad region or absent credentials fails here rather
        # than mid-investigation, after budget has been reserved.
        try:
            choice.build()
        except Exception as exc:
            print(
                f"error: provider {choice.provider.value!r} is selected but not usable: {exc}",
                file=sys.stderr,
            )
            print(
                f"       set {PROVIDER_ENV_VAR} to another provider, fix its credentials, "
                "or pass --scripted to run without a model.",
                file=sys.stderr,
            )
            return 2
        model = choice
        invoke = None  # broker_task builds default_broker_invoker itself
        print(f"model:    {choice.provider.value}:{choice.model_id}")

    budget = Budget.from_usd(args.budget_usd)

    # With a real model, domains get a real subagent; without one there is
    # nothing to drive a tool loop, so the Broker's stub stands in and reports
    # what each family *could* have used. `vt` answers either way -- its lookup
    # needs no model at all.
    run_subagent = (
        domain_runner(model=choice, budget=budget) if choice is not None else None
    )

    try:
        outcome = await broker_task(
            task, budget, model=model, invoke=invoke, run_subagent=run_subagent
        )
    except Exception as exc:
        # An investigation failing must not look like the tool crashing. Report
        # it, and report the ledger too: the call may already have been billed,
        # and that is worth seeing.
        print(f"\nerror: the investigation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        logging.getLogger(__name__).debug("broker_task failed", exc_info=True)
        print(f"spend by role (micro-USD): {budget.spend_by_role() or '(nothing spent)'}")
        return 1

    print(f"task:     {task.task_id}")
    print(f"goal:     {task.goal}")
    print(f"scope:    {', '.join(f'{e.kind}={e.value}' for e in scope.entities)}")
    print(f"window:   {scope.time_window[0].isoformat()} .. {scope.time_window[1].isoformat()}")
    _print_outcome(outcome, budget)
    return 0


def run() -> None:
    """Console-script entry point."""
    import asyncio

    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    run()
