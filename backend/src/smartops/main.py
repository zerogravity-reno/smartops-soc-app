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

from contracts import AnalystTask, Entity, EntityKind, Scope, TaskClassification, ToolFamily
from pydantic import ValidationError

from smartops.broker import (
    BrokerRequest,
    broker_task,
    investigate_edr,
    investigate_ndr,
    investigate_siem,
    investigate_vt,
)
from smartops.budget import Budget, ModelChoice
from smartops.telemetry import configure_telemetry
from smartops.tools.registry import load_mcp_servers, mcp_clients

_TOOL_BY_FAMILY = {
    "siem": investigate_siem,
    "edr": investigate_edr,
    "vt": investigate_vt,
    "ndr": investigate_ndr,
}

_ALL_FAMILIES: tuple[ToolFamily, ...] = ("siem", "edr", "vt", "ndr")
_ENTITY_KINDS = get_args(EntityKind)

# Aug-13 placeholder pairing. `pricing_key` indexes our own PRICING table;
# `model_id` is the provider-facing id Strands hands to Bedrock.
#
# ⚠️ `model_id` is UNVERIFIED. Strands' `BedrockModel` uses the legacy
# Converse/InvokeModel path, which wants an ARN-versioned inference-profile id
# whose date suffix cannot be guessed. Nothing sends it to Bedrock yet, so it is
# inert -- but resolve it against the target account before the first live call:
#
#   aws bedrock list-inference-profiles --region <region> \
#     --query "inferenceProfileSummaries[?contains(inferenceProfileId,'sonnet')].inferenceProfileId"
#
# The `us.` / `eu.` prefix is required for on-demand throughput.
_DEFAULT_MODEL = ModelChoice(
    model_id="us.anthropic.claude-sonnet-4-6-PLACEHOLDER-v1:0",
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
            await _TOOL_BY_FAMILY[family](question=request.task.goal, tool_context=context)
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
        "--families",
        default=",".join(_ALL_FAMILIES),
        help=f"comma-separated families to dispatch (default: all of {','.join(_ALL_FAMILIES)})",
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
        "--console-traces",
        action="store_true",
        help="export OpenTelemetry spans to stdout (off by default: spans can carry SOC data)",
    )
    parser.add_argument("--verbose", action="store_true", help="show INFO/WARNING logs")
    return parser


def _parse_families(raw: str) -> list[ToolFamily]:
    families = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [f for f in families if f not in _ALL_FAMILIES]
    if unknown:
        raise SystemExit(
            f"error: unknown tool famil{'y' if len(unknown) == 1 else 'ies'} "
            f"{', '.join(unknown)} -- expected from {','.join(_ALL_FAMILIES)}"
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
        print(f"  [{result.status.value:<8}] {family:<5} {result.summary}")
        if result.gaps:
            print(f"             gaps: {', '.join(result.gaps)}")
        if result.error:
            print(f"             error: {result.error}")

    spend = budget.spend_by_role()
    print("\nspend by role (micro-USD):", spend or "(nothing spent)")
    print(f"budget remaining: {budget.remaining} micro-USD")


async def _run(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

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
        print(f"mcp servers: {len(mcp_clients())} connected")

    families = _parse_families(args.families)

    now = datetime.now(timezone.utc)
    try:
        scope = Scope(entities=args.entities, time_window=(now - timedelta(hours=args.hours), now))
    except ValidationError as exc:
        # Most likely `--hours 0` or a negative value, which makes start >= end.
        print(f"error: invalid scope: {exc.errors()[0]['msg']}", file=sys.stderr)
        return 2

    task = AnalystTask(
        task_id=f"cli-{now:%Y%m%dT%H%M%S}",
        hypothesis_id="cli-hypothesis",
        goal=args.goal,
        scope=scope,
    )

    budget = Budget.from_usd(args.budget_usd)
    outcome = await broker_task(
        task,
        budget,
        model=_DEFAULT_MODEL,
        invoke=_scripted_invoker(families),
    )

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
