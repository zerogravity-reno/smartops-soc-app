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
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args

from pydantic import ValidationError

from contracts import (
    AnalystTask,
    Entity,
    EntityKind,
    FetchStep,
    HypothesisAssessment,
    HypothesisFindings,
    InvestigationContext,
    Scope,
    SubtaskResult,
    TaskClassification,
    ToolFamily,
)
from smartops.broker import (
    DEFAULT_RUNS_DIR,
    RUNS_DIR_ENV_VAR,
    TOOL_BY_FAMILY,
    BrokerRequest,
    broker_task,
    plan_fetch,
)
from smartops.budget import PROVIDER_ENV_VAR, Budget, ModelChoice, model_choice_from_env
from smartops.domains import ALL_FAMILIES
from smartops.subagent_analysts.analyze import analyze, gather
from smartops.subagent_analysts.model import analyst_model_from_env
from smartops.subagents import domain_runner
from smartops.telemetry import configure_telemetry
from smartops.tools.registry import load_mcp_servers, mcp_clients, warm_mcp_clients

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
        "--hypothesis",
        default=None,
        metavar="TEXT",
        help=(
            "the hypothesis to test, in plain language. When given AND "
            "SMARTOPS_ANALYST_MODEL_ARN is configured, the identity/network/endpoint "
            "subagent-analysts analyze the fetched evidence and report whether it "
            "supports or refutes it. Stub for an upstream Analyst agent"
        ),
    )
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
        # 1.0 was below the cost of a single run and guaranteed a confusing
        # failure: one siem subagent reserves a measured $1.2431, so a
        # default-budget run reserved the Broker's hold and was then declined on
        # siem -- the one domain most cases are about -- reporting "budget
        # exhausted" without naming the number. A realistic plan (3 siem steps
        # plus one each edr/vt/ndr) holds ~$7.67 concurrently, and both arms now
        # reserve per step, so 10.0 clears it with headroom. A ceiling is not a
        # bill: reservations settle to actual, measured ~1.27x lower.
        "--budget-usd",
        type=float,
        default=10.0,
        help="investigation budget in USD (default: 10.0)",
    )
    parser.add_argument(
        # A HARD ceiling on total output tokens across the whole investigation,
        # orthogonal to --budget-usd. The USD hold is sized from an optimistic
        # input estimate (~8 expected turns, not the 25-turn worst case), so real
        # settlement can carry spend past the USD ceiling when long subagents
        # overlap. Output is the dominant cost and already per-call capped, so one
        # investigation-wide output ceiling restores a genuine upper bound. Sized
        # generously by default -- a full run reserves well under this -- so it
        # bites only on a runaway, not a normal case.
        "--max-output-tokens",
        type=int,
        default=200_000,
        help="hard ceiling on total output tokens for the whole run (default: 200000)",
    )
    parser.add_argument(
        # The Broker's cumulative output-token ceiling for one run. The library
        # default (4000) is too low for a thinking-heavy model like Sonnet 4.6: it
        # spends the budget authoring the fetch plan and hits limit_output_tokens
        # before emitting a single dispatch, so nothing is fetched. Sonnet's large
        # context affords a much higher ceiling; 16000 clears planning + dispatch.
        "--broker-output-tokens",
        type=int,
        default=16000,
        help="cumulative output-token ceiling for the Broker's run (default: 16000)",
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
        family = result.task_id.split(":")[1] if ":" in result.task_id else "?"
        print(f"  [{result.status.value:<8}] {family:<5} {_result_line(result)}")
        if result.gaps:
            print(f"             gaps: {', '.join(result.gaps)}")
        if result.error:
            print(f"             error: {result.error}")

    spend = budget.spend_by_role()
    print("\nspend by role (micro-USD):", spend or "(nothing spent)")
    print(f"budget remaining: {budget.remaining} micro-USD")


def _print_findings(findings: HypothesisFindings) -> None:
    """Operator view of the blind path.

    Deliberately prints no overall verdict: there isn't one. Each domain judged
    its own evidence without seeing the hypothesis, and rolling those into
    SUPPORTS/REFUTES is the Analyst Agent's job. Printing a stance here would be
    inventing the very thing this path exists to keep separate.

    `rows=N` per citation is shown because it is the cheapest way to see the
    failure the exhibits exposed: a confident judgement resting on a cited block
    that returned nothing.
    """
    print(f"\ndomain findings for hypothesis {findings.hypothesis_id} (analysts were blind):")
    for judgement in findings.findings:
        print(
            f"  [{judgement.domain:<8}] {judgement.disposition:<12} "
            f"conf={judgement.confidence:.2f}"
        )
        if judgement.rationale:
            print(f"             {judgement.rationale}")
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
        "\nno overall stance: deciding whether this supports or refutes the "
        "hypothesis is the Analyst Agent's call, not this layer's."
    )


def _persist_findings(
    task_id: str, findings: HypothesisFindings, run_dir: Path | str | None = None
) -> None:
    """Write findings.json beside the broker's run artifacts.

    Same resolution rules as `_persist_assessment`, and beside it rather than
    replacing it: `assessment.json` is the shape that carries a decided stance,
    and this one deliberately does not.
    """
    if run_dir is not None:
        target_dir = Path(run_dir)
    else:
        base = os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR
        latest = Path(base) / task_id / "latest.txt"
        if not latest.exists():
            return
        target_dir = latest.parent / latest.read_text(encoding="utf-8").strip()

    if target_dir.is_dir():
        # `gather()` already set run_id where the caller knew it; fill it in when
        # it did not, so the artifact still names its own directory.
        stamped = (
            findings if findings.run_id else findings.model_copy(update={"run_id": target_dir.name})
        )
        (target_dir / "findings.json").write_text(
            stamped.model_dump_json(indent=2), encoding="utf-8"
        )


def _print_assessment(assessment: HypothesisAssessment) -> None:
    print(
        f"\nhypothesis assessment: {assessment.overall_stance.upper()} "
        f"(confidence {assessment.confidence:.2f})"
    )
    for verdict in assessment.verdicts:
        print(
            f"  [{verdict.domain:<8}] {verdict.stance:<12} conf={verdict.confidence:.2f}"
            f"  tokens p={verdict.prompt_tokens} g={verdict.generation_tokens}"
        )
        if verdict.rationale:
            print(f"             {verdict.rationale}")
        for observation in verdict.key_observations:
            print(f"               - {observation}")
        if verdict.citations:
            print(f"             cited: {', '.join(verdict.citations)}")

    # Summed here rather than through a contract method. Two such methods existed
    # on `HypothesisFindings` and both read a `verdicts` field that model does not
    # have, so calling either raised `AttributeError`; `HypothesisAssessment`,
    # which does have `verdicts`, never had them at all -- so these two lines have
    # been an `AttributeError` waiting on the shown path, unreached only because
    # production moved to the blind path and stopped calling this function.
    total_p = sum(v.prompt_tokens for v in assessment.verdicts)
    total_g = sum(v.generation_tokens for v in assessment.verdicts)
    print(
        f"\nanalyst tokens: {total_p} prompt + {total_g} generation = {total_p + total_g} total"
    )
    # The per-call ceiling is the 32,768-token context window (prompt + generation).
    # Prompts here are small, so headroom is large; raise SMARTOPS_ANALYST_MAX_GEN_LEN
    # if a verdict looks cut off. Cost is billed per model-copy-minute, not per token.
    print("  (per-call context ceiling is 32,768 tokens; imported-model cost is per warm-minute, not per token)")


def _persist_assessment(
    task_id: str,
    assessment: HypothesisAssessment,
    run_dir: Path | str | None = None,
) -> None:
    """Write assessment.json beside the broker's run artifacts.

    If `run_dir` is passed directly (from `save_run_artifacts`), it writes straight
    there to avoid pointer race conditions. Otherwise falls back to resolving via
    `latest.txt`. Best-effort: missing dir skips silently.
    """
    if run_dir is not None:
        target_dir = Path(run_dir)
    else:
        base = os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR
        latest = Path(base) / task_id / "latest.txt"
        if not latest.exists():
            return
        target_dir = latest.parent / latest.read_text(encoding="utf-8").strip()

    if target_dir.is_dir():
        # Stamp the run directory onto the artifact. The analysis layer cannot
        # know it -- the persistence layer chooses it -- so it is set here, and
        # it makes the file self-describing if it is ever copied out of its
        # folder.
        stamped = assessment.model_copy(update={"run_id": target_dir.name})
        (target_dir / "assessment.json").write_text(
            stamped.model_dump_json(indent=2), encoding="utf-8"
        )


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
    # Resolve every client's tools now, so two concurrent dispatches in one
    # Broker turn cannot race each other's connection start-up.
    await warm_mcp_clients()
    if args.verbose:
        # Which file supplied the settings is the first thing you want when a
        # credential "isn't being picked up".
        print(f"env file:    {env_file or '(none found)'}")
        print(f"mcp servers: {len(mcp_clients())} built")

    families = _parse_families(args.families)

    now = datetime.now(UTC)
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

    budget = Budget.from_usd(
        args.budget_usd, max_output_tokens_total=args.max_output_tokens
    )

    if args.skills is not None:
        from smartops.skills import pinned_skills_enabled
        skills_ctx = pinned_skills_enabled(args.skills)
    else:
        import contextlib
        skills_ctx = contextlib.nullcontext()

    with skills_ctx:
        # With a real model, domains get a real subagent; without one there is
        # nothing to drive a tool loop, so the Broker's stub stands in and reports
        # what each family *could* have used. `vt` answers either way -- its lookup
        # needs no model at all.
        run_subagent = (
            domain_runner(model=choice, budget=budget, turns=args.subagent_turns)
            if choice is not None
            else None
        )

        try:
            outcome = await broker_task(
                task,
                budget,
                model=model,
                invoke=invoke,
                run_subagent=run_subagent,
                max_output_tokens=args.broker_output_tokens,
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

    # Analysis layer: only when a hypothesis is given and the analyst model is
    # configured. `--scripted` forces no model calls at all, analysts included.
    if args.hypothesis:
        analyst_model = None if args.scripted else analyst_model_from_env()
        if analyst_model is None:
            print(
                "\nanalysis: skipped (set SMARTOPS_ANALYST_MODEL_ARN to enable, "
                "and do not pass --scripted)"
            )
        elif outcome.report is None:
            print("\nanalysis: skipped (the broker produced no report)")
        else:
            # The BLIND path. The analysts never receive `args.hypothesis` --
            # `gather` takes no `InvestigationContext` and `build_facts_user_turn`
            # has no hypothesis parameter, so it cannot reach them. The hypothesis
            # is carried on the result only, as the attachment point where three
            # independent judgements are joined to the claim they were formed
            # without.
            #
            # `analyze()`/`combine()` still exist and still produce a decided
            # stance, but nothing calls them here any more: a stance formed by an
            # analyst that was shown the hypothesis is the anchoring this path
            # exists to remove.
            run_dir = getattr(outcome, "run_dir", None)
            try:
                findings = await gather(
                    outcome.report,
                    scope,
                    analyst_model,
                    run_id=Path(run_dir).name if run_dir else None,
                    hypothesis=args.hypothesis,
                )
            except Exception as exc:
                print(
                    f"\nanalysis failed: {type(exc).__name__}: {exc}", file=sys.stderr
                )
                logging.getLogger(__name__).debug("gather failed", exc_info=True)
            else:
                _print_findings(findings)
                _persist_findings(task.task_id, findings, run_dir=run_dir)

    return 0


def run() -> None:
    """Console-script entry point."""
    import asyncio

    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    run()
