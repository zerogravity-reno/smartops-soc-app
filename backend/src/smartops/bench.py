"""Requirement R2: `smartops-bench` Interleaved A/B Runner (Task C8 / §8).

Executes N interleaved benchmark runs per topology arm (Arm S: Hierarchical Multi-Agent Task
Broker, Arm F: Flat Broker Baseline) against pre-defined or custom investigative test cases.

Collects metrics per run:
- Wall-clock duration
- Total cost & cost by role (`Budget.spend_by_role()`)
- Input / output token counts (`accumulated_usage`)
- Sequential model turns
- Queries run count
- Index scoping correctness (`guards.IndexScopeGuard` / allowlist check)
- Findings completeness (row counts per category)
- Routing correctness (`dispatched` vs expected families)
- Failure mode (`stop_reason`)

Computes statistical aggregation (median & spread) across arms and generates
a comparative report identifying statistically significant topology differences
or reporting "no measurable difference". Supports offline dry-runs with --scripted / --mock.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, Field

from contracts import AnalystTask, Entity, Scope, SubtaskResult, ToolFamily
from contracts.findings import SiemFindings, VtFindings
from smartops.broker import BROKER_ROLE, BrokerOutcome, broker_task
from smartops.broker_flat import BROKER_FLAT_ROLE, broker_flat_task
from smartops.budget import Budget, ModelChoice, model_choice_from_env
from smartops.domains import ALL_FAMILIES, spec_for
from smartops.guards import IndexScopeGuard
from smartops.main import _PLACEHOLDER_MODEL, _scripted_invoker

logger = logging.getLogger(__name__)


# Standard benchmark test cases
DEFAULT_BOTSV3_TASK = AnalystTask(
    task_id="botsv3_coinhive",
    hypothesis_id="coinhive-cryptomining",
    goal="Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?",
    scope=Scope(
        entities=[
            Entity(kind="domain", value="coinhive.com"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=timezone.utc),
        ),
    ),
)

BENCHMARK_CASES: dict[str, tuple[AnalystTask, list[ToolFamily]]] = {
    "botsv3_coinhive": (DEFAULT_BOTSV3_TASK, ["siem", "vt"]),
}


class RunMetrics(BaseModel):
    """Metrics captured for a single benchmark run."""

    arm: str  # "S" or "F"
    case_id: str
    run_index: int
    wall_clock_seconds: float
    total_cost_micro_usd: int
    cost_by_role: dict[str, int]
    input_tokens: int
    output_tokens: int
    sequential_turns: int
    queries_run_count: int
    index_scoping_correct: bool
    findings_completeness: dict[str, int]
    routing_correctness: bool
    stop_reason: str
    dispatched: list[str]


class MetricStats(BaseModel):
    """Statistical summary (median and spread) for a single metric."""

    median: float
    min: float
    max: float
    spread: float


class ArmSummary(BaseModel):
    """Summary statistics across multiple runs for a single arm."""

    arm: str
    runs_count: int
    wall_clock_seconds: MetricStats
    total_cost_micro_usd: MetricStats
    input_tokens: MetricStats
    output_tokens: MetricStats
    sequential_turns: MetricStats
    queries_run_count: MetricStats
    total_findings_rows: MetricStats
    index_scoping_correct_pct: float
    routing_correctness_pct: float
    stop_reasons: dict[str, int]
    cost_by_role_median: dict[str, float]


class ComparisonDetail(BaseModel):
    """Comparison result for a single metric across arms."""

    metric_name: str
    median_S: float | None = None
    median_F: float | None = None
    delta: float | None = None
    within_arm_spread: float | None = None
    difference_status: str
    winner: str


class BenchmarkReport(BaseModel):
    """Complete benchmark execution report."""

    timestamp: str
    cases: list[str]
    arms: list[str]
    runs_per_arm: int
    scripted: bool
    raw_runs: list[RunMetrics]
    arm_summaries: dict[str, ArmSummary]
    comparisons: list[ComparisonDetail]

    def to_markdown(self) -> str:
        lines: list[str] = [
            "# Benchmark Report — SmartOps SOC A/B Runner",
            "",
            f"- **Timestamp:** {self.timestamp}",
            f"- **Cases:** {', '.join(self.cases)}",
            f"- **Arms:** {', '.join(self.arms)}",
            f"- **Runs per arm:** {self.runs_per_arm}",
            f"- **Scripted Mode:** {self.scripted}",
            "",
            "## Summary Comparison",
            "",
            "| Metric | Arm S (Hierarchical) | Arm F (Flat) | Comparison |",
            "|---|---|---|---|",
        ]

        def _fmt_arm(arm: str, attr: str, fmt: str = ".2f") -> str:
            if arm not in self.arm_summaries:
                return "N/A"
            stats = getattr(self.arm_summaries[arm], attr, None)
            if stats is None:
                return "N/A"
            if isinstance(stats, MetricStats):
                return f"{stats.median:{fmt}} ({stats.min:{fmt}} - {stats.max:{fmt}})"
            return str(stats)

        def _fmt_pct(arm: str, attr: str) -> str:
            if arm not in self.arm_summaries:
                return "N/A"
            val = getattr(self.arm_summaries[arm], attr, None)
            return f"{val:.1f}%" if val is not None else "N/A"

        rows = [
            ("Wall clock (s)", "wall_clock_seconds", ".3f"),
            ("Total Cost (micro-USD)", "total_cost_micro_usd", ".0f"),
            ("Input Tokens", "input_tokens", ".0f"),
            ("Output Tokens", "output_tokens", ".0f"),
            ("Sequential Turns", "sequential_turns", ".0f"),
            ("Queries Run", "queries_run_count", ".0f"),
            ("Findings Rows", "total_findings_rows", ".0f"),
        ]

        comp_by_metric = {c.metric_name: c for c in self.comparisons}

        for label, attr, fmt in rows:
            val_s = _fmt_arm("S", attr, fmt)
            val_f = _fmt_arm("F", attr, fmt)
            comp = comp_by_metric.get(attr)
            if comp:
                comp_str = f"{comp.difference_status} (Winner: {comp.winner})"
            else:
                comp_str = "N/A"
            lines.append(f"| {label} | {val_s} | {val_f} | {comp_str} |")

        lines.append(
            f"| Index Scoping (% correct) | {_fmt_pct('S', 'index_scoping_correct_pct')} | "
            f"{_fmt_pct('F', 'index_scoping_correct_pct')} | "
            f"{comp_by_metric.get('index_scoping_correct_pct', ComparisonDetail(metric_name='', difference_status='N/A', winner='N/A')).difference_status} |"
        )
        lines.append(
            f"| Routing Correctness (% correct) | {_fmt_pct('S', 'routing_correctness_pct')} | "
            f"{_fmt_pct('F', 'routing_correctness_pct')} | "
            f"{comp_by_metric.get('routing_correctness_pct', ComparisonDetail(metric_name='', difference_status='N/A', winner='N/A')).difference_status} |"
        )

        lines.extend(["", "## Failure Modes by Arm", ""])
        for arm in self.arms:
            if arm in self.arm_summaries:
                reasons = self.arm_summaries[arm].stop_reasons
                reasons_str = ", ".join(f"{k}: {v}" for k, v in reasons.items()) or "(none)"
                lines.append(f"- **Arm {arm}:** {reasons_str}")

        lines.extend(["", "## Cost by Role (Median micro-USD)", ""])
        for arm in self.arms:
            if arm in self.arm_summaries:
                role_costs = self.arm_summaries[arm].cost_by_role_median
                role_str = ", ".join(f"{k}: {v:.0f}" for k, v in role_costs.items()) or "(none)"
                lines.append(f"- **Arm {arm}:** {role_str}")

        return "\n".join(lines)


def check_index_scoping(results: list[SubtaskResult]) -> bool:
    """Verify index scoping correctness across all subtask results.

    Returns False if any query targets a disallowed index or fails IndexScopeGuard check.
    """
    for res in results:
        if not res.queries_run:
            continue
        family = res.task_id.split(":")[1] if ":" in res.task_id else "siem"
        try:
            spec = spec_for(family)  # type: ignore[arg-type]
            allowlist = spec.index_allowlist
        except KeyError:
            allowlist = ("botsv3",)

        if allowlist is not None:
            guard = IndexScopeGuard(family, allowlist)
            for q in res.queries_run:
                reason = guard._reject_reason(q.query)
                if reason is not None:
                    return False
    return True


def extract_findings_completeness(results: list[SubtaskResult]) -> dict[str, int]:
    """Extract category row counts from subtask result findings."""
    counts: dict[str, int] = {
        "dns_resolutions": 0,
        "connections": 0,
        "processes": 0,
        "auth_events": 0,
        "uncategorised": 0,
        "vt_verdicts": 0,
    }

    for res in results:
        if res.findings is not None:
            if isinstance(res.findings, SiemFindings):
                counts["dns_resolutions"] += sum(rs.row_count for rs in res.findings.dns_resolutions)
                counts["connections"] += sum(rs.row_count for rs in res.findings.connections)
                counts["processes"] += sum(rs.row_count for rs in res.findings.processes)
                counts["auth_events"] += sum(rs.row_count for rs in res.findings.auth_events)
                counts["uncategorised"] += sum(rs.row_count for rs in res.findings.uncategorised)
            elif isinstance(res.findings, VtFindings):
                counts["vt_verdicts"] += len(res.findings.verdicts)
    return counts


async def _execute_single_run(
    task: AnalystTask,
    arm: str,
    run_index: int,
    expected_families: list[ToolFamily],
    *,
    model: ModelChoice,
    budget_usd: float = 1.0,
    scripted: bool = False,
    families: list[ToolFamily] | None = None,
) -> RunMetrics:
    budget = Budget.from_usd(budget_usd)
    target_families = list(families) if families is not None else list(expected_families)

    t0 = time.perf_counter()
    stop_reason = "end_turn"

    if scripted:
        invoke = _scripted_invoker(target_families)
    else:
        invoke = None

    if arm == "S":
        outcome = await broker_task(
            task,
            budget,
            model=model,
            invoke=invoke,
            run_subagent=None,
        )
    elif arm == "F":
        outcome = await broker_flat_task(
            task,
            budget,
            model=model,
            invoke=invoke,
            scripted=scripted,
            families=target_families,
        )
    else:
        raise ValueError(f"Unknown arm: {arm!r}")

    wall_clock = time.perf_counter() - t0

    cost_by_role = budget.spend_by_role()
    total_cost = sum(cost_by_role.values())

    input_tokens = sum(entry.usage.input_tokens for entry in budget.ledger)
    output_tokens = sum(entry.usage.output_tokens for entry in budget.ledger)
    turns = len(budget.ledger)

    queries_count = sum(len(res.queries_run) for res in outcome.results if res.queries_run)
    scoping_correct = check_index_scoping(outcome.results)
    findings_map = extract_findings_completeness(outcome.results)
    routing_correct = set(outcome.dispatched) == set(expected_families)

    if outcome.classification and outcome.classification.rationale:
        if "stop_reason=" in outcome.classification.rationale:
            stop_reason = outcome.classification.rationale.split("stop_reason=")[1].split(")")[0]
        elif scripted:
            stop_reason = "scripted"

    return RunMetrics(
        arm=arm,
        case_id=task.task_id,
        run_index=run_index,
        wall_clock_seconds=round(wall_clock, 4),
        total_cost_micro_usd=total_cost,
        cost_by_role=cost_by_role,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        sequential_turns=turns,
        queries_run_count=queries_count,
        index_scoping_correct=scoping_correct,
        findings_completeness=findings_map,
        routing_correctness=routing_correct,
        stop_reason=stop_reason,
        dispatched=[str(d) for d in outcome.dispatched],
    )


def compute_metric_stats(vals: Sequence[float]) -> MetricStats:
    """Compute median, min, max, and spread for a list of values."""
    if not vals:
        return MetricStats(median=0.0, min=0.0, max=0.0, spread=0.0)
    s = sorted(vals)
    n = len(s)
    median = s[n // 2] if n % 2 != 0 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    min_val = s[0]
    max_val = s[-1]
    spread = max_val - min_val
    return MetricStats(median=float(median), min=float(min_val), max=float(max_val), spread=float(spread))


def compute_arm_summary(arm: str, runs: list[RunMetrics]) -> ArmSummary:
    """Compute ArmSummary containing median and spread for all metrics across runs."""
    wall_clocks = [r.wall_clock_seconds for r in runs]
    costs = [float(r.total_cost_micro_usd) for r in runs]
    inputs = [float(r.input_tokens) for r in runs]
    outputs = [float(r.output_tokens) for r in runs]
    turns = [float(r.sequential_turns) for r in runs]
    queries = [float(r.queries_run_count) for r in runs]
    total_rows = [float(sum(r.findings_completeness.values())) for r in runs]

    index_pct = (sum(1 for r in runs if r.index_scoping_correct) / len(runs)) * 100.0 if runs else 0.0
    routing_pct = (sum(1 for r in runs if r.routing_correctness) / len(runs)) * 100.0 if runs else 0.0

    stop_reasons: dict[str, int] = {}
    for r in runs:
        stop_reasons[r.stop_reason] = stop_reasons.get(r.stop_reason, 0) + 1

    all_roles: set[str] = set()
    for r in runs:
        all_roles.update(r.cost_by_role.keys())

    cost_by_role_median: dict[str, float] = {}
    for role in all_roles:
        role_vals = [float(r.cost_by_role.get(role, 0)) for r in runs]
        cost_by_role_median[role] = compute_metric_stats(role_vals).median

    return ArmSummary(
        arm=arm,
        runs_count=len(runs),
        wall_clock_seconds=compute_metric_stats(wall_clocks),
        total_cost_micro_usd=compute_metric_stats(costs),
        input_tokens=compute_metric_stats(inputs),
        output_tokens=compute_metric_stats(outputs),
        sequential_turns=compute_metric_stats(turns),
        queries_run_count=compute_metric_stats(queries),
        total_findings_rows=compute_metric_stats(total_rows),
        index_scoping_correct_pct=round(index_pct, 1),
        routing_correctness_pct=round(routing_pct, 1),
        stop_reasons=stop_reasons,
        cost_by_role_median=cost_by_role_median,
    )


def compare_arms(summaries: dict[str, ArmSummary]) -> list[ComparisonDetail]:
    """Compare arms S and F, identifying statistically significant differences.

    If delta between medians is less than or equal to within-arm spread (max of arm spreads),
    the result is reported as 'no measurable difference'.
    """
    comparisons: list[ComparisonDetail] = []

    if "S" not in summaries or "F" not in summaries:
        return comparisons

    sum_S = summaries["S"]
    sum_F = summaries["F"]

    metrics_to_compare = [
        ("wall_clock_seconds", True),  # lower is better
        ("total_cost_micro_usd", True),
        ("input_tokens", True),
        ("output_tokens", True),
        ("sequential_turns", True),
        ("queries_run_count", True),
        ("total_findings_rows", False),  # higher is better
    ]

    for attr, lower_is_better in metrics_to_compare:
        stats_S = getattr(sum_S, attr)
        stats_F = getattr(sum_F, attr)

        delta = abs(stats_S.median - stats_F.median)
        within_arm_spread = max(stats_S.spread, stats_F.spread)

        if delta <= within_arm_spread or delta == 0.0:
            diff_status = "no measurable difference"
            winner = "none"
        else:
            diff_status = "statistically significant difference"
            if lower_is_better:
                winner = "S" if stats_S.median < stats_F.median else "F"
            else:
                winner = "S" if stats_S.median > stats_F.median else "F"

        comparisons.append(
            ComparisonDetail(
                metric_name=attr,
                median_S=stats_S.median,
                median_F=stats_F.median,
                delta=round(delta, 4),
                within_arm_spread=round(within_arm_spread, 4),
                difference_status=diff_status,
                winner=winner,
            )
        )

    for pct_attr in ["index_scoping_correct_pct", "routing_correctness_pct"]:
        val_S = getattr(sum_S, pct_attr)
        val_F = getattr(sum_F, pct_attr)
        delta = abs(val_S - val_F)
        diff_status = "no measurable difference" if delta < 0.1 else "statistically significant difference"
        winner = "none" if delta < 0.1 else ("S" if val_S > val_F else "F")
        comparisons.append(
            ComparisonDetail(
                metric_name=pct_attr,
                median_S=val_S,
                median_F=val_F,
                delta=round(delta, 1),
                within_arm_spread=0.0,
                difference_status=diff_status,
                winner=winner,
            )
        )

    return comparisons


async def run_interleaved_benchmark(
    *,
    cases: list[str],
    arms: list[str] = ["S", "F"],
    runs_per_arm: int = 3,
    scripted: bool = False,
    model: ModelChoice | None = None,
    budget_usd: float = 1.0,
) -> BenchmarkReport:
    """Execute interleaved benchmark runs across cases and arms.

    Interleaving sequence for runs_per_arm=3 and arms=['S', 'F']:
    [S, F, S, F, S, F].
    """
    model_choice = model or (None if scripted else model_choice_from_env()) or _PLACEHOLDER_MODEL

    raw_runs: list[RunMetrics] = []

    for case_name in cases:
        if case_name in BENCHMARK_CASES:
            task, expected_families = BENCHMARK_CASES[case_name]
        else:
            task = AnalystTask(
                task_id=case_name,
                hypothesis_id=f"hypothesis-{case_name}",
                goal=f"Benchmark investigation for case {case_name}",
                scope=Scope(
                    entities=[Entity(kind="domain", value="coinhive.com")],
                    time_window=(
                        datetime(2018, 8, 20, 0, 0, 0, tzinfo=timezone.utc),
                        datetime(2018, 8, 21, 0, 0, 0, tzinfo=timezone.utc),
                    ),
                ),
            )
            expected_families = ["siem", "vt"]

        # Interleaved execution: run 0 (S, F), run 1 (S, F), run 2 (S, F)
        for run_idx in range(runs_per_arm):
            for arm in arms:
                logger.info(
                    "Executing benchmark case=%s arm=%s run=%d/%d (scripted=%s)",
                    case_name,
                    arm,
                    run_idx + 1,
                    runs_per_arm,
                    scripted,
                )
                metrics = await _execute_single_run(
                    task,
                    arm,
                    run_idx,
                    expected_families,
                    model=model_choice,
                    budget_usd=budget_usd,
                    scripted=scripted,
                )
                raw_runs.append(metrics)

    arm_summaries: dict[str, ArmSummary] = {}
    for arm in arms:
        arm_runs = [r for r in raw_runs if r.arm == arm]
        if arm_runs:
            arm_summaries[arm] = compute_arm_summary(arm, arm_runs)

    comparisons = compare_arms(arm_summaries)

    return BenchmarkReport(
        timestamp=datetime.now(timezone.utc).isoformat(),
        cases=cases,
        arms=arms,
        runs_per_arm=runs_per_arm,
        scripted=scripted,
        raw_runs=raw_runs,
        arm_summaries=arm_summaries,
        comparisons=comparisons,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartops-bench",
        description="smartops-bench: Interleaved A/B benchmark runner for Task Broker",
    )
    parser.add_argument(
        "--cases",
        default="botsv3_coinhive",
        help="comma-separated benchmark cases to run (default: botsv3_coinhive)",
    )
    parser.add_argument(
        "--arms",
        default="S,F",
        help="comma-separated execution arms to benchmark, e.g. S,F (default: S,F)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="number of interleaved runs per arm (default: 3)",
    )
    parser.add_argument(
        "--scripted",
        "--mock",
        action="store_true",
        dest="scripted",
        help="run in offline/mock mode (zero cost, zero LLM calls)",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="output file path for JSON or Markdown benchmark report",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=1.0,
        help="budget per run in USD (default: 1.0)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable verbose INFO logging",
    )
    return parser


async def _run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    arms = [a.strip().upper() for a in args.arms.split(",") if a.strip()]

    report = await run_interleaved_benchmark(
        cases=cases,
        arms=arms,
        runs_per_arm=args.runs,
        scripted=args.scripted,
        budget_usd=args.budget_usd,
    )

    markdown_report = report.to_markdown()
    print(markdown_report)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.suffix.lower() == ".json":
            out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        else:
            out_path.write_text(markdown_report, encoding="utf-8")
        print(f"\nReport written to {out_path}")

    return 0


def run(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    raise SystemExit(asyncio.run(_run(argv)))


main = run


if __name__ == "__main__":
    run()
