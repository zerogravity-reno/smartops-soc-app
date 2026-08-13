"""Test suite for smartops-bench interleaved A/B benchmark runner (Task C8 / §8).

Verifies:
1. Interleaved execution sequence [S, F, S, F, S, F].
2. Accuracy of duration, tokens, cost per role, queries count, index scoping, findings, and stop_reason.
3. Median & spread statistical computation and topology comparison logic.
4. CLI flag handling and output file generation (JSON and Markdown).
"""

import asyncio
import contextlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from contracts import (
    AnalystTask,
    Entity,
    QueryRun,
    ResultSet,
    Scope,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    VtFindings,
    VtVerdict,
)

from smartops.bench import (
    BENCHMARK_CASES,
    ArmSummary,
    BenchmarkReport,
    ComparisonDetail,
    MetricStats,
    RunMetrics,
    _execute_single_run,
    _pinned_skills,
    _run,
    check_index_scoping,
    compare_arms,
    compute_arm_summary,
    compute_metric_stats,
    extract_findings_completeness,
    run,
    run_interleaved_benchmark,
)
from smartops.main import _PLACEHOLDER_MODEL
from smartops.skills import SKILLS_ENABLED_ENV_VAR, skills_enabled


class TestBenchRunnerInterleaving:
    """Verifies interleaved execution sequence [S, F, S, F, S, F]."""

    @pytest.mark.asyncio
    async def test_interleaved_sequence_order(self):
        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive"],
            arms=["S", "F"],
            runs_per_arm=3,
            scripted=True,
        )

        sequence = [r.arm for r in report.raw_runs]
        assert sequence == ["S", "F", "S", "F", "S", "F"], (
            f"Execution sequence must be interleaved [S, F, S, F, S, F], got {sequence}"
        )

        indexed_sequence = [(r.arm, r.run_index) for r in report.raw_runs]
        assert indexed_sequence == [
            ("S", 0),
            ("F", 0),
            ("S", 1),
            ("F", 1),
            ("S", 2),
            ("F", 2),
        ]

    @pytest.mark.asyncio
    async def test_interleaved_execution_multiple_cases(self):
        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive", "custom_case"],
            arms=["S", "F"],
            runs_per_arm=2,
            scripted=True,
        )

        assert len(report.raw_runs) == 8  # 2 cases * 2 arms * 2 runs
        case1_sequence = [r.arm for r in report.raw_runs[:4]]
        case2_sequence = [r.arm for r in report.raw_runs[4:]]
        assert case1_sequence == ["S", "F", "S", "F"]
        assert case2_sequence == ["S", "F", "S", "F"]


class TestBenchMetricsCollection:
    """Verifies accuracy of duration, tokens, cost per role, queries, index scoping, findings, and stop_reason."""

    def test_check_index_scoping_valid(self):
        res = SubtaskResult(
            task_id="task:siem",
            status=SubtaskStatus.OK,
            queries_run=[QueryRun(query="index=botsv3 sourcetype=dns", category="dns_resolutions")],
        )
        assert check_index_scoping([res]) is True

    def test_check_index_scoping_invalid_wildcard(self):
        res = SubtaskResult(
            task_id="task:siem",
            status=SubtaskStatus.OK,
            queries_run=[QueryRun(query="index=* sourcetype=dns", category="dns_resolutions")],
        )
        assert check_index_scoping([res]) is False

    def test_check_index_scoping_unpinned_query(self):
        res = SubtaskResult(
            task_id="task:siem",
            status=SubtaskStatus.OK,
            queries_run=[QueryRun(query="sourcetype=dns | head 5", category="dns_resolutions")],
        )
        assert check_index_scoping([res]) is False

    def test_extract_findings_completeness(self):
        siem_findings = SiemFindings(
            dns_resolutions=[
                ResultSet(query="q1", row_count=3, rows=[{"a": 1}, {"a": 2}, {"a": 3}])
            ],
            connections=[
                ResultSet(query="q2", row_count=2, rows=[{"b": 1}, {"b": 2}])
            ],
        )
        vt_findings = VtFindings(
            verdicts=[
                VtVerdict(kind="domain", value="coinhive.com", found=True, malicious=5, suspicious=0, harmless=10, undetected=0)
            ]
        )

        res_siem = SubtaskResult(task_id="t:siem", status=SubtaskStatus.OK, findings=siem_findings)
        res_vt = SubtaskResult(task_id="t:vt", status=SubtaskStatus.OK, findings=vt_findings)

        counts = extract_findings_completeness([res_siem, res_vt])
        assert counts.get("dns_resolutions") == 3
        assert counts.get("connections") == 2
        assert counts.get("vt_verdicts") == 1

    @staticmethod
    def _capture_run_subagent(monkeypatch):
        """Record what the bench hands `broker_task` as its subagent runner."""
        from contracts import TaskClassification

        from smartops import bench as bench_mod
        from smartops.broker import BrokerOutcome

        seen: dict = {}

        async def fake_broker_task(task, budget, **kwargs):
            seen["run_subagent"] = kwargs.get("run_subagent")
            return BrokerOutcome(
                results=[],
                classification=TaskClassification(tool_families=[], rationale="captured"),
                dispatched=[],
            )

        monkeypatch.setattr(bench_mod, "broker_task", fake_broker_task)
        return seen

    @pytest.mark.asyncio
    async def test_a_live_arm_s_run_gets_a_real_subagent(self, monkeypatch):
        """Arm S's entire claim is that a dedicated subagent executes the step.

        The bench passed `run_subagent=None`, which `_dispatch()` resolves to
        `broker._stub_subagent` -- no model, no tool call, `NO_DATA` and a tool
        count. Only `vt` carries a model-free enricher, so every other family
        (siem included -- the domain the case is about) retrieved nothing, while
        Arm F ran a real per-step model loop against live tools. The A/B was
        comparing a real arm against a hollow one.
        """
        seen = self._capture_run_subagent(monkeypatch)
        task, expected = BENCHMARK_CASES["botsv3_coinhive"]

        await _execute_single_run(
            task,
            arm="S",
            run_index=0,
            expected_families=expected,
            model=_PLACEHOLDER_MODEL,
            budget_usd=1.0,
            scripted=False,
        )

        assert seen["run_subagent"] is not None, (
            "a live bench run must hand Arm S a real subagent runner; None falls "
            "back to _stub_subagent, which never calls a model or a tool"
        )

    @pytest.mark.asyncio
    async def test_a_scripted_arm_s_run_keeps_the_stub(self, monkeypatch):
        """`--scripted` exists to exercise the plumbing without a provider, and
        the stub is what makes that possible. Wiring a real runner here would
        make every offline dry-run try to reach a model."""
        seen = self._capture_run_subagent(monkeypatch)
        task, expected = BENCHMARK_CASES["botsv3_coinhive"]

        await _execute_single_run(
            task,
            arm="S",
            run_index=0,
            expected_families=expected,
            model=_PLACEHOLDER_MODEL,
            budget_usd=1.0,
            scripted=True,
        )

        assert seen["run_subagent"] is None

    @pytest.mark.asyncio
    async def test_execute_single_run_scripted_metrics(self):
        task, expected = BENCHMARK_CASES["botsv3_coinhive"]
        metrics = await _execute_single_run(
            task,
            arm="S",
            run_index=0,
            expected_families=expected,
            model=_PLACEHOLDER_MODEL,
            budget_usd=1.0,
            scripted=True,
        )

        assert metrics.arm == "S"
        assert metrics.case_id == "botsv3_coinhive"
        assert metrics.wall_clock_seconds >= 0.0
        assert metrics.total_cost_micro_usd >= 0
        assert isinstance(metrics.cost_by_role, dict)
        assert metrics.input_tokens >= 0
        assert metrics.output_tokens >= 0
        assert metrics.sequential_turns >= 0
        assert metrics.queries_run_count >= 0
        assert metrics.index_scoping_correct is True
        assert metrics.routing_correctness is True
        assert metrics.stop_reason in ("scripted", "end_turn")
        assert set(metrics.dispatched) == set(expected)


class TestBenchStatsComputation:
    """Verifies median and spread computation and topology comparison logic."""

    def test_compute_metric_stats_odd(self):
        stats = compute_metric_stats([10.0, 30.0, 20.0])
        assert stats.median == 20.0
        assert stats.min == 10.0
        assert stats.max == 30.0
        assert stats.spread == 20.0

    def test_compute_metric_stats_even(self):
        stats = compute_metric_stats([10.0, 40.0, 20.0, 30.0])
        assert stats.median == 25.0
        assert stats.min == 10.0
        assert stats.max == 40.0
        assert stats.spread == 30.0

    def test_compute_arm_summary(self):
        runs = [
            RunMetrics(
                arm="S",
                case_id="case1",
                run_index=0,
                wall_clock_seconds=10.0,
                total_cost_micro_usd=1000,
                cost_by_role={"broker": 1000},
                input_tokens=100,
                output_tokens=50,
                sequential_turns=2,
                queries_run_count=3,
                index_scoping_correct=True,
                findings_completeness={"dns": 5},
                routing_correctness=True,
                stop_reason="end_turn",
                dispatched=["siem", "vt"],
            ),
            RunMetrics(
                arm="S",
                case_id="case1",
                run_index=1,
                wall_clock_seconds=12.0,
                total_cost_micro_usd=1200,
                cost_by_role={"broker": 1200},
                input_tokens=120,
                output_tokens=60,
                sequential_turns=2,
                queries_run_count=3,
                index_scoping_correct=True,
                findings_completeness={"dns": 5},
                routing_correctness=True,
                stop_reason="end_turn",
                dispatched=["siem", "vt"],
            ),
            RunMetrics(
                arm="S",
                case_id="case1",
                run_index=2,
                wall_clock_seconds=14.0,
                total_cost_micro_usd=1400,
                cost_by_role={"broker": 1400},
                input_tokens=140,
                output_tokens=70,
                sequential_turns=3,
                queries_run_count=4,
                index_scoping_correct=True,
                findings_completeness={"dns": 5},
                routing_correctness=True,
                stop_reason="end_turn",
                dispatched=["siem", "vt"],
            ),
        ]

        summary = compute_arm_summary("S", runs)
        assert summary.arm == "S"
        assert summary.runs_count == 3
        assert summary.wall_clock_seconds.median == 12.0
        assert summary.wall_clock_seconds.spread == 4.0
        assert summary.total_cost_micro_usd.median == 1200.0
        assert summary.index_scoping_correct_pct == 100.0
        assert summary.routing_correctness_pct == 100.0
        assert summary.stop_reasons == {"end_turn": 3}
        assert summary.cost_by_role_median["broker"] == 1200.0

    def test_compare_arms_statistically_significant(self):
        sum_S = ArmSummary(
            arm="S",
            runs_count=3,
            wall_clock_seconds=MetricStats(median=100.0, min=98.0, max=102.0, spread=4.0),
            total_cost_micro_usd=MetricStats(median=5000.0, min=4900.0, max=5100.0, spread=200.0),
            input_tokens=MetricStats(median=1000.0, min=950.0, max=1050.0, spread=100.0),
            output_tokens=MetricStats(median=500.0, min=480.0, max=520.0, spread=40.0),
            sequential_turns=MetricStats(median=10.0, min=9.0, max=11.0, spread=2.0),
            queries_run_count=MetricStats(median=5.0, min=5.0, max=5.0, spread=0.0),
            total_findings_rows=MetricStats(median=10.0, min=10.0, max=10.0, spread=0.0),
            index_scoping_correct_pct=100.0,
            routing_correctness_pct=100.0,
            stop_reasons={"end_turn": 3},
            cost_by_role_median={"broker": 5000.0},
        )

        sum_F = ArmSummary(
            arm="F",
            runs_count=3,
            wall_clock_seconds=MetricStats(median=20.0, min=18.0, max=22.0, spread=4.0),
            total_cost_micro_usd=MetricStats(median=1000.0, min=900.0, max=1100.0, spread=200.0),
            input_tokens=MetricStats(median=200.0, min=150.0, max=250.0, spread=100.0),
            output_tokens=MetricStats(median=100.0, min=80.0, max=120.0, spread=40.0),
            sequential_turns=MetricStats(median=2.0, min=2.0, max=2.0, spread=0.0),
            queries_run_count=MetricStats(median=5.0, min=5.0, max=5.0, spread=0.0),
            total_findings_rows=MetricStats(median=10.0, min=10.0, max=10.0, spread=0.0),
            index_scoping_correct_pct=100.0,
            routing_correctness_pct=100.0,
            stop_reasons={"end_turn": 3},
            cost_by_role_median={"broker_flat": 1000.0},
        )

        comparisons = compare_arms({"S": sum_S, "F": sum_F})
        comp_wall = next(c for c in comparisons if c.metric_name == "wall_clock_seconds")
        assert comp_wall.difference_status == "statistically significant difference"
        assert comp_wall.winner == "F"  # F is faster (20s vs 100s)

        comp_cost = next(c for c in comparisons if c.metric_name == "total_cost_micro_usd")
        assert comp_cost.difference_status == "statistically significant difference"
        assert comp_cost.winner == "F"  # F is cheaper

    def test_compare_arms_no_measurable_difference(self):
        sum_S = ArmSummary(
            arm="S",
            runs_count=3,
            wall_clock_seconds=MetricStats(median=10.0, min=5.0, max=15.0, spread=10.0),
            total_cost_micro_usd=MetricStats(median=1000.0, min=800.0, max=1200.0, spread=400.0),
            input_tokens=MetricStats(median=100.0, min=50.0, max=150.0, spread=100.0),
            output_tokens=MetricStats(median=50.0, min=20.0, max=80.0, spread=60.0),
            sequential_turns=MetricStats(median=3.0, min=2.0, max=4.0, spread=2.0),
            queries_run_count=MetricStats(median=2.0, min=1.0, max=3.0, spread=2.0),
            total_findings_rows=MetricStats(median=5.0, min=2.0, max=8.0, spread=6.0),
            index_scoping_correct_pct=100.0,
            routing_correctness_pct=100.0,
            stop_reasons={"end_turn": 3},
            cost_by_role_median={"broker": 1000.0},
        )

        sum_F = ArmSummary(
            arm="F",
            runs_count=3,
            wall_clock_seconds=MetricStats(median=12.0, min=7.0, max=17.0, spread=10.0),
            total_cost_micro_usd=MetricStats(median=1100.0, min=900.0, max=1300.0, spread=400.0),
            input_tokens=MetricStats(median=110.0, min=60.0, max=160.0, spread=100.0),
            output_tokens=MetricStats(median=55.0, min=25.0, max=85.0, spread=60.0),
            sequential_turns=MetricStats(median=3.0, min=2.0, max=4.0, spread=2.0),
            queries_run_count=MetricStats(median=2.0, min=1.0, max=3.0, spread=2.0),
            total_findings_rows=MetricStats(median=5.0, min=2.0, max=8.0, spread=6.0),
            index_scoping_correct_pct=100.0,
            routing_correctness_pct=100.0,
            stop_reasons={"end_turn": 3},
            cost_by_role_median={"broker_flat": 1100.0},
        )

        comparisons = compare_arms({"S": sum_S, "F": sum_F})
        comp_wall = next(c for c in comparisons if c.metric_name == "wall_clock_seconds")
        assert comp_wall.difference_status == "no measurable difference"
        assert comp_wall.winner == "none"


class TestBenchCLIEntrypoint:
    """Verifies CLI flag handling and output file generation."""

    @pytest.mark.asyncio
    async def test_cli_flag_handling_scripted(self):
        exit_code = await _run(["--cases", "botsv3_coinhive", "--arms", "S,F", "--runs", "1", "--scripted"])
        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_cli_output_file_generation_json(self, tmp_path: Path):
        json_out = tmp_path / "bench_report.json"
        exit_code = await _run(["--scripted", "--runs", "1", "--out", str(json_out)])
        assert exit_code == 0
        assert json_out.exists()

        data = json.loads(json_out.read_text(encoding="utf-8"))
        assert "raw_runs" in data
        assert "arm_summaries" in data
        assert len(data["raw_runs"]) == 2  # 1 run per arm for S and F

    @pytest.mark.asyncio
    async def test_cli_output_file_generation_markdown(self, tmp_path: Path):
        md_out = tmp_path / "bench_report.md"
        exit_code = await _run(["--scripted", "--runs", "1", "--out", str(md_out)])
        assert exit_code == 0
        assert md_out.exists()

        text = md_out.read_text(encoding="utf-8")
        assert "# Benchmark Report — SmartOps SOC A/B Runner" in text
        assert "Arm S (Hierarchical)" in text
        assert "Arm F (Flat)" in text

    def test_cli_run_entrypoint(self):
        with pytest.raises(SystemExit) as exc_info:
            run(["--scripted", "--runs", "1"])
        assert exc_info.value.code == 0


class TestBenchDisablesTheSkillPack:
    """The A/B compares topologies, so the skill pack -- which only Arm S can
    receive -- is pinned off for every arm, and the pin is written into the
    artifact. A run whose configuration is not recorded in its own output cannot
    be compared against a later run.
    """

    async def test_pack_is_off_for_both_arms_even_if_the_environment_enables_it(
        self, monkeypatch
    ):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive"], arms=["S", "F"], runs_per_arm=1, scripted=True
        )

        assert report.skills_enabled is False
        assert {r.arm for r in report.raw_runs} == {"S", "F"}
        assert all(r.skills_enabled is False for r in report.raw_runs)

    async def test_the_ambient_setting_is_restored_afterwards(self, monkeypatch):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")
        await run_interleaved_benchmark(
            cases=["botsv3_coinhive"], arms=["S"], runs_per_arm=1, scripted=True
        )
        assert skills_enabled() is True

        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)
        await run_interleaved_benchmark(
            cases=["botsv3_coinhive"], arms=["S"], runs_per_arm=1, scripted=True
        )
        assert SKILLS_ENABLED_ENV_VAR not in os.environ

    def test_the_pin_is_released_when_the_block_raises(self, monkeypatch):
        """A benchmark that dies mid-run must not leave the switch pinned.

        The pin outranks the environment, so a leaked pin is worse than a leaked
        env var: every later caller in the process reads an answer that no
        setting anywhere explains.
        """
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        with pytest.raises(RuntimeError, match="benchmark exploded"), _pinned_skills(False):
            assert skills_enabled() is False
            raise RuntimeError("benchmark exploded")

        assert skills_enabled() is True
        assert os.environ[SKILLS_ENABLED_ENV_VAR] == "1"

    def test_an_unset_environment_stays_unset_when_the_block_raises(self, monkeypatch):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)

        with pytest.raises(RuntimeError, match="benchmark exploded"), _pinned_skills(True):
            assert skills_enabled() is True
            raise RuntimeError("benchmark exploded")

        assert skills_enabled() is False
        assert SKILLS_ENABLED_ENV_VAR not in os.environ

    def test_nested_pins_restore_the_outer_pin(self, monkeypatch):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)

        with _pinned_skills(True):
            with contextlib.suppress(RuntimeError), _pinned_skills(False):
                raise RuntimeError("inner exploded")
            assert skills_enabled() is True

        assert skills_enabled() is False

    async def test_the_pin_does_not_leak_into_other_concurrent_tasks(self, monkeypatch):
        """The pin is scoped to the pinning task, not to the process.

        The bench holds it across an await-heavy loop. If it were process-global
        -- an `os.environ` write, as it once was -- any other coroutine running
        in the same process would silently be forced to the bench's setting, and
        neither its output nor the bench's would record that it happened.
        """
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")
        started = asyncio.Event()
        release = asyncio.Event()

        async def bystander() -> bool:
            await started.wait()
            observed = skills_enabled()
            release.set()
            return observed

        async def bench_like() -> bool:
            with _pinned_skills(False):
                started.set()
                await release.wait()
                return skills_enabled()

        # The bystander is spawned outside the pinned block, so it does not
        # inherit the pin -- exactly the situation the ContextVar protects.
        bystander_task = asyncio.create_task(bystander())
        pinned_observed = await bench_like()
        bystander_observed = await bystander_task

        assert pinned_observed is False
        assert bystander_observed is True

    async def test_tasks_spawned_inside_the_pin_do_inherit_it(self, monkeypatch):
        """The other half of the scoping rule: an `asyncio.gather` over arms,
        started from inside the block, is still covered by the pin."""
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        async def arm() -> bool:
            await asyncio.sleep(0)
            return skills_enabled()

        with _pinned_skills(False):
            observed = await asyncio.gather(arm(), arm())

        assert observed == [False, False]

    async def test_json_artifact_records_the_setting(self, tmp_path: Path):
        json_out = tmp_path / "bench_report.json"
        assert await _run(["--scripted", "--runs", "1", "--out", str(json_out)]) == 0

        data = json.loads(json_out.read_text(encoding="utf-8"))
        assert data["skills_enabled"] is False
        assert all(r["skills_enabled"] is False for r in data["raw_runs"])

    async def test_markdown_artifact_records_the_setting(self, tmp_path: Path):
        md_out = tmp_path / "bench_report.md"
        assert await _run(["--scripted", "--runs", "1", "--out", str(md_out)]) == 0

        assert f"- **Skill Pack ({SKILLS_ENABLED_ENV_VAR}):** False" in md_out.read_text(
            encoding="utf-8"
        )
