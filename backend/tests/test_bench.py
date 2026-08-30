"""Test suite for the `smartops-bench` measurement harness.

Verifies:
1. Every requested run executes, once, and is indexed.
2. Accuracy of duration, tokens, cost per role, queries count, index scoping,
   findings, and stop_reason.
3. Median & spread statistical computation.
4. CLI flag handling and output file generation (JSON and Markdown).

The cross-arm comparison tests went with the flat baseline. They exercised a
significance rule that compared two arms' medians against a hardcoded threshold
-- a rule already observed calling a one-millisecond delta significant.
"""

import asyncio
import contextlib
import json
import os
from pathlib import Path
from typing import get_args

import pytest
from smartops.bench import (
    BENCHMARK_CASES,
    EXPECTED_DISPOSITIONS,
    SYNTHETIC_INDICATOR_CASES,
    RunMetrics,
    _execute_single_run,
    _pinned_skills,
    _run,
    check_index_scoping,
    compute_arm_summary,
    compute_disposition_correct,
    compute_metric_stats,
    extract_findings_completeness,
    run,
    run_interleaved_benchmark,
)
from smartops.main import _PLACEHOLDER_MODEL
from smartops.skills import SKILLS_ENABLED_ENV_VAR, skills_enabled

from contracts import (
    AnalystDomain,
    Disposition,
    QueryRun,
    ResultSet,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    VtFindings,
    VtVerdict,
)


class TestBenchRunOrdering:
    """Every requested run happens, once, in case-then-run order."""

    @pytest.mark.asyncio
    async def test_every_run_is_executed_and_indexed(self):
        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive"],
            runs_per_arm=3,
            scripted=True,
        )

        assert [(r.arm, r.run_index) for r in report.raw_runs] == [
            ("S", 0),
            ("S", 1),
            ("S", 2),
        ]

    @pytest.mark.asyncio
    async def test_multiple_cases_each_get_their_full_run_count(self):
        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive", "custom_case"],
            runs_per_arm=2,
            scripted=True,
        )

        assert len(report.raw_runs) == 4  # 2 cases * 2 runs
        assert [r.case_id for r in report.raw_runs] == [
            "botsv3_coinhive",
            "botsv3_coinhive",
            "custom_case",
            "custom_case",
        ]


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
            queries_run=[QueryRun(query="host=BSTOLL-L | head 5", category="dns_resolutions")],
        )
        assert check_index_scoping([res]) is False

    def test_a_blocked_wildcard_fails_the_metric(self):
        # The whole point. `queries_run` holds only queries that already passed
        # IndexScopeGuard, so scoring it alone could never catch the failure this
        # metric exists for -- the 2026-08-11 run where every SPL was `index=*`.
        # Now that a guard blocks those, the attempt has to remain visible.
        res = SubtaskResult(
            task_id="task:siem",
            status=SubtaskStatus.OK,
            queries_run=[QueryRun(query="index=botsv3 sourcetype=dns", category="dns_resolutions")],
            blocked_queries=["search index=* coinhive"],
        )
        assert check_index_scoping([res]) is False

    def test_a_run_with_nothing_blocked_still_passes(self):
        res = SubtaskResult(
            task_id="task:siem",
            status=SubtaskStatus.OK,
            queries_run=[QueryRun(query="sourcetype=stream:dns coinhive", category="dns_resolutions")],
            blocked_queries=[],
        )
        assert check_index_scoping([res]) is True

    def test_the_metric_does_not_ask_the_guard(self, monkeypatch):
        # Independence, asserted directly: the metric used to be *defined* as
        # `IndexScopeGuard._reject_reason`, so it could not disagree with the
        # guard and a relaxation of the guard silently moved the measurement.
        import smartops.guards as guards_module

        def explode(self, value):  # pragma: no cover - must never be reached
            raise AssertionError("check_index_scoping consulted the guard")

        monkeypatch.setattr(guards_module.IndexScopeGuard, "_reject_reason", explode)

        res = SubtaskResult(
            task_id="task:siem",
            status=SubtaskStatus.OK,
            queries_run=[QueryRun(query="index=* sourcetype=dns", category="dns_resolutions")],
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
        from smartops import bench as bench_mod
        from smartops.broker import BrokerOutcome

        from contracts import TaskClassification

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
        assert metrics.model_calls >= 0
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
                model_calls=2,
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
                model_calls=2,
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
                model_calls=3,
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

class TestBenchCLIEntrypoint:
    """Verifies CLI flag handling and output file generation."""

    @pytest.mark.asyncio
    async def test_cli_flag_handling_scripted(self):
        exit_code = await _run(["--cases", "botsv3_coinhive", "--runs", "1", "--scripted"])
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
        assert len(data["raw_runs"]) == 1

    @pytest.mark.asyncio
    async def test_cli_output_file_generation_markdown(self, tmp_path: Path):
        md_out = tmp_path / "bench_report.md"
        exit_code = await _run(["--scripted", "--runs", "1", "--out", str(md_out)])
        assert exit_code == 0
        assert md_out.exists()

        text = md_out.read_text(encoding="utf-8")
        assert "# Benchmark Report — SmartOps SOC" in text
        assert "| Metric | Median (min - max) |" in text
        assert "Cache Read Tokens" in text

    def test_cli_run_entrypoint(self):
        with pytest.raises(SystemExit) as exc_info:
            run(["--scripted", "--runs", "1"])
        assert exc_info.value.code == 0


class TestTheSkillPackCanBeMeasuredDeliberately:
    """Off by default, but measurable on request.

    `skills_enabled()`'s docstring says the pack "stays, to be evaluated on its
    own merits against a measured baseline". That evaluation needs a way to turn
    it on that is *explicit* and lands in the artifact -- which is exactly what
    the ambient environment variable is not, and why the bench refuses to
    inherit it.
    """

    async def test_an_explicit_opt_in_turns_the_pack_on(self):
        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive"],
            arms=["S"],
            runs_per_arm=1,
            scripted=True,
            skills=True,
        )

        assert report.skills_enabled is True
        assert all(r.skills_enabled is True for r in report.raw_runs)

    async def test_the_default_is_still_off(self):
        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive"], arms=["S"], runs_per_arm=1, scripted=True
        )

        assert report.skills_enabled is False


class TestBenchDisablesTheSkillPack:
    """The skill pack is pinned off for every run, and the pin is written into
    the artifact. A run whose configuration is not recorded in its own output
    cannot be compared against a later run.
    """

    async def test_pack_is_off_even_if_the_environment_enables_it(
        self, monkeypatch
    ):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        report = await run_interleaved_benchmark(
            cases=["botsv3_coinhive"], arms=["S"], runs_per_arm=1, scripted=True
        )

        assert report.skills_enabled is False
        assert {r.arm for r in report.raw_runs} == {"S"}
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


class TestBOTSv3AnswerSheet:
    """The BOTSv3 answer key (`EXPECTED_DISPOSITIONS`) and the honest label on
    the cases built from indicators the dataset does not contain
    (`SYNTHETIC_INDICATOR_CASES`) must not drift apart from `BENCHMARK_CASES`
    or from each other, and the renamed cases must actually resolve.
    """

    def test_every_expected_disposition_case_exists_in_benchmark_cases(self):
        for case_id in EXPECTED_DISPOSITIONS:
            assert case_id in BENCHMARK_CASES, (
                f"{case_id!r} has a documented answer but is not a benchmark case"
            )

    def test_every_synthetic_case_exists_in_benchmark_cases(self):
        for case_id in SYNTHETIC_INDICATOR_CASES:
            assert case_id in BENCHMARK_CASES, (
                f"{case_id!r} is marked synthetic but is not a benchmark case"
            )

    def test_expected_dispositions_and_synthetic_cases_are_disjoint(self):
        overlap = set(EXPECTED_DISPOSITIONS) & SYNTHETIC_INDICATOR_CASES
        assert overlap == set(), (
            f"{overlap} has both a documented answer and a fictional indicator"
        )

    def test_every_domain_and_disposition_value_is_valid(self):
        valid_domains = set(get_args(AnalystDomain))
        valid_dispositions = set(get_args(Disposition))
        for case_id, per_domain in EXPECTED_DISPOSITIONS.items():
            for domain, disposition in per_domain.items():
                assert domain in valid_domains, f"{case_id}: {domain!r} is not an AnalystDomain"
                assert disposition in valid_dispositions, (
                    f"{case_id}: {disposition!r} is not a Disposition"
                )

    def test_renamed_cases_resolve_and_old_names_are_gone(self):
        assert "botsv3_c2_beacon" in BENCHMARK_CASES
        assert "botsv3_hdoor_tool" in BENCHMARK_CASES
        assert "botsv3_c2_ip" not in BENCHMARK_CASES
        assert "botsv3_powershell_hash" not in BENCHMARK_CASES

    def test_every_case_key_matches_its_own_tasks_task_id(self):
        """Finding 8: nothing else pins this.

        `_execute_single_run` looks the answer key up by `task.task_id`, while
        `EXPECTED_DISPOSITIONS` is keyed by the `BENCHMARK_CASES` dict key. The
        two agree today for every case, but nothing stops a future rename of
        just one of them from silently disabling scoring for that case --
        `compute_disposition_correct` would look up a key the answer key never
        populates and quietly return `None` (no answer key) forever.
        """
        for case_id, (task, _expected_families) in BENCHMARK_CASES.items():
            assert task.task_id == case_id, (
                f"BENCHMARK_CASES key {case_id!r} does not match its "
                f"AnalystTask.task_id {task.task_id!r} -- disposition scoring "
                "for this case would silently never match EXPECTED_DISPOSITIONS"
            )


class TestDispositionCorrect:
    """`disposition_correct` must keep "no answer key", "no findings" and a
    genuine mismatch as three distinct outcomes -- collapsing any pair of them
    into the same value would hide a real defect behind a plausible-looking
    `None`/`False`.
    """

    def test_none_when_the_case_has_no_expectation(self):
        assert compute_disposition_correct("botsv3_web_shell_url", {"network": "malicious"}) is None

    def test_none_when_findings_are_absent(self):
        assert compute_disposition_correct("botsv3_coinhive", None) is None

    def test_true_on_a_match(self):
        assert compute_disposition_correct("botsv3_coinhive", {"network": "malicious"}) is True

    def test_false_on_a_mismatch(self):
        assert compute_disposition_correct("botsv3_coinhive", {"network": "benign"}) is False

    def test_a_domain_with_no_expectation_is_not_scored(self):
        # botsv3_coinhive expects only `network`. An extra `endpoint` entry in
        # the findings -- something the answer key says nothing about -- must
        # not flip the result: silence is not a wrong answer.
        assert (
            compute_disposition_correct(
                "botsv3_coinhive", {"network": "malicious", "endpoint": "benign"}
            )
            is True
        )

    async def test_execute_single_run_carries_the_measure_and_it_is_none_today(self):
        # `_execute_single_run` never calls the analyst step, so no findings
        # ever reach it to compare -- see `RunMetrics.disposition_correct`.
        # This is the plumbing check: the field is on RunMetrics and populated
        # by `_execute_single_run`, not the disposition logic itself (covered
        # above against `compute_disposition_correct` directly).
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
        assert metrics.disposition_correct is None
