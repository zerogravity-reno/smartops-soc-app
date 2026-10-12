"""`--task-file`: the JSON contract the Analyst side hands the Broker.

Three things are tested here, and only the first is about parsing:

1. that a task file can express a real hand-built task **exactly** -- the cheap
   correctness check the handover asked for before a live run is spent;
2. that the committed example file still says what the live run needs it to say;
3. that the CLI's two-phase run shape holds -- fetch sequential, analysis one
   concurrent burst -- because both halves are load-bearing (Splunk's search
   quotas on one side, the analyst model's 5-minute billing windows on the
   other) and neither is visible from reading a single task's output.

Contract-level parsing and validation live in
`contracts/tests/test_task_input.py`.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import smartops.tools.registry as registry_module
from contracts import (
    BrokerReport,
    CostSummary,
    ResultSet,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    TaskClassification,
    TaskInputFile,
)

EXAMPLE_FILE = Path(__file__).resolve().parents[2] / "docs" / "examples" / "botsv3-coinhive-tasks.json"


@pytest.fixture(autouse=True)
def _no_mcp_clients(monkeypatch):
    """Start every test in this module with no MCP clients installed.

    `registry._clients_by_family` is process-global and other modules leave real
    clients in it, so without this these tests inherit them: `_run()` warms
    whatever is there, the warm fails with no network, and
    `warm_mcp_clients()`'s retry stops and re-resolves a client this file never
    asked for. Harmless to the assertions but it made them order-dependent, and
    it is the source of a burst of `MCPClient.stop` RuntimeWarnings that appear
    only when this module runs after `test_bench.py`.

    These tests patch `load_mcp_servers` to a no-op precisely because they are
    not about MCP, so holding no clients is the state they mean.
    """
    monkeypatch.setattr(registry_module, "_clients_by_family", {})
    yield


def write_task_file(tmp_path: Path, tasks: list[dict], name: str = "tasks.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"tasks": tasks}), encoding="utf-8")
    return path


def a_task(**overrides) -> dict:
    base = {
        "task_id": "T1",
        "hypothesis_id": "H1",
        "question": "did bostoll mine cryptocurrency on BSTOLL-L?",
        "entity": {"type": "host", "value": "BSTOLL-L"},
        "time_window": {"start": "2018-08-20T00:00:00Z", "end": "2018-08-21T00:00:00Z"},
    }
    return {**base, **overrides}


class TestATaskFileCanExpressAHandBuiltTask:
    """The round-trip. `BENCHMARK_CASES` holds tasks written directly in Python
    with real BOTSv3 indicators, so reproducing one through the file format is
    the cheapest possible proof that the loader loses nothing -- and it costs no
    Splunk query and no model call.

    `BOTSV3_HARD_MULTI_VECTOR_TASK` is the case chosen because it is the
    hardest: five entities across four kinds. It is also the case that could not
    be expressed at all if `entity` accepted only the single object the received
    template sends, which is why the list form exists.
    """

    def test_the_five_entity_case_round_trips_exactly(self, tmp_path):
        from smartops.bench import BOTSV3_HARD_MULTI_VECTOR_TASK as expected
        from smartops.main import _load_task_file

        path = write_task_file(tmp_path, [{
            "task_id": expected.task_id,
            "hypothesis_id": expected.hypothesis_id,
            "question": expected.goal,
            "entity": [
                {"type": e.kind, "value": e.value} for e in expected.scope.entities
            ],
            "time_window": {
                "start": expected.scope.time_window[0].isoformat(),
                "end": expected.scope.time_window[1].isoformat(),
            },
        }])

        (loaded, hypothesis), = _load_task_file(str(path), None)

        assert loaded == expected, "a task file must lose nothing a hand-built task carries"
        assert hypothesis == expected.goal

    def test_the_hypothesis_is_the_question(self, tmp_path):
        """`question` lands in two places, and both are deliberate: as
        `AnalystTask.goal` it tells the fetch tier what to retrieve, and as the
        returned hypothesis it is recorded on `HypothesisFindings` as the claim
        the analysts judged without seeing."""
        from smartops.main import _load_task_file

        path = write_task_file(tmp_path, [a_task(question="did X happen?")])

        (task, hypothesis), = _load_task_file(str(path), None)

        assert task.goal == "did X happen?"
        assert hypothesis == "did X happen?"


class TestTheCommittedExampleFile:
    """Guards the file the live end-to-end run uses. It is data, not code, so
    nothing else would notice it rotting."""

    def test_it_loads(self):
        from smartops.main import _load_task_file

        tasks = _load_task_file(str(EXAMPLE_FILE), None)

        assert len(tasks) == 3

    def test_every_window_is_the_one_botsv3_actually_returns_rows_for(self):
        """The trap this file exists to avoid, pinned to an exact window.

        BOTSv3 is 2018 data, so a window anywhere near now returns no rows -- and
        an empty result is indistinguishable from a dataset that had nothing to
        say. The received template's own window is 2026, which is why it cannot
        be used for a live run unmodified.

        The window asserted here is not a guess. The saved run at
        `.smartops/runs/cli-20260823T112627/` -- the one run with real evidence in
        all three domains -- issued its SPL with `earliest=1534723200
        latest=1534809600`, which is exactly this pair, and the rows it came back
        with are timestamped 2018-08-20T09:05Z to 2018-08-20T15:07Z. So this
        window is known to contain the activity, and `DEFAULT_BOTSV3_TASK` is the
        hand-built task that agrees.
        """
        from smartops.bench import DEFAULT_BOTSV3_TASK
        from smartops.main import _load_task_file

        expected = DEFAULT_BOTSV3_TASK.scope.time_window
        assert expected == (
            datetime(2018, 8, 20, tzinfo=UTC),
            datetime(2018, 8, 21, tzinfo=UTC),
        ), "the benchmark window moved -- check this file against it before a live run"

        for task, _ in _load_task_file(str(EXAMPLE_FILE), None):
            assert task.scope.time_window == expected, (
                f"{task.task_id} has window {task.scope.time_window}, not the "
                f"{expected} that BOTSv3 returns rows for -- this file is what the "
                "live run uses, and a wrong window looks exactly like an empty dataset"
            )

    def test_every_task_carries_a_hypothesis_and_real_indicators(self):
        from smartops.main import _load_task_file

        for task, hypothesis in _load_task_file(str(EXAMPLE_FILE), None):
            assert hypothesis, f"{task.task_id} has no hypothesis"
            assert task.scope.entities, f"{task.task_id} has no entities"

    def test_the_indicators_are_the_ones_botsv3_actually_holds(self):
        """Matched against the hand-built benchmark task rather than asserted
        from memory: a typo'd hostname fetches nothing and looks like a quiet
        dataset."""
        from smartops.bench import DEFAULT_BOTSV3_TASK
        from smartops.main import _load_task_file

        known = {(e.kind, e.value) for e in DEFAULT_BOTSV3_TASK.scope.entities}
        known |= {("user", "bostoll")}
        used = {
            (e.kind, e.value)
            for task, _ in _load_task_file(str(EXAMPLE_FILE), None)
            for e in task.scope.entities
        }

        assert used <= known, f"unrecognised indicators: {sorted(used - known)}"

    def test_it_validates_against_the_published_schema(self):
        """It is documentation as well as a fixture -- someone will read it to
        learn the format, so it must be a file the published contract accepts."""
        TaskInputFile.model_validate_json(EXAMPLE_FILE.read_text(encoding="utf-8"))


class TestChoosingBetweenTheTwoInputModes:
    @staticmethod
    def _args(argv):
        from smartops.main import _build_parser

        return _build_parser().parse_args(argv)

    def test_neither_mode_names_both_forms(self):
        """The message argparse's own `required=True` can no longer give, now
        that there are two ways to supply a task."""
        from smartops.main import _tasks_from_args

        with pytest.raises(ValueError, match="--task-file") as exc:
            _tasks_from_args(self._args([]))

        assert "--goal" in str(exc.value) and "--entity" in str(exc.value)

    def test_a_goal_with_no_entity_is_still_refused(self):
        from smartops.main import _tasks_from_args

        with pytest.raises(ValueError, match="--entity"):
            _tasks_from_args(self._args(["--goal", "g"]))

    @pytest.mark.parametrize(
        "extra",
        [
            ["--goal", "g"],
            ["--entity", "host:h"],
            ["--hypothesis", "h"],
            ["--since", "2018-08-20T00:00:00Z"],
            ["--until", "2018-08-21T00:00:00Z"],
        ],
    )
    def test_mixing_a_task_file_with_the_flags_is_refused(self, tmp_path, extra):
        """Not resolved by precedence. A run given both has been asked for two
        different investigations, and silently honouring one is how a live run
        gets spent on the task nobody meant."""
        from smartops.main import _tasks_from_args

        path = write_task_file(tmp_path, [a_task()])

        with pytest.raises(ValueError, match="cannot be combined"):
            _tasks_from_args(self._args(["--task-file", str(path), *extra]))

    def test_task_id_without_a_task_file_is_refused(self):
        from smartops.main import _tasks_from_args

        with pytest.raises(ValueError, match="--task-file"):
            _tasks_from_args(self._args(["--task-id", "T1", "--goal", "g", "--entity", "host:h"]))

    def test_the_flag_path_still_builds_one_task_with_the_stub_ids(self):
        """Unchanged behaviour, pinned. `bench.py` and every other caller build
        tasks directly, and this path has no upstream Analyst to supply a real
        hypothesis id."""
        from smartops.main import _tasks_from_args

        (task, hypothesis), = _tasks_from_args(
            self._args(["--goal", "g", "--entity", "host:h", "--hypothesis", "hyp"])
        )

        assert task.task_id.startswith("cli-")
        assert task.hypothesis_id == "cli-hypothesis"
        assert (task.goal, hypothesis) == ("g", "hyp")

    def test_the_flag_path_may_omit_the_hypothesis(self):
        """A task file always carries one; `--hypothesis` always was optional,
        and that asymmetry is why the analysis phase still checks."""
        from smartops.main import _tasks_from_args

        (_, hypothesis), = _tasks_from_args(self._args(["--goal", "g", "--entity", "host:h"]))

        assert hypothesis is None

    def test_selecting_one_task_by_id(self, tmp_path):
        from smartops.main import _tasks_from_args

        path = write_task_file(tmp_path, [
            a_task(), a_task(task_id="T2", hypothesis_id="H2"),
        ])

        selected = _tasks_from_args(self._args(["--task-file", str(path), "--task-id", "T2"]))

        assert [t.task_id for t, _ in selected] == ["T2"]

    def test_an_unreadable_file_says_so(self, tmp_path):
        from smartops.main import _load_task_file

        with pytest.raises(ValueError, match="could not read task file"):
            _load_task_file(str(tmp_path / "nope.json"), None)

    def test_a_file_that_is_not_a_task_file_says_so(self, tmp_path):
        """Distinct from unreadable, because "it exists but is wrong" and "it
        isn't there" need different fixes."""
        from smartops.main import _load_task_file

        path = tmp_path / "wrong.json"
        path.write_text('{"hypotheses": []}', encoding="utf-8")

        with pytest.raises(ValueError, match="not a valid task file"):
            _load_task_file(str(path), None)


def make_outcome(task_id: str, hypothesis_id: str, run_dir: Path | None = None):
    """A fetched outcome with rows in all three analyst domains, so all three
    domain analysts actually run a model call -- an empty slice short-circuits
    without one."""
    from smartops.broker import BrokerOutcome

    classification = TaskClassification(tool_families=["siem"], rationale="x")
    siem = SubtaskResult(
        task_id=f"{task_id}:siem",
        status=SubtaskStatus.OK,
        findings=SiemFindings(
            auth_events=[ResultSet(query="auth", row_count=1, rows=[{"user": "bostoll"}])],
            dns_resolutions=[ResultSet(query="dns", row_count=1, rows=[{"query": "x.com"}])],
            processes=[ResultSet(query="proc", row_count=1, rows=[{"process": "cmd.exe"}])],
        ),
    )
    report = BrokerReport(
        task_id=task_id,
        hypothesis_id=hypothesis_id,
        results=[siem],
        classification=classification,
        cost=CostSummary(),
    )
    return BrokerOutcome(
        results=[siem],
        classification=classification,
        dispatched=["siem"],
        report=report,
        run_dir=run_dir,
    )


class StubAnalyst:
    """Stands in for the imported reasoning model, recording every turn it saw.

    One instance is shared by every task, exactly as `main` shares one real
    `AnalystModel`, so `concurrent` below measures what the production path
    would do.
    """

    def __init__(self, delay: float = 0.0):
        self.turns: list[tuple[str, str]] = []
        self.in_flight = 0
        self.concurrent = 0
        self._delay = delay

    def invoke(self, system: str, user: str):
        import time

        from smartops.subagent_analysts.model import AnalystResponse

        self.in_flight += 1
        self.concurrent = max(self.concurrent, self.in_flight)
        try:
            if self._delay:
                time.sleep(self._delay)
            self.turns.append((system, user))
            return AnalystResponse(
                generation=(
                    "</think>NARRATIVE:\na logon occurred [auth_events#1]\n"
                    "OBSERVATIONS:\n- a logon [auth_events#1]\n"
                    "CITATIONS: auth_events#1"
                ),
                prompt_tokens=1,
                generation_tokens=1,
                stop_reason="stop",
            )
        finally:
            self.in_flight -= 1


class TestTheRunShapeOverSeveralTasks:
    """Fetch sequential, analysis one concurrent burst.

    Both properties are invisible in the output of any single task, and both are
    the reason the CLI is shaped this way at all, so they are asserted directly
    rather than inferred from artifacts.
    """

    THREE = [
        a_task(task_id="T1", hypothesis_id="H1", question="was it a miner?"),
        a_task(task_id="T2", hypothesis_id="H2", question="was it a legitimate scan?"),
        a_task(task_id="T3", hypothesis_id="H3", question="was it authorised?"),
    ]

    @staticmethod
    def _patch(monkeypatch, tmp_path, analyst, *, fetch_hook=None, fail_on=()):
        """Wire `main` up with no provider, no MCP and no real model."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        order: list[str] = []
        overlap = {"in_flight": 0, "max": 0}

        async def fake_broker_task(task, budget, **kwargs):
            overlap["in_flight"] += 1
            overlap["max"] = max(overlap["max"], overlap["in_flight"])
            try:
                order.append(task.task_id)
                if fetch_hook is not None:
                    await fetch_hook()
                if task.task_id in fail_on:
                    raise RuntimeError(f"fetch exploded for {task.task_id}")
                run_dir = tmp_path / "runs" / task.task_id / "stamp"
                run_dir.mkdir(parents=True, exist_ok=True)
                return make_outcome(task.task_id, task.hypothesis_id, run_dir)
            finally:
                overlap["in_flight"] -= 1

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(broker_mod, "broker_task", fake_broker_task)
        monkeypatch.setattr(broker_mod, "analyst_model_from_env", lambda: analyst)
        monkeypatch.setattr(broker_mod, "load_mcp_servers", lambda *a, **k: None)
        return order, overlap

    async def test_all_three_tasks_produce_their_own_artifacts(
        self, tmp_path, monkeypatch
    ):
        import smartops.broker as broker_mod
        import smartops.main as main_mod
        from contracts import AnalystPayload, HypothesisFindings

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        rc = await main_mod._run(["--task-file", str(path), "--families", "siem"])

        assert rc == 0
        for task_id, hypothesis_id in (("T1", "H1"), ("T2", "H2"), ("T3", "H3")):
            run_dir = tmp_path / "runs" / task_id / "stamp"
            findings = HypothesisFindings.model_validate_json(
                (run_dir / "findings.json").read_text(encoding="utf-8")
            )
            payload = AnalystPayload.model_validate_json(
                (run_dir / "analyst-payload.json").read_text(encoding="utf-8")
            )

            assert (findings.task_id, findings.hypothesis_id) == (task_id, hypothesis_id)
            assert (payload.task_id, payload.hypothesis_id) == (task_id, hypothesis_id)

    async def test_fetch_is_sequential_and_in_file_order(self, tmp_path, monkeypatch):
        """Sequential is the whole point: a single investigation already issues
        several concurrent Splunk searches, and multiplying that by the task
        count risks queued or rejected searches that read as data gaps."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)

        async def yield_control():
            # Gives the loop a chance to interleave if anything ever gathers
            # these -- without it a sequential-looking result proves nothing.
            await asyncio.sleep(0)

        order, overlap = self._patch(
            monkeypatch, tmp_path, StubAnalyst(), fetch_hook=yield_control
        )

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        assert order == ["T1", "T2", "T3"], "tasks must be fetched in file order"
        assert overlap["max"] == 1, "two Brokers must never be in flight at once"

    async def test_every_analyst_call_runs_in_one_concurrent_burst(
        self, tmp_path, monkeypatch
    ):
        """Nine calls (3 tasks x 3 domains) through one shared model, overlapping.

        This is what collapses them into a single 5-minute billing window --
        analysing each task as its own fetch finished would scatter the calls
        across the whole fetch loop and open a fresh window per gap.
        """
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        # A delay wide enough that sequential execution could not produce an
        # overlap count above 1.
        analyst = StubAnalyst(delay=0.05)
        self._patch(monkeypatch, tmp_path, analyst)

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        assert len(analyst.turns) == 9, "three domains for each of three tasks"
        assert analyst.concurrent > 3, (
            f"only {analyst.concurrent} analyst calls overlapped -- the tasks are "
            "being analysed one after another, not in one burst"
        )

    async def test_one_task_failing_to_fetch_does_not_stop_the_others(
        self, tmp_path, monkeypatch
    ):
        """The others have their own hypotheses and are worth what they cost."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        analyst = StubAnalyst()
        order, _ = self._patch(monkeypatch, tmp_path, analyst, fail_on=("T2",))

        rc = await main_mod._run(["--task-file", str(path), "--families", "siem"])

        assert rc == 1, "a failed task must be reported in the exit code"
        assert order == ["T1", "T2", "T3"], "T3 still ran after T2 failed"
        assert len(analyst.turns) == 6, "the two surviving tasks were still analysed"
        assert not (tmp_path / "runs" / "T2" / "stamp" / "findings.json").exists()

    async def test_the_analysts_never_see_any_hypothesis(self, tmp_path, monkeypatch):
        """The property the whole analysis tier rests on, asserted where it now
        matters most: with a task file, `question` IS the hypothesis and it is
        also `goal`, so the fetch tier legitimately saw it. Nothing on the
        analyst path reads a goal, and this is what proves the two stayed apart.
        """
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        analyst = StubAnalyst()
        self._patch(monkeypatch, tmp_path, analyst)

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        assert analyst.turns, "no analyst ran, so this asserts nothing"
        for system, user in analyst.turns:
            for question in ("was it a miner?", "legitimate scan", "authorised"):
                assert question not in system and question not in user
            assert "hypothesis" not in user.lower()

    async def test_the_findings_record_the_hypothesis_each_task_carried(
        self, tmp_path, monkeypatch
    ):
        """The other half of blindness: unreachable by the analysts, but present
        on the record, because the artifact has to be self-describing at the
        boundary it crosses."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod
        from contracts import HypothesisFindings

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        findings = HypothesisFindings.model_validate_json(
            (tmp_path / "runs" / "T2" / "stamp" / "findings.json").read_text(encoding="utf-8")
        )

        assert findings.hypothesis == "was it a legitimate scan?"

    async def test_the_default_budget_scales_with_the_task_count(
        self, tmp_path, monkeypatch
    ):
        """One `Budget` is one cumulative pot. A flat default would exhaust
        partway through the second investigation, and a budget refusal reads as
        a data gap rather than the cost problem it is."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())
        seen = {}

        original = broker_mod.Budget.from_usd

        def record(usd, **kwargs):
            seen["usd"] = usd
            seen["max_output_tokens_total"] = kwargs.get("max_output_tokens_total")
            return original(usd, **kwargs)

        monkeypatch.setattr(broker_mod.Budget, "from_usd", record)

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        assert seen["usd"] == main_mod.DEFAULT_BUDGET_USD_PER_TASK * 3
        assert seen["max_output_tokens_total"] == (
            main_mod.DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK * 3
        )

    async def test_an_explicit_budget_is_a_whole_run_ceiling(self, tmp_path, monkeypatch):
        """Someone naming a number means it."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())
        seen = {}

        original = broker_mod.Budget.from_usd
        monkeypatch.setattr(
            broker_mod.Budget,
            "from_usd",
            lambda usd, **kw: (seen.update(usd=usd), original(usd, **kw))[1],
        )

        await main_mod._run([
            "--task-file", str(path), "--families", "siem", "--budget-usd", "4.5",
        ])

        assert seen["usd"] == 4.5

    @staticmethod
    def _batch(tmp_path):
        """The one batch file written under the runs root, whatever it is named."""
        from contracts import AnalystPayloadBatch

        found = list((tmp_path / "runs").glob("batch-*/analyst-payload.json"))
        assert len(found) == 1, f"expected exactly one batch, found {found}"
        return AnalystPayloadBatch.model_validate_json(found[0].read_text(encoding="utf-8"))

    async def test_one_payload_carries_every_hypothesis_in_the_file(
        self, tmp_path, monkeypatch
    ):
        """The unit of handover is the task file. Three hypotheses about one alert
        go out as one message, not three the recipient has to group itself."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        batch = self._batch(tmp_path)
        assert [p.hypothesis_id for p in batch.payloads] == ["H1", "H2", "H3"], (
            "file order, not completion order"
        )
        assert [p.task_id for p in batch.payloads] == ["T1", "T2", "T3"]

    async def test_the_per_task_payloads_are_still_written_beside_each_run(
        self, tmp_path, monkeypatch
    ):
        """Not redundant with the batch: the per-run-dir copy is what lets a
        reader of one run directory see what that investigation produced."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        for task_id in ("T1", "T2", "T3"):
            assert (tmp_path / "runs" / task_id / "stamp" / "analyst-payload.json").exists()

    async def test_the_batch_sits_beside_the_task_directories_not_inside_one(
        self, tmp_path, monkeypatch
    ):
        """It belongs to no single task, and filing it under one task's id would
        make it look like that task's artifact."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        found = list((tmp_path / "runs").glob("batch-*/analyst-payload.json"))
        assert found[0].parent.parent == tmp_path / "runs"
        assert not list((tmp_path / "runs" / "T1").glob("batch-*"))

    async def test_a_named_batch_lands_where_the_caller_said(self, tmp_path, monkeypatch):
        """A caller that has to find the payload again (the webapp loop) names the
        batch instead of guessing which timestamped directory is its own."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run(
            ["--task-file", str(path), "--families", "siem", "--batch-id", "run-1-L2"]
        )

        assert (tmp_path / "runs" / "run-1-L2" / "analyst-payload.json").is_file()

    async def test_a_single_task_file_still_produces_a_batch_of_one(
        self, tmp_path, monkeypatch
    ):
        """So the consumer has one predictable input shape rather than a batch
        sometimes and a bare payload other times."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, [a_task()])
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        batch = self._batch(tmp_path)
        assert len(batch.payloads) == 1

    async def test_a_task_that_failed_to_fetch_is_absent_from_the_batch(
        self, tmp_path, monkeypatch
    ):
        """The batch carries what was actually analysed. A hypothesis with no
        findings must not appear as an empty member, which would read as
        'we looked and found nothing'."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, self.THREE)
        self._patch(monkeypatch, tmp_path, StubAnalyst(), fail_on=("T2",))

        await main_mod._run(["--task-file", str(path), "--families", "siem"])

        batch = self._batch(tmp_path)
        assert [p.hypothesis_id for p in batch.payloads] == ["H1", "H3"]

    async def test_the_flag_path_writes_no_batch(self, tmp_path, monkeypatch):
        """It investigates one hand-written task and has no file whose grouping a
        batch could represent."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        self._patch(monkeypatch, tmp_path, StubAnalyst())

        await main_mod._run([
            "--goal", "g", "--entity", "host:BSTOLL-L", "--hypothesis", "h",
            "--families", "siem",
        ])

        assert not list((tmp_path / "runs").glob("batch-*")), "no task file, no batch"

    async def test_one_task_file_still_behaves_like_the_single_task_cli(
        self, tmp_path, monkeypatch, capsys
    ):
        """A one-task file must not gain the multi-task banners, and its budget
        must be the unscaled single-run default."""
        import smartops.broker as broker_mod
        import smartops.main as main_mod

        path = write_task_file(tmp_path, [a_task()])
        self._patch(monkeypatch, tmp_path, StubAnalyst())

        rc = await main_mod._run(["--task-file", str(path), "--families", "siem"])
        out = capsys.readouterr().out

        assert rc == 0
        assert "tasks:" not in out
        assert "fetching 1/1" not in out
        assert "task:     T1" in out
