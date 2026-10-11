"""The reasoning trace is auditable locally, and reaches nothing else.

Three destinations, three different answers, and the point of this file is that
they stay different:

- `traces.json` on the run directory  -- YES, this is the audit record
- `findings.json` / `DomainRecord` -- NO, that crosses to another model
- an OTel span attribute              -- NO, that leaves the process

The middle one was already true and tested. The first was NOT: `_as_record`
drops the trace, `gather()` did not hand it to anyone, and nothing wrote it --
while `DomainFinding.reasoning_trace` still described itself as "persisted for
audit". It had been, by an older artifact format that dumped `DomainFinding`
directly; the wire projection removed the only writer and nothing replaced it.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from smartops.main import _persist_reasoning_traces, _resolve_run_dir
from smartops.subagent_analysts.analyze import gather
from smartops.subagent_analysts.model import AnalystResponse

from contracts import (
    BrokerReport,
    DomainFinding,
    Entity,
    ResultSet,
    CostSummary,
    Scope,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    TaskClassification,
)

_ANSWER = (
    "I should check the auth rows for a burst. </think>\n"
    "NARRATIVE: a burst of failures.\n"
    "OBSERVATIONS:\n- repeated failures for one account [auth_events#1]\n"
    "CITATIONS: auth_events#1"
)


class _FakeModel:
    def invoke(self, system: str, user: str) -> AnalystResponse:
        return AnalystResponse(
            generation=_ANSWER, prompt_tokens=100, generation_tokens=50, stop_reason="stop"
        )


def _scope() -> Scope:
    return Scope(
        entities=[Entity(kind="user", value="bostoll")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


def _report() -> BrokerReport:
    return BrokerReport(
        task_id="t-1",
        hypothesis_id="h-1",
        results=[
            SubtaskResult(
                task_id="t-1",
                tool_family="siem",
                status=SubtaskStatus.OK,
                findings=SiemFindings(
                    auth_events=[
                        ResultSet(
                            query="q",
                            row_count=1,
                            rows=[{"user": "bostoll", "action": "failure"}],
                        )
                    ]
                ),
            )
        ],
        classification=TaskClassification(tool_families=["siem"], rationale="x"),
        cost=CostSummary(),
    )


def _finding(domain="identity", trace="I checked the rows."):
    return DomainFinding(
        domain=domain,
        narrative="a burst of failures.",
        observations=["failures [auth_events#1]"],
        citations=["auth_events#1"],
        reasoning_trace=trace,
        prompt_tokens=100,
        generation_tokens=50,
    )


class TestTheSinkIsTheOnlyWayToReachTheTrace:
    def test_gather_hands_the_raw_findings_to_the_sink(self):
        seen: list[list[DomainFinding]] = []
        findings = asyncio.run(
            gather(_report(), _scope(), _FakeModel(), trace_sink=seen.append)
        )

        assert len(seen) == 1
        assert [f.domain for f in seen[0]] == ["identity", "network", "endpoint"]
        identity = next(f for f in seen[0] if f.domain == "identity")
        assert identity.reasoning_trace is not None
        assert "check the auth rows" in identity.reasoning_trace
        # And the wire artifact it returned still does not carry it.
        assert "reasoning_trace" not in findings.model_dump_json()

    def test_no_sink_means_the_trace_is_discarded(self):
        """The default, stated so it reads as a decision rather than an accident.
        `gather` returns only the wire artifact, and `_as_record` has already
        dropped the trace by then -- with no sink there is no other reference."""
        findings = asyncio.run(gather(_report(), _scope(), _FakeModel()))

        assert "reasoning_trace" not in findings.model_dump_json()

    def test_a_sink_failure_is_not_swallowed(self):
        """A caller that asked for its traces to be written and had that fail
        should hear about it. Contrast `_persist_reasoning_traces` itself, which
        no-ops on a missing run directory -- that is a legitimately absent
        destination, not a broken one."""
        def boom(_findings):
            raise RuntimeError("disk full")

        try:
            asyncio.run(gather(_report(), _scope(), _FakeModel(), trace_sink=boom))
        except RuntimeError as exc:
            assert "disk full" in str(exc)
        else:
            raise AssertionError("the sink's exception was swallowed")


class TestTracesJson:
    def test_it_lands_beside_the_other_artifacts_with_the_join_keys(self, tmp_path):
        _persist_reasoning_traces("t-1", "h-1", [_finding()], run_dir=tmp_path)

        written = json.loads((tmp_path / "traces.json").read_text(encoding="utf-8"))

        assert written["task_id"] == "t-1"
        assert written["hypothesis_id"] == "h-1"
        assert written["run_id"] == tmp_path.name
        assert written["traces"][0]["reasoning_trace"] == "I checked the rows."

    def test_it_carries_only_the_domain_and_cost_alongside_the_reasoning(self, tmp_path):
        """No verdict to carry any more -- `DomainFinding` has none. What is left
        that a reader wants alongside the reasoning is which domain produced it
        and what it cost, without opening findings.json and joining on domain."""
        _persist_reasoning_traces("t-1", "h-1", [_finding()], run_dir=tmp_path)

        entry = json.loads((tmp_path / "traces.json").read_text(encoding="utf-8"))["traces"][0]

        assert entry["domain"] == "identity"
        assert "disposition" not in entry
        assert "confidence" not in entry
        assert entry["prompt_tokens"] == 100
        assert entry["generation_tokens"] == 50

    def test_all_three_domains_are_written_including_a_traceless_one(self, tmp_path):
        """An empty-slice domain short-circuits without a model call, so it has no
        trace. It is still written, `null`, for the same reason
        `HypothesisFindings` always carries all three: "we looked and there was
        nothing to reason about" and "this domain is missing" are different facts."""
        _persist_reasoning_traces(
            "t-1",
            "h-1",
            [_finding("identity"), _finding("network"), _finding("endpoint", trace=None)],
            run_dir=tmp_path,
        )

        traces = json.loads((tmp_path / "traces.json").read_text(encoding="utf-8"))["traces"]

        assert [t["domain"] for t in traces] == ["identity", "network", "endpoint"]
        assert traces[2]["reasoning_trace"] is None

    def test_a_missing_run_directory_is_not_an_error(self, tmp_path, monkeypatch):
        """An audit artifact must not be the thing that fails a completed
        analysis whose findings have already printed."""
        monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path / "nowhere"))

        _persist_reasoning_traces("no-such-task", "h-1", [_finding()])  # must not raise

        assert not (tmp_path / "nowhere").exists()


class TestBothWritersResolveTheSameDirectory:
    """Two copies of the resolution rules would drift, and the failure mode is a
    trace file landing beside a different run's findings -- silently, since both
    files would look well-formed. `_resolve_run_dir` is the one copy."""

    def test_an_explicit_run_dir_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path / "ignored"))

        assert _resolve_run_dir("t-1", tmp_path / "chosen") == tmp_path / "chosen"

    def test_otherwise_it_follows_the_latest_pointer(self, tmp_path, monkeypatch):
        run = tmp_path / "t-1" / "20260830T120000"
        run.mkdir(parents=True)
        (tmp_path / "t-1" / "latest.txt").write_text("20260830T120000", encoding="utf-8")
        monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))

        assert _resolve_run_dir("t-1", None) == run

    def test_none_when_there_is_no_pointer(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))

        assert _resolve_run_dir("t-1", None) is None
