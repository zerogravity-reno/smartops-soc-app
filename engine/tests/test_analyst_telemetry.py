"""The analyst tier emits OTel spans, and they nest under the analysis root.

This tier is the one Strands cannot instrument: the Broker and the fetch
subagents are `Agent`s and get spans for free, while the three analysts drive a
Bedrock custom-imported model through raw `invoke_model`. A trace therefore
covered the fetch half only, and the analyze half -- where the judgement is
actually formed -- was invisible.

Hand-rolled spans need their own tests for two reasons Strands' do not: nothing
upstream guarantees the parent/child shape, and nothing stops an attribute from
carrying content that must not leave the process.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from smartops.subagent_analysts.analyze import gather_finding
from smartops.subagent_analysts.model import AnalystResponse
from smartops.subagent_analysts.routing import DomainSlice
from smartops.telemetry import analysis_span

from contracts import Entity, ResultSet, Scope

_ANSWER = (
    "some reasoning </think>\n"
    "NARRATIVE: repeated failures for one account.\n"
    "OBSERVATIONS:\n- a burst of failures [auth_events#1]\n"
    "CITATIONS: auth_events#1"
)


class _FakeModel:
    """Returns one parseable reply. No boto3, no AWS."""

    def invoke(self, system: str, user: str) -> AnalystResponse:
        return AnalystResponse(
            generation=_ANSWER,
            prompt_tokens=1234,
            generation_tokens=567,
            stop_reason="stop",
        )


def _scope() -> Scope:
    return Scope(
        entities=[Entity(kind="host", value="BSTOLL-L")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


def _populated() -> DomainSlice:
    return DomainSlice(
        domain="identity",
        siem_sets=[
            (
                "auth_events",
                ResultSet(
                    query="q", row_count=1, rows=[{"user": "bostoll", "action": "failure"}]
                ),
            )
        ],
    )


@pytest.fixture
def spans():
    """An in-memory exporter for the duration of one test.

    A fresh `TracerProvider` per test rather than a module-level one: the OTel
    global can only be set once per process, so a shared provider would leak
    spans between tests and make an assertion on "which spans were emitted"
    depend on test order.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    token = trace._TRACER_PROVIDER
    trace._TRACER_PROVIDER = provider
    try:
        yield exporter
    finally:
        trace._TRACER_PROVIDER = token


def _by_name(exporter) -> dict:
    return {s.name: s for s in exporter.get_finished_spans()}


class TestTheAnalystTierIsTraced:
    def test_an_analyst_call_emits_a_span_under_the_analysis_root(self, spans):
        with analysis_span("t-1", "h-1"):
            gather_finding(_FakeModel(), _scope(), _populated())

        emitted = _by_name(spans)
        root, analyst = emitted["smartops.analysis"], emitted["smartops.analyst.identity"]

        assert analyst.parent is not None
        assert analyst.parent.span_id == root.context.span_id
        assert analyst.context.trace_id == root.context.trace_id

    def test_the_finding_and_its_cost_are_on_the_span(self, spans):
        with analysis_span("t-1", "h-1"):
            gather_finding(_FakeModel(), _scope(), _populated())

        a = _by_name(spans)["smartops.analyst.identity"].attributes

        assert a["analyst.narrative_chars"] == len("repeated failures for one account.")
        assert a["analyst.citation_count"] == 1
        assert a["analyst.observation_count"] == 1
        # OTel GenAI semantic-convention names, so a collector that already reads
        # Strands' spans reads these the same way.
        assert a["gen_ai.usage.input_tokens"] == 1234
        assert a["gen_ai.usage.output_tokens"] == 567

    def test_the_reasoning_trace_never_reaches_a_span(self, spans):
        """It is the model's private chain of thought -- persisted for audit,
        never re-fed. A span export is not an audit store: Strands' span-content
        redaction is opt-in and OFF by default, so anything put here reaches a
        collector in plaintext."""
        with analysis_span("t-1", "h-1"):
            gather_finding(_FakeModel(), _scope(), _populated())

        a = _by_name(spans)["smartops.analyst.identity"].attributes

        assert not any("reasoning" in key for key in a)
        assert not any("some reasoning" in str(v) for v in a.values())

    def test_a_domain_with_no_evidence_produces_no_span(self, spans):
        """No model call happens on that branch. A span would report a
        zero-token, zero-latency "analyst call" that never ran -- the exact
        never-attempted state the rest of this pipeline works to keep
        distinguishable from a real one."""
        with analysis_span("t-1", "h-1"):
            gather_finding(_FakeModel(), _scope(), DomainSlice(domain="endpoint"))

        assert "smartops.analyst.endpoint" not in _by_name(spans)


class TestTheTwoRootsAreJoinable:
    def test_the_analysis_root_carries_the_join_keys(self, spans):
        with analysis_span("t-1", "h-1"):
            pass

        a = _by_name(spans)["smartops.analysis"].attributes

        assert a["task_id"] == "t-1"
        assert a["hypothesis_id"] == "h-1"

    def test_it_records_which_fetch_trace_produced_the_evidence(self, spans):
        """The analyze tier is a SECOND root: `investigation_span` opens inside
        `broker_task()` and has closed before `gather()` runs. `fetch_trace_id`
        is what lets a reader holding this trace reach the retrieval that fed
        it -- otherwise the two halves of one run are unrelated trees."""
        with analysis_span("t-1", "h-1", fetch_trace_id="a" * 32):
            pass

        assert _by_name(spans)["smartops.analysis"].attributes["fetch.trace_id"] == "a" * 32

    def test_run_id_is_what_actually_identifies_the_run(self, spans):
        """`task_id` is NOT enough, and this is the assertion that says so.

        A task_id is reused every time the same case is investigated again --
        `botsv3_coinhive` has four runs under one id. Two traces joined on
        task_id + hypothesis_id alone can therefore belong to different
        investigations. `run_id` is the timestamped directory, and both roots
        carry it: the fetch tier via `record_run_id()` after
        `save_run_artifacts()` mints it, the analyze tier via this parameter.
        """
        with analysis_span("t-1", "h-1", run_id="20260830T120000"):
            pass

        assert _by_name(spans)["smartops.analysis"].attributes["run_id"] == "20260830T120000"

    def test_run_id_is_omitted_rather_than_faked_when_unknown(self, spans):
        """A broker that wrote no run directory has no id to give. An empty string
        would be a real-looking join key matching nothing."""
        with analysis_span("t-1", "h-1", run_id=None):
            pass

        assert "run_id" not in _by_name(spans)["smartops.analysis"].attributes

    def test_the_fetch_trace_id_is_omitted_rather_than_faked_when_absent(self, spans):
        """`BrokerReport.trace_id` is `None` when telemetry was never configured.
        Recording an all-zero id would be a real-looking value pointing at
        nothing, the same reason `current_trace_id()` returns `None`."""
        with analysis_span("t-1", "h-1", fetch_trace_id=None):
            pass

        assert "fetch.trace_id" not in _by_name(spans)["smartops.analysis"].attributes


class TestTheFetchTierStampsTheSameRunId:
    """`record_run_id` is how the fetch root gets the key the analyze root is
    given directly. It has to be a late stamp rather than a span attribute:
    `save_run_artifacts()` mints the timestamped directory, so nothing upstream of
    it -- including `investigation_span` at the top of `broker_task` -- can know
    the name yet. Spans accept attributes until they end, and it is still open."""

    def test_it_lands_on_the_open_investigation_span(self, spans):
        from contracts import AnalystTask, Entity, Scope
        from smartops.telemetry import investigation_span, record_run_id

        task = AnalystTask(
            task_id="t-1",
            hypothesis_id="h-1",
            goal="g",
            scope=Scope(
                entities=[Entity(kind="user", value="bostoll")],
                time_window=(
                    datetime(2018, 8, 20, tzinfo=UTC),
                    datetime(2018, 8, 21, tzinfo=UTC),
                ),
            ),
        )

        with investigation_span(task):
            record_run_id("20260830T120000")

        attrs = _by_name(spans)["smartops.investigation"].attributes
        assert attrs["run_id"] == "20260830T120000"
        assert attrs["task_id"] == "t-1"
        assert attrs["hypothesis_id"] == "h-1"

    def test_it_is_a_no_op_with_no_recording_span(self):
        """Must never be the thing that breaks a run that finished its work."""
        from smartops.telemetry import record_run_id

        record_run_id("20260830T120000")  # outside any span; must not raise

    def test_both_roots_carry_the_same_three_join_keys(self, spans):
        """The property the two-trace design rests on: a reader holding either
        trace can find the other, and can tell WHICH run it belongs to."""
        from contracts import AnalystTask, Entity, Scope
        from smartops.telemetry import investigation_span, record_run_id

        task = AnalystTask(
            task_id="t-1",
            hypothesis_id="h-1",
            goal="g",
            scope=Scope(
                entities=[Entity(kind="user", value="bostoll")],
                time_window=(
                    datetime(2018, 8, 20, tzinfo=UTC),
                    datetime(2018, 8, 21, tzinfo=UTC),
                ),
            ),
        )
        with investigation_span(task):
            record_run_id("20260830T120000")
        with analysis_span("t-1", "h-1", run_id="20260830T120000"):
            pass

        emitted = _by_name(spans)
        fetch = emitted["smartops.investigation"].attributes
        analyze = emitted["smartops.analysis"].attributes

        for key in ("task_id", "hypothesis_id", "run_id"):
            assert fetch[key] == analyze[key], f"{key} differs between the two roots"

    def test_the_two_roots_are_separate_traces_on_purpose(self, spans):
        """Recorded as a decision rather than left to be discovered. Unifying them
        would mean hoisting the fetch root into the CLI, which puts a tracing
        concern in the entry point and leaves `broker_task` untraced when called as
        a library (bench, replay). The join keys above are the alternative."""
        from contracts import AnalystTask, Entity, Scope
        from smartops.telemetry import investigation_span

        task = AnalystTask(
            task_id="t-1",
            hypothesis_id="h-1",
            goal="g",
            scope=Scope(
                entities=[Entity(kind="user", value="bostoll")],
                time_window=(
                    datetime(2018, 8, 20, tzinfo=UTC),
                    datetime(2018, 8, 21, tzinfo=UTC),
                ),
            ),
        )
        with investigation_span(task):
            pass
        with analysis_span("t-1", "h-1", run_id="r"):
            pass

        emitted = _by_name(spans)
        assert (
            emitted["smartops.investigation"].context.trace_id
            != emitted["smartops.analysis"].context.trace_id
        )


class TestContextSurvivesTheThreadFanOut:
    def test_concurrent_analysts_still_nest_under_the_root(self, spans):
        """`gather()` fans out with `asyncio.to_thread`. Spans nest across that
        boundary only because `to_thread` copies the current `contextvars`
        context and OTel's active span is a contextvar. Asserted rather than
        assumed: if it stopped holding, every analyst span would silently become
        its own root and the trace would look like three unrelated calls."""

        async def run():
            with analysis_span("t-1", "h-1"):
                await asyncio.gather(
                    asyncio.to_thread(gather_finding, _FakeModel(), _scope(), _populated()),
                    asyncio.to_thread(
                        gather_finding,
                        _FakeModel(),
                        _scope(),
                        DomainSlice(
                            domain="network",
                            siem_sets=[
                                (
                                    "connections",
                                    ResultSet(
                                        query="q",
                                        row_count=1,
                                        rows=[{"dest": "1.2.3.4"}],
                                    ),
                                )
                            ],
                        ),
                    ),
                )

        asyncio.run(run())

        emitted = _by_name(spans)
        root_id = emitted["smartops.analysis"].context.span_id
        for domain in ("identity", "network"):
            child = emitted[f"smartops.analyst.{domain}"]
            assert child.parent.span_id == root_id, f"{domain} span became its own root"


class TestOneTracePerInvestigation:
    def test_a_rounds_spans_join_the_webapps_trace(self, spans, monkeypatch):
        # 874ab334 was 9 traces: every task its own root (O5).
        from smartops.telemetry import analysis_span, round_span

        trace_id = "ab" * 16
        with round_span("874ab334-L2", f"00-{trace_id}-{'cd' * 8}-01"):
            with analysis_span("874ab334-L2-T1", "874ab334-L2-T1"):
                pass
            with analysis_span("874ab334-L2-T2", "874ab334-L2-T2"):
                pass

        finished = spans.get_finished_spans()
        assert {format(s.context.trace_id, "032x") for s in finished} == {trace_id}
        round_ = next(s for s in finished if s.name == "smartops.round")
        assert all(s.parent.span_id == round_.context.span_id for s in finished if s.name == "smartops.analysis")


class TestPrintTo:
    async def test_a_rounds_prints_reach_its_sink_and_no_other(self, capsys):
        # In the server a round's progress is its log and event stream, not the console.
        import asyncio

        from smartops.telemetry import print_to

        lines = []
        with print_to(lines.append):
            print("fetch plan (2 step(s))")
            await asyncio.to_thread(print, "from a worker thread")
            print("partial", end="")
        print("console")
        assert lines == ["fetch plan (2 step(s))", "from a worker thread", "partial"]
        assert capsys.readouterr().out == "console\n"
