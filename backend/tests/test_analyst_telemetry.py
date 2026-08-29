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
    "OBSERVATIONS:\n- a burst of failures [auth_events#1]\n"
    "DISPOSITION: suspicious\nCONFIDENCE: 0.85\n"
    "RATIONALE: repeated failures for one account.\n"
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

    def test_the_judgement_and_its_cost_are_on_the_span(self, spans):
        with analysis_span("t-1", "h-1"):
            gather_finding(_FakeModel(), _scope(), _populated())

        a = _by_name(spans)["smartops.analyst.identity"].attributes

        assert a["analyst.disposition"] == "suspicious"
        assert a["analyst.confidence"] == 0.85
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

    def test_the_fetch_trace_id_is_omitted_rather_than_faked_when_absent(self, spans):
        """`BrokerReport.trace_id` is `None` when telemetry was never configured.
        Recording an all-zero id would be a real-looking value pointing at
        nothing, the same reason `current_trace_id()` returns `None`."""
        with analysis_span("t-1", "h-1", fetch_trace_id=None):
            pass

        assert "fetch.trace_id" not in _by_name(spans)["smartops.analysis"].attributes


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
