"""B1: every routed set's computed summary reaches the Analyst, cited or not.

On check-B1c the endpoint analyst cited the set holding 4 rows with a parent
running from the Administrator's Desktop and still described it as "system
checks". The narrative is model-written; the summary is not.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

from smartops.subagent_analysts.analyze import gather
from smartops.subagent_analysts.model import AnalystResponse

from contracts import (
    BrokerReport,
    CostSummary,
    Entity,
    ResultSet,
    Scope,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    TaskClassification,
)


class _CitesOnlyTheFirstSet:
    def invoke(self, system: str, user: str) -> AnalystResponse:
        return AnalystResponse(
            generation=(
                "</think>\nNARRATIVE: [auth_events#1] one failure.\n"
                "OBSERVATIONS:\n- one failure for bostoll [auth_events#1]\n"
                "CITATIONS: auth_events#1"
            ),
            prompt_tokens=100,
            generation_tokens=50,
            stop_reason="stop",
        )


def _report() -> BrokerReport:
    sets = [
        ResultSet(query="q1", row_count=1, rows=[{"user": "bostoll", "action": "failure"}]),
        ResultSet(query="q2", row_count=1, rows=[{"user": "bostoll", "src": "203.0.113.9"}]),
        ResultSet(query="q3", row_count=0, rows=[]),
    ]
    return BrokerReport(
        task_id="t-1",
        hypothesis_id="h-1",
        results=[
            SubtaskResult(
                task_id="t-1",
                tool_family="siem",
                status=SubtaskStatus.OK,
                findings=SiemFindings(auth_events=sets),
            )
        ],
        classification=TaskClassification(tool_families=["siem"], rationale="x"),
        cost=CostSummary(),
    )


def test_uncited_sets_summaries_reach_the_payload():
    scope = Scope(
        entities=[Entity(kind="user", value="bostoll")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )
    findings = asyncio.run(gather(_report(), scope, _CitesOnlyTheFirstSet()))
    identity = next(f for f in findings.findings if f.domain == "identity")

    assert identity.citations == ["auth_events#1"]
    # Two non-empty sets, two summaries; the empty set has none.
    assert len(identity.summaries) == 2
    assert "auth_events#2" in identity.summaries[1]
    assert "203.0.113.9" in identity.summaries[1]  # never cited, still there

    wire = next(f for f in findings.for_analyst().findings if f.domain == "identity")
    assert wire.summaries == identity.summaries


class _CitesOnlyTheSecondSet(_CitesOnlyTheFirstSet):
    def invoke(self, system: str, user: str) -> AnalystResponse:
        r = super().invoke(system, user)
        return replace(r, generation=r.generation.replace("auth_events#1", "auth_events#2"))


def test_cited_sets_summaries_come_first():
    """`for_analyst`'s size cap drops from the end, so uncited sets go first."""
    scope = Scope(
        entities=[Entity(kind="user", value="bostoll")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )
    findings = asyncio.run(gather(_report(), scope, _CitesOnlyTheSecondSet()))
    identity = next(f for f in findings.findings if f.domain == "identity")

    assert identity.citations == ["auth_events#2"]
    assert "auth_events#2" in identity.summaries[0]
    assert "auth_events#1" in identity.summaries[1]
