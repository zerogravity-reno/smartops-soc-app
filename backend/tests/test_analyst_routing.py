"""Tests for splitting a BrokerReport into per-domain evidence slices."""

from __future__ import annotations

from datetime import UTC, datetime

from smartops.subagent_analysts.routing import route

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
    VtFindings,
    VtVerdict,
)


def _scope(*kinds: str) -> Scope:
    entities = [Entity(kind=k, value=f"val-{k}") for k in kinds]
    return Scope(
        entities=entities,
        time_window=(
            datetime(2018, 8, 20, tzinfo=UTC),
            datetime(2018, 8, 21, tzinfo=UTC),
        ),
    )


def _report(*results: SubtaskResult) -> BrokerReport:
    return BrokerReport(
        task_id="t1",
        hypothesis_id="h1",
        results=list(results),
        classification=TaskClassification(tool_families=["siem"], rationale="x"),
        cost=CostSummary(),
    )


def _rs(query: str = "q") -> ResultSet:
    return ResultSet(query=query, row_count=1, rows=[{"a": "b"}])


class TestSiemRouting:
    def test_each_category_lands_in_its_domain(self):
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(
                auth_events=[_rs("auth")],
                dns_resolutions=[_rs("dns")],
                connections=[_rs("conn")],
                processes=[_rs("proc")],
            ),
        )
        routed = route(_report(siem), _scope("user", "host"))

        assert [c for c, _ in routed.identity.siem_sets] == ["auth_events"]
        assert sorted(c for c, _ in routed.network.siem_sets) == ["connections", "dns_resolutions"]
        assert [c for c, _ in routed.endpoint.siem_sets] == ["processes"]

    def test_uncategorised_routed_by_entity_kind_and_flagged(self):
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(uncategorised=[_rs("mystery")]),
        )
        # scope has only a user -> untagged goes to identity, not network/endpoint
        routed = route(_report(siem), _scope("user"))
        assert len(routed.identity.untagged_sets) == 1
        assert routed.network.untagged_sets == []
        assert routed.endpoint.untagged_sets == []

    def test_host_untagged_reaches_endpoint(self):
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(uncategorised=[_rs()]),
        )
        routed = route(_report(siem), _scope("host"))
        assert routed.endpoint.untagged_sets
        assert routed.identity.untagged_sets == []
        assert routed.network.untagged_sets == []


class TestVtRouting:
    def test_network_and_endpoint_kinds_split(self):
        vt = SubtaskResult(
            task_id="t1:vt:1",
            status=SubtaskStatus.OK,
            findings=VtFindings(
                verdicts=[
                    VtVerdict(kind="ip", value="1.2.3.4", found=True, malicious=5),
                    VtVerdict(kind="domain", value="bad.com", found=True, malicious=3),
                    VtVerdict(kind="file_hash", value="abc", found=True, malicious=9),
                ]
            ),
        )
        routed = route(_report(vt), _scope("ip", "file_hash"))
        assert {v.kind for v in routed.network.vt_verdicts} == {"ip", "domain"}
        assert [v.kind for v in routed.endpoint.vt_verdicts] == ["file_hash"]
        assert routed.identity.vt_verdicts == []


class TestNoFindings:
    def test_result_without_findings_routes_nothing(self):
        rejected = SubtaskResult(
            task_id="t1:edr:1",
            status=SubtaskStatus.REJECTED,
            reason="no server",
        )
        routed = route(_report(rejected), _scope("host"))
        assert not any(s.has_evidence() for s in routed.slices())
