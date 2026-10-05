"""`RetrievalSummary.gaps`: recording a domain the run could not search.

The third retrieval state. `RetrievalSummary` already separated "we looked and
found nothing" from "we did not look"; these cover "we *could not* look, because
the instrument is not there" -- and, crucially, whether anything else covered the
domain anyway.

The design decision these encode (2026-09-02): do NOT withhold a family whose
tools are missing. Let the Broker try, let SIEM stand in where it can -- it
carries auth, DNS, connection and process events, so it genuinely answers
endpoint and network questions -- and then record the residue. If a substitute
covered the domain, roll with it. If nothing did, say that "no evidence in this
window" and "no instrument to look with" are indistinguishable, rather than
silently picking one.
"""

from __future__ import annotations

from datetime import UTC, datetime

from contracts import (
    BrokerReport,
    CostSummary,
    Entity,
    FetchStep,
    ResultSet,
    Scope,
    SiemFindings,
    StepOutcome,
    SubtaskResult,
    SubtaskStatus,
    TaskClassification,
)

from smartops.subagent_analysts.analyze import _domain_gaps
from smartops.subagent_analysts.routing import DomainSlice, domains_for_family


def make_scope(kinds=("host",)):
    return Scope(
        entities=[Entity(kind=k, value=f"val-{k}") for k in kinds],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


def make_report(*, results=(), steps=(), dispatched=()):
    return BrokerReport(
        task_id="t1",
        hypothesis_id="h1",
        results=list(results),
        step_outcomes=[
            StepOutcome(step=FetchStep(step_id=f"{f}-1", family=f, objective="o"), reason=r)
            for f, r in steps
        ],
        dispatched=list(dispatched),
        classification=TaskClassification(tool_families=list(dispatched), rationale="x"),
        cost=CostSummary(),
    )


def siem_result(*, gaps=(), rows=1):
    return SubtaskResult(
        task_id="t1:siem:tooluse_a",
        status=SubtaskStatus.OK,
        findings=SiemFindings(
            processes=[ResultSet(query="q", row_count=rows, rows=[{"a": 1}] * rows)]
        ),
        gaps=list(gaps),
    )


def slices_with(*domains_with_evidence):
    """Routed slices where the named domains carry evidence and the rest do not."""
    out = []
    for domain in ("identity", "network", "endpoint"):
        slice_ = DomainSlice(domain=domain)
        if domain in domains_with_evidence:
            slice_.siem_sets.append(
                ("processes", ResultSet(query="q", row_count=1, rows=[{"a": 1}]))
            )
        out.append(slice_)
    return out


class TestTheFamilyToDomainMapping:
    """Added deliberately, and it does not contradict `AnalystDomain`'s "not
    derived from ToolFamily": `route()` still assigns evidence by CIM category
    and entity kind. This answers the opposite question -- if this instrument is
    missing, whose evidence might be thinner?"""

    def test_edr_serves_endpoint_and_ndr_serves_network(self):
        assert domains_for_family("edr") == ("endpoint",)
        assert domains_for_family("ndr") == ("network",)

    def test_siem_serves_all_three_which_is_why_it_can_stand_in(self):
        assert set(domains_for_family("siem")) == {"identity", "network", "endpoint"}

    def test_vt_spans_two_domains_by_indicator_kind(self):
        assert set(domains_for_family("vt")) == {"network", "endpoint"}

    def test_an_unmapped_family_over_reports_rather_than_dropping_the_caveat(self):
        assert set(domains_for_family("newthing")) == {"identity", "network", "endpoint"}


class TestAMissingInstrumentThatSomethingElseCoveredFor:
    """"If it found info from siem then we can roll with it."

    The normal case in a SIEM-only deployment, and what actually happened on the
    `botsv3-coinhive-*` live run: `edr` was `{"disabled": true}`, the Broker
    planned an `edr_host_processes` step it could not dispatch, and the endpoint
    domain still came back with a full narrative built from 244 Sysmon process
    rows fetched through Splunk.
    """

    def test_the_gap_is_recorded_even_though_nothing_was_lost(self):
        """Recorded because it changes confidence, not because it cost an answer:
        the endpoint judgement rests on one instrument rather than two."""
        report = make_report(
            results=[siem_result(gaps=["edr"])],
            steps=[("edr", None), ("siem", None)],
            dispatched=["siem"],
        )

        gaps = _domain_gaps(report, make_scope(("host",)), slices_with("endpoint"))

        assert [g.family for g in gaps] == ["edr"]
        assert gaps[0].reason == "not_configured"

    def test_nothing_is_unanswered_because_siem_stood_in(self):
        report = make_report(
            results=[siem_result(gaps=["edr"])], steps=[("edr", None)], dispatched=["siem"]
        )

        (gap,) = _domain_gaps(report, make_scope(("host",)), slices_with("endpoint"))

        assert gap.served_domains == ["endpoint"]
        assert gap.unanswered_domains == [], (
            "endpoint had evidence, so the substitution worked and there is "
            "nothing open-ended to report"
        )

    def test_the_subagent_that_asked_for_it_is_named(self):
        """`SubagentAnswer.gaps` used to reach only a log line and a print. A
        `not_configured` edr that siem explicitly asked for is a different fact
        from one nothing missed."""
        report = make_report(
            results=[siem_result(gaps=["edr"])], steps=[("edr", None)], dispatched=["siem"]
        )

        (gap,) = _domain_gaps(report, make_scope(("host",)), slices_with("endpoint"))

        assert gap.advised_by == ["siem"]


class TestAMissingInstrumentThatNothingCoveredFor:
    """The open-ended case: the ambiguity is the finding."""

    def test_the_unanswered_domain_is_named(self):
        report = make_report(
            results=[siem_result(gaps=["edr"])], steps=[("edr", None)], dispatched=["siem"]
        )

        (gap,) = _domain_gaps(report, make_scope(("host",)), slices_with())

        assert gap.unanswered_domains == ["endpoint"], (
            "endpoint got nothing AND its instrument was missing, so 'nothing "
            "happened' and 'nobody could look' are indistinguishable"
        )

    def test_a_partial_substitution_is_reported_precisely(self):
        """Why this is two lists rather than a `substituted` bool: for a family
        spanning two domains, one covered and one not, either value of a bool
        would be misleading."""
        report = make_report(steps=[("vt", None)], dispatched=[])

        (gap,) = _domain_gaps(report, make_scope(("ip",)), slices_with("network"))

        assert set(gap.served_domains) == {"network", "endpoint"}
        assert gap.unanswered_domains == ["endpoint"]


class TestWhyTheDomainCouldNotBeSearched:
    """Classified structurally, never by matching the refusal text -- so editing
    an error message cannot silently re-classify a gap."""

    def test_a_family_with_nothing_wired_up_is_not_configured(self):
        report = make_report(steps=[("edr", None)], dispatched=[])

        (gap,) = _domain_gaps(report, make_scope(("host",)), slices_with("endpoint"))

        assert gap.reason == "not_configured"

    def test_a_scope_with_no_usable_observable_is_no_observable_in_scope(self):
        """Exactly what happened to `vt` on the authorization hypothesis: its
        scope was `user` + `host`, and VT needs a hash, address, domain or URL.
        The correct outcome, recorded so the reader knows the domain was
        considered and ruled out rather than forgotten."""
        rejected = SubtaskResult(
            task_id="t1:vt:tooluse_b",
            status=SubtaskStatus.REJECTED,
            reason=(
                "no vt observable in scope: needs one of "
                "['domain', 'file_hash', 'ip', 'url'], scope has ['host', 'user']"
            ),
        )
        report = make_report(results=[rejected], steps=[("vt", None)], dispatched=["vt"])

        (gap,) = _domain_gaps(report, make_scope(("host", "user")), slices_with("endpoint"))

        assert gap.reason == "no_observable_in_scope"

    def test_an_absent_instrument_outranks_an_unsupported_scope(self):
        """A family can satisfy both at once, and the binding reason is the one
        that would still hold if the other were fixed.

        Found on the real `botsv3-coinhive-authorization` run: `ndr` was both
        unconfigured (`{"disabled": true}`) and unsupported by the scope
        (`user` + `host`, where ndr needs an ip/domain/url). Reporting the scope
        was actively misleading -- it implies a task carrying an IP would have
        got an answer, when there is no ndr instrument to answer with.
        """
        report = make_report(steps=[("ndr", None)], dispatched=[])

        (gap,) = _domain_gaps(report, make_scope(("user", "host")), slices_with("network"))

        assert gap.reason == "not_configured", (
            "no instrument exists, so the scope is moot -- fixing the scope "
            "would change nothing"
        )

    def test_an_unsupported_scope_is_reported_when_the_instrument_does_exist(self):
        """The other side of that ordering. `vt` answers through native tools, so
        it is always configured -- which makes the scope the real obstacle, and
        one the caller can actually act on."""
        report = make_report(steps=[("vt", None)], dispatched=[])

        (gap,) = _domain_gaps(report, make_scope(("user", "host")), slices_with())

        assert gap.reason == "no_observable_in_scope"

    def test_the_refusal_message_is_carried_verbatim(self):
        """So the artifact quotes the run rather than paraphrasing it, and the
        two cannot disagree about why."""
        detail = "no tools resolved for siem: 1 MCP server(s) configured but returning no tools"
        rejected = SubtaskResult(
            task_id="t1:siem:tooluse_c", status=SubtaskStatus.REJECTED, reason=detail
        )
        report = make_report(results=[rejected], steps=[("siem", None)], dispatched=["siem"])

        (gap,) = _domain_gaps(report, make_scope(("host",)), slices_with())

        assert gap.detail == detail

    def test_a_configured_family_that_resolved_nothing_is_no_tools_resolved(
        self, monkeypatch
    ):
        """Distinct from `not_configured`: operational rather than structural,
        and `warm_mcp_clients()` retries it before it can reach here.

        The client has to be installed for this to be the right answer, and that
        is the point rather than test scaffolding: the same empty result means
        `not_configured` in a deployment with no siem server and
        `no_tools_resolved` in one where the server exists but answered nothing.
        The classification is a fact about the deployment, so the test has to
        state which deployment it is describing.
        """
        import smartops.tools.registry as registry_module

        monkeypatch.setattr(registry_module, "_clients_by_family", {"siem": [object()]})
        rejected = SubtaskResult(
            task_id="t1:siem:tooluse_d",
            status=SubtaskStatus.REJECTED,
            reason="no tools resolved for siem: 1 MCP server(s) configured but returning no tools",
        )
        report = make_report(results=[rejected], steps=[("siem", None)], dispatched=["siem"])

        (gap,) = _domain_gaps(report, make_scope(("host",)), slices_with())

        assert gap.reason == "no_tools_resolved", (
            "siem IS configured in this deployment, so an empty result is a "
            "server problem, not a missing instrument"
        )


class TestWhatIsNotAGap:
    def test_a_family_that_ran_and_found_nothing_is_not_a_gap(self):
        """It was searched and had nothing, which `covered`/`confirmed_empty`
        already speak to. Calling that a gap would make the field meaningless."""
        empty = SubtaskResult(task_id="t1:siem:tooluse_e", status=SubtaskStatus.NO_DATA)
        report = make_report(results=[empty], steps=[("siem", None)], dispatched=["siem"])

        assert _domain_gaps(report, make_scope(("host",)), slices_with()) == []

    def test_a_family_that_ran_successfully_is_not_a_gap(self):
        report = make_report(results=[siem_result()], steps=[("siem", None)], dispatched=["siem"])

        assert _domain_gaps(report, make_scope(("host",)), slices_with("endpoint")) == []

    def test_a_family_nobody_planned_dispatched_or_asked_for_is_not_reported(self):
        """Only families the investigation actually wanted. Otherwise every run
        in a SIEM-only deployment would carry edr and ndr gaps forever, and the
        field would be noise rather than signal."""
        report = make_report(results=[siem_result()], steps=[("siem", None)], dispatched=["siem"])

        gaps = _domain_gaps(report, make_scope(("host",)), slices_with("endpoint"))

        assert [g.family for g in gaps] == []
