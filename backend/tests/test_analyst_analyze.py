"""Tests for analyst orchestration: run_one, combine, and analyze."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest
from smartops.subagent_analysts.analyze import (
    _finalize,
    _finalize_finding,
    analyze,
    combine,
    gather,
    gather_finding,
    run_one,
)
from smartops.subagent_analysts.model import AnalystResponse
from smartops.subagent_analysts.routing import DomainSlice

from contracts import (
    AnalystVerdict,
    BrokerReport,
    DomainFinding,
    CostSummary,
    Entity,
    InvestigationContext,
    ResultSet,
    Scope,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    TaskClassification,
)


def _scope() -> Scope:
    return Scope(
        entities=[Entity(kind="user", value="bostoll"), Entity(kind="host", value="BSTOLL-L")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


def _ctx() -> InvestigationContext:
    return InvestigationContext(hypothesis="bostoll was brute-forced on BSTOLL-L")


class _SequenceModel:
    """Returns queued generations in order, one per invoke."""

    def __init__(self, generations: list[str]):
        self._queue = list(generations)
        self.calls = 0

    def invoke(self, system: str, user: str) -> AnalystResponse:
        self.calls += 1
        gen = self._queue.pop(0)
        return AnalystResponse(generation=gen, prompt_tokens=10, generation_tokens=5, stop_reason="stop")


class _RaisingModel:
    def invoke(self, system: str, user: str) -> AnalystResponse:
        raise RuntimeError("bedrock unavailable")


class _DomainModel:
    """Answers based on which domain the system prompt is for."""

    # Phrases unique to each curated domain body.
    _MARKERS = {
        "identity": "identity and authentication analyst",
        "network": "network detection and response analyst",
        "endpoint": "endpoint and host-forensics analyst",
    }

    def __init__(self, by_domain: dict[str, str]):
        self._by_domain = by_domain

    def invoke(self, system: str, user: str) -> AnalystResponse:
        # Whitespace-normalised: the blind bodies wrap at a different column, so
        # the network marker spans a line break in `facts_system_prompt` while
        # sitting on one line in `system_prompt`. Matching the wrapped text is a
        # property of the prompt's formatting, not of which domain it addresses.
        flat = " ".join(system.split())
        for domain, gen in self._by_domain.items():
            if self._MARKERS[domain] in flat:
                return AnalystResponse(generation=gen, prompt_tokens=1, generation_tokens=1, stop_reason="stop")
        raise AssertionError("no domain matched the system prompt")


class TestCombine:
    def test_supports_wins_scaled_by_margin(self):
        # win=0.9, lose=0.3 -> margin 0.5, mean(win)=0.9 -> 0.45
        stance, conf = combine([
            AnalystVerdict(domain="identity", stance="supports", confidence=0.9),
            AnalystVerdict(domain="network", stance="refutes", confidence=0.3),
        ])
        assert stance == "supports"
        assert conf == pytest.approx(0.45, abs=0.01)

    def test_unopposed_confidence_is_mean_not_pinned_to_one(self):
        # Two supports, nothing against -> confidence is their MEAN (~0.85), not 1.0.
        stance, conf = combine([
            AnalystVerdict(domain="network", stance="supports", confidence=0.8),
            AnalystVerdict(domain="endpoint", stance="supports", confidence=0.9),
            AnalystVerdict(domain="identity", stance="inconclusive", confidence=0.0),
        ])
        assert stance == "supports"
        assert conf == pytest.approx(0.85, abs=0.01)

    def test_tie_is_inconclusive(self):
        stance, _ = combine([
            AnalystVerdict(domain="identity", stance="supports", confidence=0.5),
            AnalystVerdict(domain="network", stance="refutes", confidence=0.5),
        ])
        assert stance == "inconclusive"

    def test_all_inconclusive(self):
        stance, conf = combine([
            AnalystVerdict(domain="identity", stance="inconclusive", confidence=0.2),
            AnalystVerdict(domain="network", stance="inconclusive", confidence=0.4),
        ])
        assert stance == "inconclusive"
        assert conf == pytest.approx(0.3, abs=0.01)


class TestRunOne:
    def _slice(self) -> DomainSlice:
        return DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )

    def test_good_verdict_first_try(self):
        model = _SequenceModel([
            "reasoning </think> VERDICT: supports\nCONFIDENCE: 0.8\nCITATIONS: auth_events#1"
        ])
        v = run_one(model, _ctx(), _scope(), self._slice())
        assert v.stance == "supports" and v.confidence == 0.8
        assert v.citations == ["auth_events#1"]
        assert model.calls == 1

    def test_reask_recovers_a_malformed_first_reply(self):
        model = _SequenceModel([
            "I think it looks bad but I won't format it",
            "</think> VERDICT: refutes\nCONFIDENCE: 0.6\nCITATIONS: auth_events#1",
        ])
        v = run_one(model, _ctx(), _scope(), self._slice())
        assert v.stance == "refutes"
        assert model.calls == 2

    def test_tokens_recorded_and_reask_sums_them(self):
        # _SequenceModel reports prompt=10, generation=5 per call.
        one = _SequenceModel([
            "</think> VERDICT: supports\nCONFIDENCE: 0.8\nCITATIONS: auth_events#1"
        ])
        v1 = run_one(one, _ctx(), _scope(), self._slice())
        assert (v1.prompt_tokens, v1.generation_tokens) == (10, 5)
        two = _SequenceModel([
            "unformatted",
            "</think> VERDICT: refutes\nCONFIDENCE: 0.6\nCITATIONS: auth_events#1",
        ])
        v2 = run_one(two, _ctx(), _scope(), self._slice())
        assert (v2.prompt_tokens, v2.generation_tokens) == (20, 10)  # both calls billed

    def test_invented_citation_is_dropped_valid_kept(self):
        model = _SequenceModel([
            "</think> VERDICT: supports\nCONFIDENCE: 0.8\nCITATIONS: auth_events#1, auth_events#9"
        ])
        v = run_one(model, _ctx(), _scope(), self._slice())
        assert v.stance == "supports"
        assert v.citations == ["auth_events#1"]  # #9 was never emitted -> dropped

    def test_ungrounded_decisive_verdict_downgraded_to_inconclusive(self):
        model = _SequenceModel([
            "</think> VERDICT: supports\nCONFIDENCE: 0.9\nCITATIONS: auth_events#9"
        ])
        v = run_one(model, _ctx(), _scope(), self._slice())
        assert v.stance == "inconclusive"  # decisive claim with no resolvable citation
        assert v.confidence <= 0.3
        assert "ungrounded" in v.rationale
        assert v.citations == []

    def test_both_attempts_unparseable_yields_inconclusive(self):
        model = _SequenceModel(["no verdict here", "still nothing"])
        v = run_one(model, _ctx(), _scope(), self._slice())
        assert v.stance == "inconclusive"
        assert "no parseable verdict" in v.rationale

    def test_model_exception_is_contained(self):
        v = run_one(_RaisingModel(), _ctx(), _scope(), self._slice())
        assert v.stance == "inconclusive"
        assert "could not run" in v.rationale

    def test_empty_slice_short_circuits_without_a_model_call(self):
        model = _SequenceModel([])  # would IndexError if invoked
        v = run_one(model, _ctx(), _scope(), DomainSlice(domain="network"))
        assert v.stance == "inconclusive"
        assert v.confidence == 0.0
        assert "no network evidence" in v.rationale
        assert model.calls == 0  # the model was never called


class TestGatherFinding:
    def test_good_finding_first_try(self):
        gen = (
            "</think>OBSERVATIONS:\n- clean logon for bostoll [auth_events#1]\n"
            "CONFIDENCE: 0.6\nRATIONALE: nothing unusual.\nCITATIONS: auth_events#1"
        )
        model = _SequenceModel([gen])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.domain == "identity"
        assert finding.confidence == 0.6
        assert finding.citations == ["auth_events#1"]
        assert model.calls == 1

    def test_reask_recovers_a_malformed_first_reply(self):
        good = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCITATIONS: auth_events#1"
        model = _SequenceModel(["no recognisable block here", good])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.citations == ["auth_events#1"]
        assert model.calls == 2

    def test_both_attempts_unparseable_yields_empty_finding(self):
        model = _SequenceModel(["prose one", "prose two"])
        slice_ = DomainSlice(
            domain="network",
            siem_sets=[("connections", ResultSet(query="q", row_count=1, rows=[{"dest": "1.2.3.4"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.confidence == 0.0
        assert "no parseable finding" in finding.rationale
        assert model.calls == 2

    def test_invented_citation_is_dropped(self):
        gen = (
            "</think>OBSERVATIONS:\n- x [auth_events#1]\n- y [auth_events#99]\n"
            "CITATIONS: auth_events#1, auth_events#99"
        )
        model = _SequenceModel([gen])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.citations == ["auth_events#1"]

    def test_empty_slice_short_circuits_without_a_model_call(self):
        model = _SequenceModel([])  # would IndexError if invoked
        finding = gather_finding(model, _scope(), DomainSlice(domain="endpoint"))
        assert finding.confidence == 0.0
        assert "no endpoint evidence" in finding.rationale
        assert model.calls == 0

    def test_model_exception_is_contained(self):
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(_RaisingModel(), _scope(), slice_)
        assert finding.confidence == 0.0
        assert "could not run" in finding.rationale

    def test_a_prose_colon_does_not_cost_a_later_observations_inline_citation(self):
        """The parse layer is upstream of the grounding gate, and used to starve it.

        `_finalize_finding` unions the valid inline ids found inside observations
        into `citations` -- the fix committed as `f9bc706`. But
        `_FINDING_OBSERVATIONS_RE` ended the capture at any prose line looking
        like a label, so observations dropped before the gate ever saw them took
        their inline citations with them. Here the trailing `CITATIONS:` line
        names only `auth_events#1`; `auth_events#2` exists solely inline, on an
        observation sitting after an un-bulleted line containing a colon.
        """
        gen = (
            "</think>OBSERVATIONS:\n"
            "- 14 failed logons for bostoll [auth_events#1]\n"
            "The pattern was: burst, pause, burst\n"
            "- then a success from the same source [auth_events#2]\n"
            "CITATIONS: auth_events#1"
        )
        model = _SequenceModel([gen])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[
                ("auth_events", ResultSet(query="q1", row_count=1, rows=[{"user": "bostoll"}])),
                ("auth_events", ResultSet(query="q2", row_count=1, rows=[{"user": "bostoll"}])),
            ],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert len(finding.observations) == 3
        assert finding.citations == ["auth_events#1", "auth_events#2"]


class TestAnalyze:
    async def test_full_pipeline_produces_assessment(self):
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(
                auth_events=[ResultSet(query="auth", row_count=1, rows=[{"user": "bostoll", "action": "failure"}])],
                dns_resolutions=[ResultSet(query="dns", row_count=1, rows=[{"query": "x.com"}])],
                processes=[ResultSet(query="proc", row_count=1, rows=[{"process": "cmd.exe"}])],
            ),
        )
        report = BrokerReport(
            task_id="t1",
            hypothesis_id="h-42",
            results=[siem],
            classification=TaskClassification(tool_families=["siem"], rationale="x"),
            cost=CostSummary(),
        )
        model = _DomainModel({
            "identity": "</think> VERDICT: supports\nCONFIDENCE: 0.9\nCITATIONS: auth_events#1",
            "network": "</think> VERDICT: inconclusive\nCONFIDENCE: 0.2",
            "endpoint": "</think> VERDICT: supports\nCONFIDENCE: 0.5\nCITATIONS: processes#1",
        })
        assessment = await analyze(report, _ctx(), _scope(), model)

        assert assessment.hypothesis_id == "h-42"
        assert len(assessment.verdicts) == 3
        assert assessment.overall_stance == "supports"
        domains = {v.domain for v in assessment.verdicts}
        assert domains == {"identity", "network", "endpoint"}


class TestInlineObservationCitations:
    """`_finalize` filtered only the trailing CITATIONS: line.

    Both prompt footers tell the model to attach a `[header_id]` to every
    observation, and those went unchecked -- so a verdict came back
    supports/0.95 whose observations cited `auth_events#7` (does not exist) and
    `processes#3` (wrong domain), and both were printed to the operator and
    written into assessment.json.
    """

    def test_an_observation_citing_only_an_invalid_id_is_dropped(self):
        verdict = AnalystVerdict(
            domain="identity", stance="supports", confidence=0.95,
            citations=["auth_events#1"],
            key_observations=[
                "400 failed logons for bostoll [auth_events#1]",
                "lateral movement to DC01 [processes#3]",
            ],
        )
        out = _finalize(verdict, {"auth_events#1": []}, 10, 20)
        assert out.key_observations == ["400 failed logons for bostoll [auth_events#1]"]

    def test_an_observation_keeps_only_its_resolving_ids(self):
        verdict = AnalystVerdict(
            domain="identity", stance="supports", confidence=0.9,
            citations=["auth_events#1"],
            key_observations=["spray from one source [auth_events#1][auth_events#9]"],
        )
        out = _finalize(verdict, {"auth_events#1": []}, 10, 20)
        assert "auth_events#9" not in out.key_observations[0]
        assert "auth_events#1" in out.key_observations[0]

    def test_a_valid_inline_citation_counts_toward_grounding(self):
        # The converse failure: a verdict that cited correctly INLINE but omitted
        # the CITATIONS: line resolved to zero citations and was downgraded to
        # inconclusive -- a grounded claim discarded on a formatting technicality.
        verdict = AnalystVerdict(
            domain="identity", stance="supports", confidence=0.9,
            citations=[],
            key_observations=["brute force against bostoll [auth_events#1]"],
        )
        out = _finalize(verdict, {"auth_events#1": []}, 10, 20)
        assert out.stance == "supports"
        assert "auth_events#1" in out.citations

    def test_an_uncited_observation_is_left_alone(self):
        # Dropping uncited prose is a different (and unmade) decision -- the
        # trailing CITATIONS: line may still ground the verdict as a whole.
        verdict = AnalystVerdict(
            domain="identity", stance="supports", confidence=0.9,
            citations=["auth_events#1"],
            key_observations=["the account is a service account"],
        )
        out = _finalize(verdict, {"auth_events#1": []}, 10, 20)
        assert out.key_observations == ["the account is a service account"]

    def test_the_hypothesis_blind_path_drops_them_too(self):
        finding = DomainFinding(
            domain="endpoint", confidence=0.8,
            citations=["processes#1"],
            observations=[
                "powershell -enc observed [processes#1]",
                "invented claim [processes#42]",
            ],
        )
        out = _finalize_finding(finding, {"processes#1": []}, 10, 20)
        assert out.observations == ["powershell -enc observed [processes#1]"]


def test_a_verdict_records_which_evidence_its_citations_resolve_to():
    from contracts import AnalystVerdict
    from smartops.subagent_analysts.analyze import _finalize

    verdict = AnalystVerdict(
        domain="network", stance="supports", confidence=0.9,
        citations=["connections#1"], key_observations=[],
    )
    out = _finalize(verdict, {"connections#1": ["t:siem:x:0"]}, 10, 20)

    assert out.citations == ["connections#1"]
    assert out.citation_evidence == {"connections#1": ["t:siem:x:0"]}


class _RecordingDomainModel(_DomainModel):
    """`_DomainModel` that keeps every (system, user) pair it was handed.

    The blindness test needs to inspect what actually reached the model, not
    what a prompt builder returns in isolation.
    """

    def __init__(self, by_domain: dict[str, str]):
        super().__init__(by_domain)
        self.seen: list[tuple[str, str]] = []

    def invoke(self, system: str, user: str) -> AnalystResponse:
        self.seen.append((system, user))
        return super().invoke(system, user)


def _report_with_all_three_domains() -> BrokerReport:
    siem = SubtaskResult(
        task_id="t1:siem:1",
        status=SubtaskStatus.OK,
        findings=SiemFindings(
            auth_events=[ResultSet(query="auth", row_count=1, rows=[{"user": "bostoll"}])],
            dns_resolutions=[ResultSet(query="dns", row_count=1, rows=[{"query": "x.com"}])],
            processes=[ResultSet(query="proc", row_count=1, rows=[{"process": "cmd.exe"}])],
        ),
    )
    return BrokerReport(
        task_id="t1",
        hypothesis_id="h-42",
        results=[siem],
        classification=TaskClassification(tool_families=["siem"], rationale="x"),
        cost=CostSummary(),
    )


class TestGather:
    """`gather()` -- the blind path's producer, and the Analyst Agent's contract."""

    _GENS = {
        "identity": (
            "</think>OBSERVATIONS:\n- one logon for bostoll [auth_events#1]\n"
            "DISPOSITION: suspicious\nCONFIDENCE: 0.7\nCITATIONS: auth_events#1"
        ),
        "network": (
            "</think>OBSERVATIONS:\n- a lookup of x.com [dns_resolutions#1]\n"
            "DISPOSITION: benign\nCONFIDENCE: 0.4\nCITATIONS: dns_resolutions#1"
        ),
        "endpoint": (
            "</think>OBSERVATIONS:\n- cmd.exe ran [processes#1]\n"
            "DISPOSITION: malicious\nCONFIDENCE: 0.9\nCITATIONS: processes#1"
        ),
    }

    async def test_the_hypothesis_never_reaches_the_model(self):
        """The guarantee, tested end to end rather than per prompt builder.

        `gather_finding` and `build_facts_user_turn` have no hypothesis
        parameter, so this cannot fail without someone adding one -- which is
        exactly the change this test exists to catch.
        """
        secret = "bostoll was brute-forced on BSTOLL-L"
        model = _RecordingDomainModel(self._GENS)

        await gather(
            _report_with_all_three_domains(),
            _scope(),
            model,
            hypothesis=secret,
        )

        assert len(model.seen) == 3
        for system, user in model.seen:
            assert secret not in system and secret not in user
            assert "hypothesis" not in system.lower()
            assert "hypothesis" not in user.lower()
            assert "brute" not in user.lower()

    async def test_carries_all_three_domains_and_their_dispositions(self):
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        assert findings.task_id == "t1"
        assert findings.hypothesis_id == "h-42"
        assert {f.domain: f.disposition for f in findings.findings} == {
            "identity": "suspicious",
            "network": "benign",
            "endpoint": "malicious",
        }

    async def test_the_contract_carries_no_hypothesis_level_stance(self):
        """The absence is the contract -- that call belongs to the Analyst Agent."""
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        assert not hasattr(findings, "overall_stance")
        assert not any(hasattr(f, "stance") for f in findings.findings)

    async def test_a_domain_with_no_evidence_is_reported_not_omitted(self):
        """"we looked and found nothing" and "we did not look" are different facts."""
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(
                auth_events=[ResultSet(query="auth", row_count=1, rows=[{"user": "bostoll"}])],
            ),
        )
        report = BrokerReport(
            task_id="t1",
            hypothesis_id="h-42",
            results=[siem],
            classification=TaskClassification(tool_families=["siem"], rationale="x"),
            cost=CostSummary(),
        )
        findings = await gather(report, _scope(), _DomainModel(self._GENS))

        assert {f.domain for f in findings.findings} == {"identity", "network", "endpoint"}
        network = next(f for f in findings.findings if f.domain == "network")
        assert network.disposition == "inconclusive"
        assert "no network evidence" in network.rationale

    async def test_citations_are_frozen_to_their_evidence_ids(self):
        """The consumer must be able to trace a judgement without recomputing routing."""
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(
                auth_events=[
                    ResultSet(
                        query="auth",
                        row_count=1,
                        rows=[{"user": "bostoll"}],
                        evidence_id="t1:siem:1:0",
                    )
                ],
            ),
        )
        report = BrokerReport(
            task_id="t1",
            hypothesis_id="h-42",
            results=[siem],
            classification=TaskClassification(tool_families=["siem"], rationale="x"),
            cost=CostSummary(),
        )
        findings = await gather(report, _scope(), _DomainModel(self._GENS))

        identity = next(f for f in findings.findings if f.domain == "identity")
        assert [e.citation for e in identity.exhibits] == ["auth_events#1"]
        assert identity.exhibits[0].evidence_ids == ["t1:siem:1:0"]

    async def test_the_cited_rows_travel_with_the_judgement(self):
        """The Analyst Agent must be able to check a judgement without the store."""
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        identity = next(f for f in findings.findings if f.domain == "identity")
        exhibit = identity.exhibits[0]
        assert exhibit.citation == "auth_events#1"
        assert exhibit.row_count == 1
        assert "auth_events#1" in exhibit.rows  # the `# header` line
        assert "bostoll" in exhibit.rows  # the actual row

    async def test_only_cited_blocks_travel(self):
        """Identity is routed dns/process sets too; it cited neither."""
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        identity = next(f for f in findings.findings if f.domain == "identity")
        assert [e.citation for e in identity.exhibits] == ["auth_events#1"]
        assert "x.com" not in "".join(e.rows for e in identity.exhibits)

    async def test_audit_fields_do_not_cross_the_boundary(self):
        """`reasoning_trace` is documented "never re-fed"; the tokens are our telemetry."""
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        for judgement in findings.findings:
            for field in ("reasoning_trace", "prompt_tokens", "generation_tokens"):
                assert not hasattr(judgement, field)
        assert "reasoning_trace" not in findings.model_dump_json()

    async def test_run_id_is_set_at_construction_not_left_for_the_writer(self):
        findings = await gather(
            _report_with_all_three_domains(), _scope(), _DomainModel(self._GENS),
            run_id="20260825T100741262",
        )
        assert findings.run_id == "20260825T100741262"


class TestFindingGroundingGate:
    """The blind path's equivalent of `_finalize`'s grounding downgrade."""

    def _finding(self, disposition, citations, observations=()):
        return DomainFinding(
            domain="identity",
            disposition=disposition,
            confidence=0.95,
            rationale="a confident read.",
            observations=list(observations),
            citations=list(citations),
        )

    def test_a_decisive_disposition_with_no_resolving_citation_is_downgraded(self):
        out = _finalize_finding(self._finding("malicious", ["auth_events#9"]), {}, 1, 1)
        assert out.disposition == "inconclusive"
        assert out.confidence <= 0.3
        assert "downgraded" in out.rationale

    def test_inconclusive_needs_no_citation(self):
        out = _finalize_finding(self._finding("inconclusive", []), {}, 1, 1)
        assert out.disposition == "inconclusive"
        assert out.confidence == 0.95  # not capped; nothing was claimed

    def test_a_grounded_disposition_survives(self):
        out = _finalize_finding(
            self._finding("malicious", ["auth_events#1"]), {"auth_events#1": ["e:0"]}, 1, 1
        )
        assert out.disposition == "malicious"
        assert out.confidence == 0.95

    def test_an_inline_citation_alone_is_enough_to_keep_it(self):
        """Same converse `_finalize` guards: cited correctly inline, no CITATIONS line."""
        out = _finalize_finding(
            self._finding("suspicious", [], ["odd logon [auth_events#1]"]),
            {"auth_events#1": ["e:0"]},
            1,
            1,
        )
        assert out.disposition == "suspicious"


class TestEmptyCitedBlocksAreSurfacedNotPunished:
    async def test_a_disposition_resting_only_on_empty_blocks_warns(self, caplog):
        """Defect (b): visible, deliberately not downgraded."""
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(
                auth_events=[ResultSet(query="auth", row_count=0, rows=[])],
            ),
        )
        report = BrokerReport(
            task_id="t1", hypothesis_id="h-42", results=[siem],
            classification=TaskClassification(tool_families=["siem"], rationale="x"),
            cost=CostSummary(),
        )
        gen = (
            "</think>OBSERVATIONS:\n- bostoll logged on [auth_events#1]\n"
            "DISPOSITION: benign\nCONFIDENCE: 0.72\nCITATIONS: auth_events#1"
        )
        with caplog.at_level("WARNING"):
            findings = await gather(report, _scope(), _DomainModel({
                "identity": gen, "network": gen, "endpoint": gen,
            }))

        identity = next(f for f in findings.findings if f.domain == "identity")
        # Surfaced to the consumer...
        assert identity.exhibits[0].row_count == 0
        assert any("zero rows" in r.getMessage() for r in caplog.records)
        # ...but NOT downgraded: an empty set is legitimate negative evidence.
        assert identity.disposition == "benign"
        assert identity.confidence == 0.72


class TestGatherCarriesTheRetrievalRecord:
    """`HypothesisFindings.retrieval` -- see `RetrievalSummary`.

    Without it the contract carried three judgements and no account of the
    retrieval behind them, so an `inconclusive` was unreadable: a domain reports
    it both when the rows genuinely decide nothing and when nothing was ever
    retrieved for it. Telling those apart is the Analyst Agent's call, which
    means it has to be handed the facts to make it.
    """

    _GENS = {
        "identity": (
            "</think>OBSERVATIONS:\n- one logon for bostoll [auth_events#1]\n"
            "DISPOSITION: suspicious\nCONFIDENCE: 0.7\nCITATIONS: auth_events#1"
        ),
        "network": (
            "</think>OBSERVATIONS:\n- a lookup of x.com [dns_resolutions#1]\n"
            "DISPOSITION: benign\nCONFIDENCE: 0.4\nCITATIONS: dns_resolutions#1"
        ),
        "endpoint": (
            "</think>OBSERVATIONS:\n- cmd.exe ran [processes#1]\n"
            "DISPOSITION: malicious\nCONFIDENCE: 0.9\nCITATIONS: processes#1"
        ),
    }

    @staticmethod
    def _report() -> BrokerReport:
        from contracts import FetchPlan, FetchStep, SiemAssessment, StepOutcome

        step_done = FetchStep(step_id="siem-1", family="siem", objective="get auth events")
        step_unplanned = FetchStep(step_id="siem-2", family="siem", objective="get dns")
        siem = SubtaskResult(
            task_id="t1:siem:1",
            status=SubtaskStatus.OK,
            findings=SiemFindings(
                auth_events=[ResultSet(query="auth", row_count=1, rows=[{"user": "bostoll"}])],
                dns_resolutions=[ResultSet(query="dns", row_count=1, rows=[{"query": "x.com"}])],
                processes=[ResultSet(query="proc", row_count=1, rows=[{"process": "cmd.exe"}])],
            ),
            assessment=SiemAssessment(
                covered=["auth_events", "dns_resolutions"], not_covered=["connections"]
            ),
        )
        return BrokerReport(
            task_id="t1",
            hypothesis_id="h-42",
            plan=FetchPlan(steps=[step_done, step_unplanned], rationale="r"),
            step_outcomes=[
                StepOutcome(step=step_done, completed=True, rows_retrieved=3, evaluated=True),
                # Planned, never dispatched: `completed=False, evaluated=False`.
                StepOutcome(step=step_unplanned, completed=False, evaluated=False),
            ],
            results=[siem],
            dispatched=["siem"],
            classification=TaskClassification(tool_families=["siem"], rationale="x"),
            cost=CostSummary(),
        )

    async def test_steps_carry_completion_and_whether_it_was_judged(self):
        findings = await gather(self._report(), _scope(), _RecordingDomainModel(self._GENS))

        assert findings.retrieval is not None
        assert findings.retrieval.dispatched == ["siem"]

        by_id = {s.step_id: s for s in findings.retrieval.steps}
        assert by_id["siem-1"].completed is True
        assert by_id["siem-1"].evaluated is True
        assert by_id["siem-1"].rows_retrieved == 3
        # The distinction `StepOutcome.evaluated` exists for: nobody judged this
        # one, which is not the same fact as "ran and fell short".
        assert by_id["siem-2"].completed is False
        assert by_id["siem-2"].evaluated is False

    async def test_coverage_comes_from_the_subagents_own_assessment(self):
        findings = await gather(self._report(), _scope(), _RecordingDomainModel(self._GENS))

        assert findings.retrieval.covered == ["auth_events", "dns_resolutions"]
        assert findings.retrieval.not_covered == ["connections"]

    async def test_a_category_one_dispatch_retrieved_is_not_reported_unmet(self):
        """The two lists are disjoint, and the subtraction is load-bearing.

        A step scoped to one category honestly reports the other three as not
        covered. On `cli-20260825T100434` -- four siem steps, one category each --
        a plain union of both fields put all four categories in BOTH lists, which
        tells the consumer nothing.
        """
        from contracts import SiemAssessment

        report = self._report()
        # A second dispatch that got `connections`, which the first declared unmet.
        report.results.append(
            SubtaskResult(
                task_id="t1:siem:2",
                status=SubtaskStatus.OK,
                findings=SiemFindings(
                    connections=[ResultSet(query="conn", row_count=2, rows=[{"src_ip": "1.1.1.1"}])]
                ),
                assessment=SiemAssessment(
                    covered=["connections"], not_covered=["auth_events", "processes"]
                ),
            )
        )

        findings = await gather(report, _scope(), _RecordingDomainModel(self._GENS))

        covered = findings.retrieval.covered
        not_covered = findings.retrieval.not_covered
        assert set(covered) == {"auth_events", "dns_resolutions", "connections"}
        # `processes` is the only category nobody retrieved.
        assert not_covered == ["processes"]
        assert not set(covered) & set(not_covered)

    async def test_a_vt_assessment_contributes_no_categories(self):
        """A reputation lookup is not bucketed by CIM category."""
        from contracts import VtAssessment, VtFindings, VtVerdict

        report = self._report()
        report.results.append(
            SubtaskResult(
                task_id="t1:vt:1",
                status=SubtaskStatus.OK,
                findings=VtFindings(
                    verdicts=[VtVerdict(kind="domain", value="x.com", found=True, malicious=3)]
                ),
                assessment=VtAssessment(looked_up=1),
            )
        )

        findings = await gather(report, _scope(), _RecordingDomainModel(self._GENS))

        # Unchanged by the vt result -- no spurious category, and no crash on an
        # assessment that has no `covered` field at all.
        assert findings.retrieval.covered == ["auth_events", "dns_resolutions"]
        assert findings.retrieval.not_covered == ["connections"]


class TestTheTwoGatesStayDistinguishable:
    """Characterization tests, written before the shared-helper extraction.

    `_finalize` and `_finalize_finding` apply the same discipline and differ in
    exactly three ways: the observations field they read, the test for "this
    verdict claimed something", and the note appended on a downgrade. A helper
    that unifies any of those looks like a tidy-up and is a behaviour change, so
    each difference is pinned here in full rather than by substring.
    """

    def _verdict(self, stance, citations):
        return AnalystVerdict(
            domain="identity",
            stance=stance,
            confidence=0.95,
            rationale="a confident read.",
            citations=list(citations),
        )

    def _finding(self, disposition, citations):
        return DomainFinding(
            domain="identity",
            disposition=disposition,
            confidence=0.95,
            rationale="a confident read.",
            citations=list(citations),
        )

    def test_the_verdict_note_is_the_verdict_note(self):
        out = _finalize(self._verdict("supports", ["auth_events#9"]), {}, 1, 1)
        assert out.rationale == (
            "a confident read. "
            "[ungrounded: no cited evidence resolved to the provided evidence]"
        )

    def test_the_finding_note_is_the_finding_note(self):
        out = _finalize_finding(self._finding("malicious", ["auth_events#9"]), {}, 1, 1)
        assert out.rationale == "a confident read. [downgraded: no cited evidence resolved]"

    def test_a_benign_disposition_is_decisive_too(self):
        """The finding gate tests `!= inconclusive`, not membership of a
        decisive pair. "benign, and I am 95% sure" rests on evidence just as
        much as "malicious" does, and an uncitable benign call is the one most
        likely to close an investigation."""
        out = _finalize_finding(self._finding("benign", []), {}, 1, 1)
        assert out.disposition == "inconclusive"
        assert out.confidence <= 0.3

    def test_a_suspicious_disposition_is_decisive_too(self):
        out = _finalize_finding(self._finding("suspicious", []), {}, 1, 1)
        assert out.disposition == "inconclusive"

    def test_the_drop_log_says_which_path_dropped_it(self, caplog):
        """Two paths log the same event, and the artifact is the only place the
        difference shows. Reading a log that says "a finding" tells you which
        analyst tier you are looking at."""
        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            _finalize(self._verdict("supports", ["auth_events#9"]), {}, 1, 1)
        assert "dropped 1 invented citation(s): auth_events#9" in caplog.text
        assert "from a finding" not in caplog.text

        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            _finalize_finding(self._finding("malicious", ["auth_events#9"]), {}, 1, 1)
        assert "dropped 1 invented citation(s) from a finding: auth_events#9" in caplog.text


class TestTheTwoOrchestratorsStayDistinguishable:
    """Characterization tests for `run_one` vs `gather_finding`, same reason.

    Their failure paths return different types with different wording, and the
    wording is what an operator reads out of `assessment.json` / `findings.json`
    when a run went wrong.
    """

    @staticmethod
    def _slice(domain="network"):
        return DomainSlice(
            domain=domain,
            siem_sets=[("connections", ResultSet(query="q", row_count=1, rows=[{"dest": "1.2.3.4"}]))],
        )

    def test_the_verdicts_empty_slice_rationale_names_the_hypothesis(self):
        """The shown path can say what it could not assess. The blind path
        cannot -- it does not know a hypothesis exists."""
        v = run_one(_SequenceModel([]), _ctx(), _scope(), DomainSlice(domain="network"))
        assert v.rationale == (
            "no network evidence was retrieved, so the hypothesis cannot be "
            "assessed from this domain"
        )

    def test_the_findings_empty_slice_rationale_does_not(self):
        f = gather_finding(_SequenceModel([]), _scope(), DomainSlice(domain="network"))
        assert f.rationale == "no network evidence was retrieved"
        assert "hypothesis" not in f.rationale

    def test_the_unparseable_rationales_name_what_was_being_parsed(self):
        v = run_one(_SequenceModel(["no", "still no"]), _ctx(), _scope(), self._slice())
        f = gather_finding(_SequenceModel(["no", "still no"]), _scope(), self._slice())
        assert v.rationale == "network analyst produced no parseable verdict after a re-ask"
        assert f.rationale == "network analyst produced no parseable finding after a re-ask"

    def test_the_reasoning_trace_comes_from_the_first_reply_not_the_retry(self):
        """`split_reasoning` is applied to `response`, the first generation --
        the retry's trace is discarded. Easy to get backwards when the two
        invocations are folded into one helper."""
        first = "<think>first thoughts</think> no verdict"
        v = run_one(_SequenceModel([first, "<think>second</think> still no"]),
                    _ctx(), _scope(), self._slice())
        assert v.reasoning_trace == "first thoughts"

        f = gather_finding(_SequenceModel([first, "<think>second</think> still no"]),
                           _scope(), self._slice())
        assert f.reasoning_trace == "first thoughts"

    def test_both_bill_both_calls_on_a_reask(self):
        v = run_one(_SequenceModel(["no", "still no"]), _ctx(), _scope(), self._slice())
        f = gather_finding(_SequenceModel(["no", "still no"]), _scope(), self._slice())
        assert v.prompt_tokens > 0 and v.generation_tokens > 0
        assert f.prompt_tokens > 0 and f.generation_tokens > 0

    def test_a_failed_first_call_bills_nothing(self):
        v = run_one(_RaisingModel(), _ctx(), _scope(), self._slice())
        f = gather_finding(_RaisingModel(), _scope(), self._slice())
        assert (v.prompt_tokens, v.generation_tokens) == (0, 0)
        assert (f.prompt_tokens, f.generation_tokens) == (0, 0)
