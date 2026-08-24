"""Tests for analyst orchestration: run_one, combine, and analyze."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from smartops.subagent_analysts.analyze import (
    _finalize,
    _finalize_finding,
    analyze,
    combine,
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
        for domain, gen in self._by_domain.items():
            if self._MARKERS[domain] in system:
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
