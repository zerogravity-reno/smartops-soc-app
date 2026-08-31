"""Tests for analyst orchestration: run_one, gather_finding, and gather."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from smartops.subagent_analysts.analyze import (
    _finalize_finding,
    gather,
    gather_finding,
)

# The shown arm, which `blind_compare` still measures against. Imported from its
# own module now, which is what makes the two paths tellable apart at a glance --
# see `subagent_analysts/shown.py`. `analyze()` and `combine()` were deleted with
# the rest of that path, and their tests with them.
from smartops.subagent_analysts.shown import _finalize, run_one
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


class TestRunOne:
    """The hypothesis-SHOWN arm, which keeps its `Stance` and `confidence`.

    Untouched by the 2026-08-31 removal of the blind arm's verdict, and pinned
    here because `_apply_grounding` is shared: a "simplification" that stripped
    the downgrade arm would break `blind_compare` and nothing else would say so.
    """

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


def _finding_gen(narrative: str, observation: str, citation: str) -> str:
    """One well-formed blind reply, in the order `_NARRATIVE_ANSWER_BLOCK` asks for."""
    return (
        f"</think>NARRATIVE: {narrative}\n"
        f"OBSERVATIONS:\n- {observation} [{citation}]\n"
        f"CITATIONS: {citation}"
    )


class TestGatherFinding:
    def test_good_finding_first_try(self):
        model = _SequenceModel([
            _finding_gen("bostoll logged on once from 10.0.1.50.", "clean logon for bostoll", "auth_events#1")
        ])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.domain == "identity"
        assert finding.narrative == "bostoll logged on once from 10.0.1.50."
        assert finding.citations == ["auth_events#1"]
        assert model.calls == 1

    def test_the_finding_carries_no_verdict(self):
        """Pinned at the orchestrator as well as the parser.

        `gather_finding` is what `gather` runs; a `disposition` reappearing
        anywhere between the model and here is the regression this rework exists
        to prevent.
        """
        model = _SequenceModel([
            _finding_gen("bostoll logged on once.", "clean logon", "auth_events#1")
        ])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert not hasattr(finding, "disposition")
        assert not hasattr(finding, "confidence")

    def test_reask_recovers_a_malformed_first_reply(self):
        good = _finding_gen("one logon.", "x", "auth_events#1")
        model = _SequenceModel(["no recognisable block here", good])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.citations == ["auth_events#1"]
        assert model.calls == 2

    def test_a_reply_with_no_narrative_triggers_the_reask(self):
        """The narrative is the product, so its absence is a parse failure.

        The re-ask's last instruction is `_NARRATIVE_ANSWER_BLOCK` itself, which
        leads with NARRATIVE -- so this is the path that recovers it rather than
        the parser quietly substituting `""`.
        """
        without = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCITATIONS: auth_events#1"
        model = _SequenceModel([without, _finding_gen("one logon.", "x", "auth_events#1")])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert model.calls == 2
        assert finding.narrative == "one logon."

    def test_both_attempts_unparseable_yields_an_empty_finding_that_says_why(self):
        model = _SequenceModel(["prose one", "prose two"])
        slice_ = DomainSlice(
            domain="network",
            siem_sets=[("connections", ResultSet(query="q", row_count=1, rows=[{"dest": "1.2.3.4"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.observations == []
        # Unlike the empty-slice branch, this one keeps its sentence: a model ran
        # and failed, which is not a retrieval fact and `RetrievalSummary` has
        # nowhere to record it.
        assert "no parseable finding" in finding.narrative
        assert model.calls == 2

    def test_invented_citation_is_dropped(self):
        gen = (
            "</think>NARRATIVE: one logon and one thing that did not happen.\n"
            "OBSERVATIONS:\n- x [auth_events#1]\n- y [auth_events#99]\n"
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
        """An EMPTY finding, not a sentence saying it is empty.

        No model ran, so there is no account of any rows to record; writing one
        would put words into a translator's mouth exactly as the old
        `inconclusive` default put a verdict there.
        `HypothesisFindings.retrieval` is what now carries the reason -- see
        `TestGatherCarriesTheRetrievalRecord`.
        """
        model = _SequenceModel([])  # would IndexError if invoked
        finding = gather_finding(model, _scope(), DomainSlice(domain="endpoint"))
        assert finding.narrative == ""
        assert finding.observations == []
        assert finding.citations == []
        assert model.calls == 0

    def test_model_exception_is_contained(self):
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(_RaisingModel(), _scope(), slice_)
        assert finding.observations == []
        assert "could not run" in finding.narrative

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
            "</think>NARRATIVE: a burst of failures, then a success.\n"
            "OBSERVATIONS:\n"
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
            domain="endpoint",
            narrative="chrome.exe and one thing that did not happen.",
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
    from smartops.subagent_analysts.shown import _finalize

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


_THREE_DOMAIN_GENS = {
    "identity": _finding_gen(
        "bostoll logged on once from 10.0.1.50 at 09:14.",
        "one logon for bostoll",
        "auth_events#1",
    ),
    "network": _finding_gen(
        "One DNS query resolved x.com.", "a lookup of x.com", "dns_resolutions#1"
    ),
    "endpoint": _finding_gen("cmd.exe ran on BSTOLL-L.", "cmd.exe ran", "processes#1"),
}


class TestGather:
    """`gather()` -- the blind path's producer, and the Analyst Agent's contract."""

    _GENS = _THREE_DOMAIN_GENS

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

    async def test_carries_all_three_domains_and_their_narratives(self):
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        assert findings.task_id == "t1"
        assert findings.hypothesis_id == "h-42"
        assert {f.domain: f.narrative for f in findings.findings} == {
            "identity": "bostoll logged on once from 10.0.1.50 at 09:14.",
            "network": "One DNS query resolved x.com.",
            "endpoint": "cmd.exe ran on BSTOLL-L.",
        }

    async def test_the_contract_carries_no_verdict_at_any_level(self):
        """The absence is the contract -- every call here belongs to the Analyst Agent.

        No hypothesis-level stance (there never was one), and since 2026-08-31 no
        per-domain `disposition` or `confidence` either. A sub-analyst that
        judges its own slice, blind, with nothing able to check it, is the thing
        that was removed; this is what would notice it coming back.
        """
        findings = await gather(_report_with_all_three_domains(), _scope(), _DomainModel(self._GENS))

        assert not hasattr(findings, "overall_stance")
        for judgement in findings.findings:
            for field in ("stance", "disposition", "confidence"):
                assert not hasattr(judgement, field)
        dumped = findings.model_dump_json()
        assert "disposition" not in dumped
        assert "confidence" not in dumped

    async def test_a_domain_with_no_evidence_is_reported_not_omitted(self):
        """"we looked and found nothing" and "we did not look" are different facts.

        The domain is still present and still empty; what tells the two apart is
        now `HypothesisFindings.retrieval` alone, because the finding itself no
        longer carries a sentence explaining itself. That is deliberate -- see
        `contracts.reasoning.HypothesisFindings`, where `RetrievalSummary` is
        recorded as load-bearing for exactly this reason.
        """
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
        assert network.narrative == ""
        assert network.observations == []
        assert network.exhibits == []
        assert findings.retrieval is not None

    async def test_citations_are_frozen_to_their_evidence_ids(self):
        """The consumer must be able to trace a narrative to the rows behind it."""
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

    async def test_the_cited_rows_travel_with_the_finding(self):
        """The Analyst Agent must be able to check a narrative without the store."""
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
    """The blind path's half of the shared gate, after the verdict was removed.

    There is no stance to downgrade and no confidence to cap. What is left is
    strip-what-cannot-be-checked plus a note on the narrative -- and the
    narrative itself is KEPT, deliberately: it is the record of what the model
    claimed, and blanking it would destroy the only evidence that a fabrication
    happened. `observations: []` / `citations: []` / `exhibits: []` beside it are
    what tell the consumer the claim rests on nothing.
    """

    def _finding(self, citations, observations=("a claim [auth_events#9]",)):
        return DomainFinding(
            domain="identity",
            narrative="a confident read.",
            observations=list(observations),
            citations=list(citations),
        )

    def test_a_finding_with_no_resolving_citation_keeps_its_narrative_and_is_marked(self):
        out = _finalize_finding(self._finding(["auth_events#9"]), {}, 1, 1)
        assert out.narrative.startswith("a confident read.")
        assert "downgraded: no cited evidence resolved" in out.narrative
        assert out.citations == []
        assert out.observations == []

    def test_a_finding_that_asserted_nothing_is_not_marked(self):
        """An empty finding is empty, not ungrounded.

        The empty-slice and both-attempts-failed paths reach the wire with no
        observations and no citations. Marking those "ungrounded" would attach a
        fabrication note to a domain that never claimed anything.
        """
        finding = DomainFinding(domain="identity", narrative="", observations=[], citations=[])
        out = _finalize_finding(finding, {}, 1, 1)
        assert out.narrative == ""

    def test_a_grounded_finding_survives_unmarked(self):
        out = _finalize_finding(
            self._finding(["auth_events#1"], ["a claim [auth_events#1]"]),
            {"auth_events#1": ["e:0"]},
            1,
            1,
        )
        assert out.narrative == "a confident read."
        assert out.citations == ["auth_events#1"]

    def test_an_inline_citation_alone_is_enough_to_keep_it(self):
        """Same converse `_finalize` guards: cited correctly inline, no CITATIONS line."""
        out = _finalize_finding(
            self._finding([], ["odd logon [auth_events#1]"]),
            {"auth_events#1": ["e:0"]},
            1,
            1,
        )
        assert out.narrative == "a confident read."
        assert out.citations == ["auth_events#1"]


class TestEmptyCitedBlocksAreSurfacedNotPunished:
    async def test_observations_resting_only_on_empty_blocks_warn(self, caplog):
        """Defect (b): visible, deliberately not removed.

        The warning used to key off `disposition != "inconclusive"` -- "the
        analyst committed to something". With the disposition gone the same
        defect is stated directly: this tier commits to something by writing an
        observation, so an observation standing on nothing but zero-row blocks is
        the case worth surfacing. An empty result set is legitimate negative
        evidence, so it is surfaced and not punished; only reading the claim
        against the rows could tell the two apart, and that is not decidable
        here.
        """
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
        gen = _finding_gen(
            "The query for bostoll's logons returned no rows.",
            "bostoll logged on",
            "auth_events#1",
        )
        with caplog.at_level("WARNING"):
            findings = await gather(report, _scope(), _DomainModel({
                "identity": gen, "network": gen, "endpoint": gen,
            }))

        identity = next(f for f in findings.findings if f.domain == "identity")
        # Surfaced to the consumer...
        assert identity.exhibits[0].row_count == 0
        assert any("zero rows" in r.getMessage() for r in caplog.records)
        # ...but NOT punished: an empty set is legitimate negative evidence, so
        # the narrative and the observation both survive intact.
        assert identity.narrative == "The query for bostoll's logons returned no rows."
        assert identity.observations == ["bostoll logged on [auth_events#1]"]

    async def test_a_finding_with_no_observations_does_not_warn(self, caplog):
        """The re-keyed condition needs both halves, or every empty domain warns."""
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
            "</think>NARRATIVE: the query returned no rows.\n"
            "CITATIONS: auth_events#1"
        )
        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            await gather(report, _scope(), _DomainModel({
                "identity": gen, "network": gen, "endpoint": gen,
            }))

        assert "zero rows" not in caplog.text


class TestGatherCarriesTheRetrievalRecord:
    """`HypothesisFindings.retrieval` -- see `RetrievalSummary`.

    Without it the contract carried three narratives and no account of the
    retrieval behind them, so an empty domain was unreadable: it looks identical
    whether the rows genuinely showed nothing or nothing was ever retrieved.
    Telling those apart is the Analyst Agent's call, which means it has to be
    handed the facts to make it -- and since the sub-analysts stopped judging,
    this summary is the ONLY place those facts live.
    """

    _GENS = _THREE_DOMAIN_GENS

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

    `_finalize` and `_finalize_finding` share `_apply_grounding` and now differ
    in FOUR ways, all parameters rather than branches: the observations field,
    the prose field, the note, and -- since 2026-08-31 -- whether there is a
    stance to downgrade at all. `shown.py` still has `Stance` and `confidence`;
    the blind arm has neither.

    A helper that unifies any of those looks like a tidy-up and is a behaviour
    change, so each difference is pinned here in full rather than by substring.
    In particular, stripping the stance arm as "dead" would break
    `blind_compare`, the harness whose measurements are the evidence the blind
    design rests on.
    """

    def _verdict(self, stance, citations):
        return AnalystVerdict(
            domain="identity",
            stance=stance,
            confidence=0.95,
            rationale="a confident read.",
            citations=list(citations),
        )

    def _finding(self, citations, observations=("a claim [auth_events#9]",)):
        return DomainFinding(
            domain="identity",
            narrative="a confident read.",
            observations=list(observations),
            citations=list(citations),
        )

    def test_the_verdict_note_is_the_verdict_note(self):
        out = _finalize(self._verdict("supports", ["auth_events#9"]), {}, 1, 1)
        assert out.rationale == (
            "a confident read. "
            "[ungrounded: no cited evidence resolved to the provided evidence]"
        )

    def test_the_finding_note_is_the_finding_note(self):
        out = _finalize_finding(self._finding(["auth_events#9"]), {}, 1, 1)
        assert out.narrative == "a confident read. [downgraded: no cited evidence resolved]"

    def test_the_shown_gate_still_downgrades_its_stance_and_caps_confidence(self):
        """The arm that must NOT be simplified away.

        `shown.py` imports `_apply_grounding` and passes `stance_field`; deleting
        that arm because the blind path no longer needs it would silently stop
        `blind_compare`'s shown side from ever downgrading.
        """
        out = _finalize(self._verdict("refutes", ["auth_events#9"]), {}, 1, 1)
        assert out.stance == "inconclusive"
        assert out.confidence <= 0.3

    def test_the_shown_gate_still_exempts_inconclusive(self):
        out = _finalize(self._verdict("inconclusive", []), {}, 1, 1)
        assert out.stance == "inconclusive"
        assert out.confidence == 0.95  # not capped; nothing was claimed
        assert out.rationale == "a confident read."  # and not marked

    def test_the_blind_gate_has_no_decisive_test_left(self):
        """Any assertion with no surviving citation is marked, full stop.

        The old gate asked `disposition != "inconclusive"` -- a four-member
        vocabulary of which one member was exempt. There is no vocabulary now, so
        the test is simply "did it assert anything": an observation, or a
        citation the model offered. A `benign` call resting on nothing used to be
        the case most likely to close an investigation, and the equivalent now is
        an observation resting on nothing.
        """
        out = _finalize_finding(self._finding([], ["a claim [auth_events#9]"]), {}, 1, 1)
        assert "downgraded: no cited evidence resolved" in out.narrative

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
            _finalize_finding(self._finding(["auth_events#9"]), {}, 1, 1)
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
        """The shown path can say what it could not assess."""
        v = run_one(_SequenceModel([]), _ctx(), _scope(), DomainSlice(domain="network"))
        assert v.rationale == (
            "no network evidence was retrieved, so the hypothesis cannot be "
            "assessed from this domain"
        )

    def test_the_findings_empty_slice_says_nothing_at_all(self):
        """The blind path writes no prose it did not read from rows.

        It used to say "no network evidence was retrieved", which was a sentence
        the pipeline wrote and attributed to an analyst that never ran -- the
        same shape of fabrication as the `inconclusive` default it sat beside.
        `HypothesisFindings.retrieval` carries the fact instead.
        """
        f = gather_finding(_SequenceModel([]), _scope(), DomainSlice(domain="network"))
        assert f.narrative == ""
        assert f.observations == []

    def test_the_unparseable_failures_name_what_was_being_parsed(self):
        v = run_one(_SequenceModel(["no", "still no"]), _ctx(), _scope(), self._slice())
        f = gather_finding(_SequenceModel(["no", "still no"]), _scope(), self._slice())
        assert v.rationale == "network analyst produced no parseable verdict after a re-ask"
        assert f.narrative == "network analyst produced no parseable finding after a re-ask"

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


class TestTheTokenEstimateIsCheckedAgainstWhatTheModelCounted:
    """`estimate_tokens` is `len(text) // 2.5` and can still run low on
    unusually dense evidence.

    The comment on `_CHARS_PER_TOKEN` used to say the inexactness was safe
    "because the model reports the true count back". It does report it, on every
    call, and nothing compared the two -- so a pack that overran the window
    surfaced as a provider error indistinguishable from a bad credential, or, if
    the provider truncated instead of rejecting, not at all.

    Finding 4 (2026-08-30 whole-branch review): the comparison used to be
    `prompt_tokens > token_budget`, where `token_budget` bounds the EVIDENCE
    alone while `prompt_tokens` is the FULL system+user prompt Bedrock counted
    -- so the warning fired on every full pack even when the estimator was
    correct, blaming "the chars-per-token estimate" for tokens the system
    prompt and generation reserve (both already reserved separately) accounted
    for on their own. It now compares against `_DANGER_THRESHOLD` (the window
    minus the generation reserve minus the safety margin) -- the real line a
    full prompt has to stay under -- and the message names what actually
    overran instead.
    """

    class _CountingModel:
        """Reports a prompt-token count of its own choosing."""

        def __init__(self, prompt_tokens: int):
            self._prompt_tokens = prompt_tokens
            self.calls = 0

        def invoke(self, system: str, user: str) -> AnalystResponse:
            self.calls += 1
            return AnalystResponse(
                generation=_finding_gen(
                    "one outbound connection to 1.2.3.4.", "x", "connections#1"
                ),
                prompt_tokens=self._prompt_tokens,
                generation_tokens=5,
                stop_reason="stop",
            )

    @staticmethod
    def _slice():
        return DomainSlice(
            domain="network",
            siem_sets=[("connections", ResultSet(query="q", row_count=1, rows=[{"dest": "1.2.3.4"}]))],
        )

    def test_a_count_over_the_danger_threshold_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            gather_finding(self._CountingModel(31_000), _scope(), self._slice())
        assert "31000" in caplog.text
        # Names what actually overran -- the window's headroom for the
        # generation reserve -- rather than blaming the chars-per-token
        # estimate, which is not always the cause.
        assert "window" in caplog.text
        assert "generation reserve" in caplog.text

    def test_a_count_inside_the_danger_threshold_is_silent(self, caplog):
        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            gather_finding(self._CountingModel(4_000), _scope(), self._slice())
        assert caplog.text == ""

    def test_a_full_pack_over_the_evidence_budget_alone_no_longer_false_alarms(self, caplog):
        """The exact false positive Finding 4 describes.

        This count exceeds `_PACK_TOKEN_BUDGET` (the evidence-only budget) --
        which is what the OLD comparison checked, and would have warned on --
        but the window itself still has plenty of room once the system prompt
        and generation reserve, both already carved out separately, are
        accounted for. The corrected comparison must stay silent.
        """
        from smartops.subagent_analysts.packing import _PACK_TOKEN_BUDGET

        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            gather_finding(
                self._CountingModel(_PACK_TOKEN_BUDGET + 1_000), _scope(), self._slice()
            )
        assert caplog.text == ""

    def test_the_shown_path_checks_it_too(self, caplog):
        """One helper, so both paths get this or neither does."""
        with caplog.at_level(logging.WARNING, logger="smartops.subagent_analysts.analyze"):
            run_one(self._CountingModel(31_000), _ctx(), _scope(), self._slice())
        assert "generation reserve" in caplog.text
