"""Tests for analyst orchestration: run_one, gather_finding, and gather."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from smartops.subagent_analysts.analyze import (
    _drop_unsupported_figures,
    _drop_unsupported_sentences,
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
    VtVerdict,
)


def _scope() -> Scope:
    return Scope(
        entities=[Entity(kind="user", value="bostoll"), Entity(kind="host", value="BSTOLL-L")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


def _ctx() -> InvestigationContext:
    return InvestigationContext(hypothesis="bostoll was brute-forced on BSTOLL-L")



def _bare_slice() -> DomainSlice:
    """An evidence-free slice, for the tests that exercise the CITATION gate alone.

    `_finalize_finding` runs two gates. The first asks whether a cited id
    resolves against `valid_ids`; the second (`_drop_unsupported_figures`) asks
    whether the rows behind that id actually say what the observation claims,
    and it reads those rows out of the slice. Given a slice holding nothing,
    `exhibits_for` returns no blocks, the second gate has nothing to check and
    passes every observation through -- so these tests keep measuring citation
    resolution and only that.

    The slice's `domain` label is unused: the gate takes the domain it logs from
    the finding, not from here.
    """
    return DomainSlice(domain="identity")


class _SequenceModel:
    """Returns queued generations in order, one per invoke."""

    def __init__(self, generations: list[str]):
        self._queue = list(generations)
        self.calls = 0
        # Recorded so a test can assert on what the RE-ASK actually said, not just
        # that one happened -- `_invoke_with_one_reask` now appends the parse
        # error to it, and "the model was asked again" is a weaker claim than
        # "the model was told what it got wrong".
        self.prompts: list[str] = []

    def invoke(self, system: str, user: str) -> AnalystResponse:
        self.calls += 1
        self.prompts.append(user)
        gen = self._queue.pop(0)
        # A `(generation, stop_reason)` pair queues a reply that ended some other way.
        gen, stop = gen if isinstance(gen, tuple) else (gen, "stop")
        return AnalystResponse(generation=gen, prompt_tokens=10, generation_tokens=5, stop_reason=stop)


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

    def test_a_reply_cut_off_at_the_token_limit_is_reasked_not_parsed(self):
        # c7dbf51d T1: a parseable reply whose last observation looped until
        # `max_gen_len` shipped as if whole.
        good = _finding_gen("one logon.", "x", "auth_events#1")
        model = _SequenceModel([(good, "length"), good])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert model.calls == 2
        assert "token limit" in model.prompts[1]
        assert finding.citations == ["auth_events#1"]

    def test_a_reask_also_cut_off_keeps_the_finished_lines(self):
        # 78cd60ec T1 endpoint: both replies hit the limit and the domain was lost.
        good = _finding_gen("one logon.", "x", "auth_events#1")
        runaway = good + "\n- and then , , , , , , [auth_ev"
        model = _SequenceModel([(runaway, "length"), (runaway, "length")])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert model.calls == 2
        assert finding.narrative == "one logon."
        assert not any(", , ," in o for o in finding.observations)

    _LOOP = "Host H ran processes under user U, started by OneDrive.exe; one command line, repeated."

    def _slice(self) -> DomainSlice:
        return DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )

    def test_a_repeated_sentence_is_kept_once(self):
        # a818a3fd T4 endpoint (B-1): one sentence written over and over.
        model = _SequenceModel([_finding_gen(" ".join([self._LOOP] * 30), "x", "auth_events#1")])
        finding = gather_finding(model, _scope(), self._slice())
        assert finding.narrative.count(self._LOOP) == 1
        assert model.calls == 1

    def test_a_looping_cut_off_reask_names_the_sentence(self):
        looping = "</think>NARRATIVE: " + " ".join([self._LOOP] * 30)
        model = _SequenceModel([(looping, "length"), _finding_gen("one logon.", "x", "auth_events#1")])
        gather_finding(model, _scope(), self._slice())
        assert f'You wrote "{self._LOOP}" 30 times' in model.prompts[1]

    def test_the_first_cut_off_reply_is_salvaged_when_the_reask_is_not(self):
        first = _finding_gen(" ".join([self._LOOP] * 5), "x", "auth_events#1") + "\n- and then [auth_ev"
        model = _SequenceModel([(first, "length"), ("</think>NARRATIVE: " + self._LOOP * 40, "length")])
        finding = gather_finding(model, _scope(), self._slice())
        assert finding.citations == ["auth_events#1"]
        assert finding.narrative.count(self._LOOP) == 1

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
                # `count=14` so the observation's "14 failed logons" is a claim the
                # rows actually support: `_drop_unsupported_figures` runs after the
                # citation gate and would otherwise drop the line for asserting a
                # figure absent from its own set, costing this test its subject.
                ("auth_events", ResultSet(query="q1", row_count=1, rows=[{"user": "bostoll", "action": "failure", "count": "14"}])),
                ("auth_events", ResultSet(query="q2", row_count=1, rows=[{"user": "bostoll"}])),
            ],
        )
        finding = gather_finding(model, _scope(), slice_)
        # Two, not three. The un-bulleted "The pattern was: burst, pause, burst"
        # is swept into the OBSERVATIONS block by `_FINDING_OBSERVATIONS_RE` and
        # then dropped by `_drop_unsupported_figures` for citing nothing. That is
        # the intended behaviour and not this test's subject: what matters here is
        # that the observation AFTER the prose colon survived with its inline id,
        # which is the assertion below.
        assert len(finding.observations) == 2
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
        out = _finalize_finding(finding, {"processes#1": []}, 10, 20, _bare_slice())
        assert out.observations == ["powershell -enc observed [processes#1]"]


class TestACitationCountsWhateverTheModelWrapsItIn:
    """The brackets are not the citation; the id is.

    `_OBSERVATION_CITE_RE` required `[header_id]` until 2026-09-01. The live run
    `cli-20260901T075503` wrote its ids in prose instead -- `(dns_resolutions#11
    and #34)`, `Processes#16 and #18`, `Uncategorised#1-20` -- so nothing matched,
    every observation took the "cited nothing at all" branch, and the per-claim
    gate validated NOTHING in all three domains. Two endpoint observations
    claiming 1,573,654 and 240,882 events crossed the boundary on sets that never
    resolved, unmarked, because the downgrade note needs a finding to have zero
    surviving citations and this one had two.

    Requiring a punctuation style is asking the model to arm the gate that exists
    to check the model.
    """

    def test_a_parenthesised_id_is_validated_not_waved_through(self):
        finding = DomainFinding(
            domain="network",
            narrative="dns and one claim that rests on nothing.",
            citations=["dns_resolutions#11"],
            observations=[
                "BSTOLL-L performed 21 DNS lookups (dns_resolutions#11).",
                "eight flows of exactly one byte (connections#42).",
            ],
        )
        out = _finalize_finding(finding, {"dns_resolutions#11": []}, 10, 20, _bare_slice())
        assert out.observations == ["BSTOLL-L performed 21 DNS lookups (dns_resolutions#11)."]

    def test_a_capitalised_prose_id_resolves_against_the_lowercase_key(self):
        """`valid_ids` keys are lowercase; `Processes#16` is still citing one."""
        finding = DomainFinding(
            domain="endpoint",
            narrative="processes.",
            citations=[],
            observations=["Processes#16 and #18 each contained 240,882 events."],
        )
        out = _finalize_finding(finding, {"processes#16": []}, 10, 20, _bare_slice())
        assert out.observations == ["Processes#16 and #18 each contained 240,882 events."]
        assert out.citations == ["processes#16"]

    def test_the_live_run_failure_is_now_caught(self):
        """The exact shape that escaped: a prose id naming a set that does not exist."""
        finding = DomainFinding(
            domain="endpoint",
            narrative="a great deal that did not happen.",
            citations=["processes#3"],
            observations=[
                "Processes#3 grouped 25 events into four sets.",
                "Uncategorised#1 aggregated 1,573,654 events across 17 groups.",
                "Processes#16 and #18 each contained 240,882 events.",
            ],
        )
        out = _finalize_finding(finding, {"processes#3": []}, 10, 20, _bare_slice())
        assert out.observations == ["Processes#3 grouped 25 events into four sets."]

    def test_an_invented_id_is_stripped_from_a_line_that_survives(self):
        """The strip assumed brackets and exact case, so it silently no-opped and
        left the invented reference sitting in the kept line."""
        finding = DomainFinding(
            domain="endpoint",
            narrative="mixed.",
            citations=["processes#1"],
            observations=["powershell ran processes#1 and also Processes#42 somewhere"],
        )
        out = _finalize_finding(finding, {"processes#1": []}, 10, 20, _bare_slice())
        assert "42" not in out.observations[0]
        assert "processes#1" in out.observations[0]


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
        "bostoll logged on once from 10.0.1.50.",
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
            "identity": "bostoll logged on once from 10.0.1.50.",
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
        out = _finalize_finding(self._finding(["auth_events#9"]), {}, 1, 1, _bare_slice())
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
        out = _finalize_finding(finding, {}, 1, 1, _bare_slice())
        assert out.narrative == ""

    def test_a_grounded_finding_survives_unmarked(self):
        out = _finalize_finding(
            self._finding(["auth_events#1"], ["a claim [auth_events#1]"]),
            {"auth_events#1": ["e:0"]},
            1,
            1,
            _bare_slice(),
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
            _bare_slice(),
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
        # the prose and the observation both survive intact; code names the
        # empty search after it.
        assert identity.narrative == "The query for bostoll's logons returned no rows."
        assert "Searches that returned no rows:" in identity.facts
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
                StepOutcome(step=step_done, completed=True, rows_retrieved=3, evaluated=True,
                            proven_empty={"file_events": "Endpoint.Filesystem"}),
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
        # The dataset an absence proof holds in reaches the Analyst (B54).
        assert by_id["siem-1"].proven_empty == {"file_events": "Endpoint.Filesystem"}
        # The distinction `StepOutcome.evaluated` exists for: nobody judged this
        # one, which is not the same fact as "ran and fell short".
        assert by_id["siem-2"].completed is False
        assert by_id["siem-2"].evaluated is False

    async def test_coverage_is_the_assessment_plus_what_rows_settle(self):
        # The assessment omits `processes`, but a processes row was projected:
        # rows settle coverage, not the model's claim (a818a3fd T1, B-6).
        findings = await gather(self._report(), _scope(), _RecordingDomainModel(self._GENS))

        assert findings.retrieval.covered == ["auth_events", "dns_resolutions", "processes"]
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
                    covered=["connections"], not_covered=["auth_events", "registry_events"]
                ),
            )
        )

        findings = await gather(report, _scope(), _RecordingDomainModel(self._GENS))

        covered = findings.retrieval.covered
        not_covered = findings.retrieval.not_covered
        assert set(covered) == {"auth_events", "dns_resolutions", "processes", "connections"}
        # `registry_events` is the only category nobody retrieved.
        assert not_covered == ["registry_events"]
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
        assert findings.retrieval.covered == ["auth_events", "dns_resolutions", "processes"]
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
        out = _finalize_finding(self._finding(["auth_events#9"]), {}, 1, 1, _bare_slice())
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
        out = _finalize_finding(self._finding([], ["a claim [auth_events#9]"]), {}, 1, 1, _bare_slice())
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
            _finalize_finding(self._finding(["auth_events#9"]), {}, 1, 1, _bare_slice())
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


class TestTheFigureGateReplaysTheRecordedRuns:
    """`_drop_unsupported_figures` against the three 2026-09-02 coinhive runs.

    The blocks here are the real `Exhibit.rows` those runs stored -- the exact
    projected text each analyst read -- trimmed to the lines the assertion turns
    on. Built as a `DomainSlice` of `ResultSet`s rather than by loading
    `.smartops/runs/...` so the test does not depend on artifacts that are not
    checked in.

    The gate exists because the CITATION gate cannot see this failure: every
    observation below cites an id that resolves.
    """

    def _slice(self, rows, category="processes", domain="endpoint"):
        return DomainSlice(
            domain=domain,
            siem_sets=[(category, ResultSet(query="q", row_count=len(rows), rows=rows))],
        )

    def test_the_prompt_example_leaking_into_a_finding_is_dropped(self):
        """The authorization run's endpoint lead observation.

        `processes#2` is 100 grouped rows totalling 654 events, carrying no
        timestamp. The observation reported 124 processes, 18 distinct images
        and 46 repeated command lines between 11:04 and 17:17 -- the three
        figures in `_ENDPOINT_FACTS_BODY`'s worked example, and a time range for
        rows that have no time.
        """
        rows = [
            {"host": "H.example", "user": "-", "process_name": "VACon64.exe", "count": "3"},
            {"host": "H.example", "user": "BudStoll", "process_name": "chrome.exe", "count": "216"},
        ]
        observation = (
            "Host H.example ran 124 processes under user bstoll between "
            "2018-08-20T11:04 and 2018-08-20T17:17, with 18 distinct images and "
            "46 repeated command lines. [processes#1]"
        )
        kept = _drop_unsupported_figures([observation], self._slice(rows), "endpoint")
        assert kept == []

    def test_a_time_range_on_rows_that_carry_none_is_dropped(self):
        """Separately checked, because a range is not a figure.

        An observation can state a time whose digits all happen to appear
        somewhere in the block. What condemns it is that every set it cites
        reports `NO_TIME_MARKER`.
        """
        rows = [{"host": "H.example", "process_name": "a.exe", "count": "11"}]
        observation = "Host H.example was busy between 11:00 and 11:11. [processes#1]"
        kept = _drop_unsupported_figures([observation], self._slice(rows), "endpoint")
        assert kept == []

    def test_a_genuine_observation_survives(self):
        """`138 backgroundTaskHost.exe` -- real, and it must not be collateral."""
        rows = [
            {"host": "H.example", "user": "-", "process_name": "backgroundTaskHost.exe", "count": "138"},
        ]
        observation = "Host H.example ran 138 backgroundTaskHost.exe processes. [processes#1]"
        kept = _drop_unsupported_figures([observation], self._slice(rows), "endpoint")
        assert kept == [observation]

    def test_a_figure_the_summary_supplies_is_supported(self):
        """The point of the aggregate: a total no single row carries.

        No row says `216`+`138`=`354`, but `summarise_rows` computes it into the
        block, so an observation quoting the set total is grounded. Before the
        aggregate this figure was unverifiable and the model was guessing at it.
        """
        rows = [
            {"host": "H.example", "process_name": "chrome.exe", "count": "216"},
            {"host": "H.example", "process_name": "git.exe", "count": "138"},
        ]
        observation = "Host H.example accounts for 354 process events. [processes#1]"
        kept = _drop_unsupported_figures([observation], self._slice(rows), "endpoint")
        assert kept == [observation]

    def test_a_real_time_range_survives(self):
        rows = [
            {"_time": "2018-08-20T11:04:21+02:00", "host": "H.example", "process_name": "a.exe"},
            {"_time": "2018-08-20T17:17:22+02:00", "host": "H.example", "process_name": "a.exe"},
        ]
        observation = (
            "Host H.example ran processes between 2018-08-20T11:04:21+02:00 and "
            "2018-08-20T17:17:22+02:00. [processes#1]"
        )
        kept = _drop_unsupported_figures([observation], self._slice(rows), "endpoint")
        assert kept == [observation]

    def test_the_reputation_line_survives(self):
        """consent/network: `12 malicious, 2 suspicious, 77 harmless` is verbatim."""
        slice_ = DomainSlice(
            domain="network",
            vt_verdicts=[
                VtVerdict(kind="domain", value="example.test", found=True,
                          malicious=12, suspicious=2, harmless=77, evidence_id="e:0"),
            ],
        )
        observation = (
            "example.test had 12 malicious, 2 suspicious and 77 harmless hits. [reputation#1]"
        )
        assert _drop_unsupported_figures([observation], slice_, "network") == [observation]

    def test_bare_hash_continuations_are_not_read_as_figures(self):
        """`[uncategorised#2, #4, ... #23]` -- the authorization identity finding.

        `23` came from the citation list, not from a claim. A gate stripping only
        full `category#N` ids reports it unsupported and drops a sound line.
        """
        rows = [{"sourcetype": "WinEventLog", "count": "40"}]
        slice_ = DomainSlice(
            domain="identity",
            untagged_sets=[ResultSet(query="q", row_count=len(rows), rows=rows)],
        )
        observation = "System-wide monitoring occurred. [uncategorised#1, #4, #23]"
        assert _drop_unsupported_figures([observation], slice_, "identity") == [observation]

    def test_an_uncited_observation_is_dropped(self):
        """The decision `_resolve_observation_citations` left unmade, made here.

        It was measured: 4 of the 9 observations in the 2026-09-02 consent
        endpoint finding cited nothing, and one put "240,882 total events" on the
        wire resting on no set at all. A claim nothing can check is what this gate
        drops everywhere else, and an uncited line is the purest case of one.
        """
        rows = [{"host": "H.example", "process_name": "a.exe"}]
        observation = "Something happened involving 999999 events."
        kept = _drop_unsupported_figures([observation], self._slice(rows), "endpoint")
        assert kept == []

    def test_a_figure_inside_a_longer_number_is_not_support(self):
        """The gate's own blind spot, found in review on 2026-09-05.

        The check was `figure not in haystack` -- a raw substring test over the
        rendered block. So `18` was "supported" by any row containing `2018`,
        `1080`, or an IP octet. That is not hypothetical: `18` is one of the three
        fabricated figures in the defect this gate was built to catch
        (124 / 18 / 46), and it was passing, because `processes#2` contains longer
        numbers that contain it.

        It stayed invisible because every hand-verification of this gate examined
        the observations it DROPPED and none of the ones it KEPT. Both sides are
        now tokenised by `_figures` and compared as sets.
        """
        rows = [{"host": "H.example", "process_name": "a.exe", "count": "2018"}]
        observation = "Host H.example ran 18 distinct images. [processes#1]"
        assert _drop_unsupported_figures(
            [observation], self._slice(rows), "endpoint"
        ) == []

    def test_a_timestamp_in_the_rows_cannot_support_a_count(self):
        """Symmetry: times are stripped from the EVIDENCE as well as the claim.

        Without that, a row timestamped `...T15:35:34...` would support an
        observation claiming 35 of something.
        """
        rows = [{"_time": "2018-08-20T15:35:34+02:00", "host": "H.example",
                 "process_name": "a.exe"}]
        observation = (
            "Host H.example ran 35 processes between 2018-08-20T15:35:34+02:00 and "
            "2018-08-20T15:35:34+02:00. [processes#1]"
        )
        assert _drop_unsupported_figures(
            [observation], self._slice(rows), "endpoint"
        ) == []

    def test_a_calendar_date_is_not_an_asserted_figure(self):
        """The 2026-09-05 re-measure regression, pinned.

        Rule 3 tells the model to copy times verbatim; it kept writing "August 20,
        2018" anyway. The gate read 20 and 2018 as figures the observation
        asserted, found them in no row, and dropped every dated line -- emptying
        all three domains. Whether the model obeys the verbatim rule is a separate
        question from whether this gate may treat a date as a claim about rows.
        """
        rows = [{"host": "H.example", "process_name": "a.exe", "count": "46"}]
        for observation in (
            "Between August 20, 2018 and August 21, 2018 there were 46 events. [processes#1]",
            "Between August 20th and 21st there were 46 events. [processes#1]",
            "On 20 August 2018 there were 46 events. [processes#1]",
        ):
            assert _drop_unsupported_figures(
                [observation], self._slice(rows), "endpoint"
            ) == [observation], observation

    def test_a_real_count_beside_a_date_is_still_checked(self):
        # Guards the over-correction: stripping dates must not blind the gate to
        # the figure sitting next to one.
        rows = [{"host": "H.example", "process_name": "a.exe", "count": "46"}]
        observation = "Between August 20, 2018 and August 21, 2018 there were 999 events. [processes#1]"
        assert _drop_unsupported_figures([observation], self._slice(rows), "endpoint") == []

    def test_thousands_separators_are_normalised(self):
        """`88,851` against `88851` in the rows. Not normalising flags every
        large figure the model formats for a human reader."""
        rows = [{"sourcetype": "stream:dns", "count": "88851"}]
        slice_ = DomainSlice(
            domain="network",
            untagged_sets=[ResultSet(query="q", row_count=len(rows), rows=rows)],
        )
        observation = "There were 88,851 DNS-related events. [uncategorised#1]"
        assert _drop_unsupported_figures([observation], slice_, "network") == [observation]


class TestTheReaskNamesWhatBroke:
    """T15. `parse_finding` raises for five distinct reasons now.

    A fixed "did not end with the required block" tells the model none of them.
    Each message already says which rule broke and quotes the offending text, so
    it is appended to the re-ask -- last, after the rules and the block, where it
    is the most specific thing the model reads.
    """

    def test_the_second_prompt_carries_the_parse_error(self):
        # First reply breaks the "observations cite nothing" rule. (It used to
        # break the narrative-anchor rule; that one was withdrawn after the model
        # was measured against it -- see
        # `parse.TestTheNarrativeAnchorRuleIsAskedForButNotEnforced`.)
        bad = (
            "</think>NARRATIVE: Two accounts each saw four failed authentication "
            "attempts against the host, every one from the loopback address.\n"
            "OBSERVATIONS:\n- something happened\n- something else happened\n"
            "CITATIONS: auth_events#1"
        )
        good = (
            "</think>NARRATIVE: auth_events#1 shows four failed logons from the "
            "loopback address for two accounts against one host, none succeeding.\n"
            "OBSERVATIONS:\n- four failed logons [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        model = _SequenceModel([bad, good])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[
                (
                    "auth_events",
                    ResultSet(query="q", row_count=1, rows=[{"user": "u", "count": "4"}]),
                ),
            ],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.observations == ["four failed logons [auth_events#1]"]
        assert model.calls == 2

        second = model.prompts[1]
        assert "What was wrong with your previous reply:" in second
        assert "cited no evidence in any" in second
        # The rules and the block are still there, before the reason.
        assert "these rows carry no time" in second
        assert "CITATIONS:" in second


def test_narrative_sentences_with_figures_no_summary_prints_are_dropped():
    # c7dbf51d T5: "18 events under AR-F6EDDB5B-DF6$, 11 under SYSTEM" over rows
    # whose summaries print neither; the path's version digits are not figures.
    rows = [{"Processes.process_path": r"C:\Edge\154.0.4258.62\setup.exe", "count": "3"}]
    slice_ = DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=1, rows=rows))])
    narrative = (
        r"Host ran C:\Edge\154.0.4258.62\setup.exe. "
        "It accounted for 18 events under SYSTEM and 11 under Mariam.\n\nNothing else ran."
    )

    kept = _drop_unsupported_sentences(narrative, slice_, "endpoint")

    assert kept == r"Host ran C:\Edge\154.0.4258.62\setup.exe. Nothing else ran."
    assert _drop_unsupported_sentences("Host ran setup.exe.", slice_, "endpoint") == "Host ran setup.exe."


def test_a_protocol_the_rows_do_not_carry_is_dropped():
    # B11, 20592fea replay: "used UDP port 5353" over rows grouped by address and port only.
    def network(row):
        return DomainSlice(domain="network", siem_sets=[("connections", ResultSet(query="q", row_count=1, rows=[row]))])

    narrative = "Traffic went to 224.0.0.251:5353. These connections used UDP port 5353."
    dest_only = network({"DestinationIp": "224.0.0.251", "DestinationPort": "5353"})
    assert _drop_unsupported_sentences(narrative, dest_only, "network") == "Traffic went to 224.0.0.251:5353."
    assert _drop_unsupported_figures(["Used UDP to port 5353 [connections#1]"], dest_only, "network") == []

    with_proto = network({"DestinationIp": "224.0.0.251", "DestinationPort": "5353", "transport": "udp"})
    assert _drop_unsupported_sentences(narrative, with_proto, "network") == narrative
