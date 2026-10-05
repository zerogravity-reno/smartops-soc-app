"""Contract tests for the analysis-layer shapes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contracts import (
    AnalystVerdict,
    DomainJudgement,
    HypothesisAssessment,
    HypothesisFindings,
    InvestigationContext,
)


class TestInvestigationContext:
    def test_hypothesis_is_required_and_non_empty(self):
        with pytest.raises(ValidationError):
            InvestigationContext(hypothesis="")

    def test_seed_event_defaults_to_none(self):
        ctx = InvestigationContext(hypothesis="host BSTOLL-L was compromised")
        assert ctx.seed_event is None

    def test_seed_event_carries_arbitrary_alert_fields(self):
        ctx = InvestigationContext(
            hypothesis="h", seed_event={"rule": "brute force", "count": 42}
        )
        assert ctx.seed_event["count"] == 42


class TestAnalystVerdict:
    def test_confidence_is_bounded_to_unit_interval(self):
        with pytest.raises(ValidationError):
            AnalystVerdict(domain="identity", stance="supports", confidence=1.5)
        with pytest.raises(ValidationError):
            AnalystVerdict(domain="identity", stance="supports", confidence=-0.1)

    def test_domain_and_stance_are_constrained(self):
        with pytest.raises(ValidationError):
            AnalystVerdict(domain="malware", stance="supports", confidence=0.5)
        with pytest.raises(ValidationError):
            AnalystVerdict(domain="identity", stance="maybe", confidence=0.5)

    def test_minimal_verdict_defaults(self):
        v = AnalystVerdict(domain="network", stance="inconclusive", confidence=0.0)
        assert v.rationale == ""
        assert v.key_observations == []
        assert v.citations == []
        assert v.reasoning_trace is None

    def test_reasoning_trace_is_carried_when_present(self):
        v = AnalystVerdict(
            domain="endpoint",
            stance="refutes",
            confidence=0.8,
            reasoning_trace="the process tree shows nothing anomalous",
        )
        assert "process tree" in v.reasoning_trace


class TestHypothesisAssessment:
    def test_rolls_up_domain_verdicts(self):
        assessment = HypothesisAssessment(
            task_id="t-1",
            hypothesis_id="h-1",
            overall_stance="supports",
            confidence=0.7,
            verdicts=[
                AnalystVerdict(domain="identity", stance="supports", confidence=0.8),
                AnalystVerdict(domain="network", stance="inconclusive", confidence=0.2),
            ],
        )
        assert assessment.schema_version == 1
        assert len(assessment.verdicts) == 2

    def test_hypothesis_id_is_required(self):
        with pytest.raises(ValidationError):
            HypothesisAssessment(
                task_id="t-1", hypothesis_id="", overall_stance="refutes", confidence=0.1
            )


class TestAssessmentJoinKey:
    def test_task_id_is_required(self):
        # Every assessment.json on disk carried hypothesis_id "cli-hypothesis" --
        # a hardcoded constant -- and no task_id, so the directory path was the
        # only link back to the report. That is what made a misfiled assessment
        # undetectable.
        with pytest.raises(ValidationError):
            HypothesisAssessment(
                hypothesis_id="h1", overall_stance="supports", confidence=0.5
            )

    def test_run_id_defaults_to_none_and_round_trips(self):
        a = HypothesisAssessment(
            task_id="cli-1", hypothesis_id="h1",
            overall_stance="supports", confidence=0.5,
        )
        assert a.run_id is None
        stamped = a.model_copy(update={"run_id": "20260101T000000000"})
        back = HypothesisAssessment.model_validate_json(stamped.model_dump_json())
        assert back.task_id == "cli-1"
        assert back.run_id == "20260101T000000000"


class TestTheAnalystPayloadIsAProjectionNotTheRecord:
    """`findings.json` is the audit trail; `analyst-payload.json` is the message.

    Mohammed's call on 2026-09-01: the Analyst Agent receives prose and
    observations, and nothing else. The record keeps citations, exhibits and the
    retrieval summary.

    The reason is size, and it is not marginal. On that day's live run the record
    was 42,200 characters, 73% of it exhibits -- the 584 raw rows this tier exists
    to compress into prose. Sending them on undoes the compression.
    """

    @staticmethod
    def _findings():
        return HypothesisFindings(
            task_id="t1",
            run_id="r1",
            hypothesis_id="h1",
            hypothesis="something was compromised",
            findings=[
                DomainJudgement(
                    domain="network",
                    narrative="six connections to one address.",
                    observations=["six connections [connections#4]"],
                    citations=["connections#4"],
                )
            ],
        )

    def test_it_carries_the_prose_and_the_observations(self):
        payload = self._findings().for_analyst()
        assert payload.task_id == "t1"
        assert payload.run_id == "r1"
        assert payload.hypothesis_id == "h1"
        assert payload.hypothesis == "something was compromised"
        assert payload.findings[0].domain == "network"
        assert payload.findings[0].narrative == "six connections to one address."
        assert payload.findings[0].observations == ["six connections [connections#4]"]

    def test_a_domain_narrative_carries_nothing_else(self):
        """The field set is pinned deliberately.

        A field added to `DomainJudgement` should NOT start crossing the boundary
        because someone edited the projection in sympathy with the model. This
        test failing is the intended prompt to decide, not a chore to silence.
        """
        fields = set(type(self._findings().for_analyst().findings[0]).model_fields)
        assert fields == {"domain", "narrative", "observations"}

    def test_the_envelope_carries_no_retrieval_summary(self):
        """What this costs, recorded where it will be found.

        `retrieval` is the only signal separating "we looked and found nothing"
        from "we never looked" -- both arrive as an empty narrative with no
        observations. With Splunk unreachable on 2026-09-01 that is exactly what
        two of three domains produced. Accepted with the trade-off stated; the
        distinction survives in `findings.json`.
        """
        assert "retrieval" not in type(self._findings().for_analyst()).model_fields

    def test_the_record_is_untouched_by_the_projection(self):
        record = self._findings()
        record.for_analyst()
        assert record.findings[0].citations == ["connections#4"]
        assert record.retrieval is None
        assert record.schema_version == 2

    def test_the_projection_is_much_smaller_than_the_record(self):
        record = self._findings()
        assert len(record.for_analyst().model_dump_json()) < len(record.model_dump_json())

    def test_its_version_line_is_its_own_and_starts_at_one(self):
        """1 beside the record's 2 is not staleness, and the field says so.

        Both files land in the same run directory. A reader seeing
        `schema_version: 2` in `findings.json` and `1` here will reasonably ask
        which is out of date; neither is. `AnalystPayload` is a new contract, not
        a successor, and `HypothesisFindings` is not superseded by it.
        """
        record = self._findings()
        assert record.schema_version == 2
        assert record.for_analyst().schema_version == 1

        from contracts import AnalystPayload

        described = AnalystPayload.model_fields["schema_version"].description or ""
        assert "independently" in described, (
            "the field most likely to be misread must explain itself in the "
            "published schema, not only in the class docstring"
        )


class TestTheAnalystPayloadBatch:
    """One message per task FILE, not per hypothesis.

    A file arrives with several hypotheses about one alert and the Analyst Agent
    weighs them against each other; three separate payloads leave that grouping
    for the recipient to infer from nothing in the payloads themselves.
    """

    @staticmethod
    def _payload(hypothesis_id="H1", task_id="T1"):
        from contracts import AnalystPayload, DomainNarrative

        return AnalystPayload(
            task_id=task_id,
            run_id="20260902T120611157",
            hypothesis_id=hypothesis_id,
            hypothesis="did bostoll mine on BSTOLL-L?",
            findings=[
                DomainNarrative(domain=d, narrative=f"{d} prose", observations=[f"{d} [x#1]"])
                for d in ("identity", "network", "endpoint")
            ],
        )

    def test_it_carries_every_hypothesis_in_file_order(self):
        from contracts import AnalystPayloadBatch

        batch = AnalystPayloadBatch(
            batch_id="batch-20260902T121500",
            payloads=[self._payload("H1", "T1"), self._payload("H2", "T2"), self._payload("H3", "T3")],
        )

        assert [p.hypothesis_id for p in batch.payloads] == ["H1", "H2", "H3"]
        assert batch.schema_version == 1

    def test_members_stay_independently_resolvable(self):
        """The envelope adds grouping and takes nothing away: each member keeps
        its own ids, so it still joins back to the run directory that made it."""
        from contracts import AnalystPayloadBatch

        batch = AnalystPayloadBatch(batch_id="b1", payloads=[self._payload("H2", "T2")])
        member = batch.payloads[0]

        assert (member.task_id, member.hypothesis_id, member.run_id) == (
            "T2", "H2", "20260902T120611157",
        )
        assert member.schema_version == 1, "AnalystPayload's own version is untouched"

    def test_it_does_not_merge_summarise_or_reconcile(self):
        """The envelope must not grow a field that compares the hypotheses.

        Weighing them against each other is the Analyst Agent's job, and doing
        any of it here would be this tier forming the judgement it exists not to
        form -- the same reason `HypothesisFindings` has no `overall_stance`.
        """
        from contracts import AnalystPayloadBatch

        assert set(AnalystPayloadBatch.model_fields) == {
            "schema_version", "batch_id", "created_at", "payloads"
        }

    def test_a_duplicate_hypothesis_in_one_batch_is_refused(self):
        """The id is the join key, so two members sharing one are
        indistinguishable to the recipient. `TaskInputFile` already refuses this
        at load; this covers a batch assembled by hand or by a future producer."""
        import pytest
        from pydantic import ValidationError

        from contracts import AnalystPayloadBatch

        with pytest.raises(ValidationError, match="unique within a batch"):
            AnalystPayloadBatch(
                batch_id="b1", payloads=[self._payload("H1", "T1"), self._payload("H1", "T2")]
            )

    def test_an_empty_batch_is_refused(self):
        import pytest
        from pydantic import ValidationError

        from contracts import AnalystPayloadBatch

        with pytest.raises(ValidationError):
            AnalystPayloadBatch(batch_id="b1", payloads=[])

    def test_created_at_is_timezone_aware(self):
        from contracts import AnalystPayloadBatch

        batch = AnalystPayloadBatch(batch_id="b1", payloads=[self._payload()])

        assert batch.created_at.tzinfo is not None
