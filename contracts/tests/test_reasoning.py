"""Contract tests for the analysis-layer shapes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contracts import (
    AnalystVerdict,
    HypothesisAssessment,
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
            HypothesisAssessment(hypothesis_id="", overall_stance="refutes", confidence=0.1)
