"""Tests for context packing and prompt assembly."""

from __future__ import annotations

from datetime import UTC, datetime

from smartops.subagent_analysts.packing import estimate_tokens, pack_evidence
from smartops.subagent_analysts.prompts import build_user_turn, system_prompt
from smartops.subagent_analysts.routing import DomainSlice

from contracts import Entity, InvestigationContext, ResultSet, Scope, VtVerdict


def _scope() -> Scope:
    return Scope(
        entities=[Entity(kind="host", value="BSTOLL-L")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


class TestSystemPrompt:
    def test_domain_focus_is_embedded(self):
        assert "authentication" in system_prompt("identity").lower()
        assert "dns" in system_prompt("network").lower()
        assert "process" in system_prompt("endpoint").lower()

    def test_states_verdict_format_and_untrusted_regions(self):
        p = system_prompt("identity")
        assert "VERDICT:" in p and "CONFIDENCE:" in p and "CITATIONS:" in p
        assert "UNTRUSTED" in p

    def test_augments_metis_persona_not_replaces_it(self):
        # The official Metis system prompt must be present (safety/reasoning
        # alignment), with the domain body appended after it.
        p = system_prompt("network")
        assert "You are Metis" in p
        assert p.index("You are Metis") < p.index("network detection")


class TestUserTurn:
    def test_hypothesis_is_escaped_and_fenced(self):
        ctx = InvestigationContext(hypothesis="host was <script>owned</script>")
        turn = build_user_turn(ctx, _scope(), "(evidence)")
        assert "<hypothesis>" in turn and "</hypothesis>" in turn
        # the injected markup is escaped, so it cannot forge a fence
        assert "<script>" not in turn
        assert "&lt;script&gt;" in turn

    def test_scope_and_evidence_are_fenced(self):
        ctx = InvestigationContext(hypothesis="h")
        turn = build_user_turn(ctx, _scope(), "# auth_events#1 · rows=1")
        assert "<scope>" in turn and "host: BSTOLL-L" in turn
        assert "<evidence>" in turn and "auth_events#1" in turn


class TestPacking:
    def test_empty_slice_reports_no_evidence(self):
        text, valid_ids, truncated = pack_evidence(DomainSlice(domain="network"))
        assert "no evidence" in text.lower()
        assert valid_ids == set()
        assert truncated is False

    def test_small_slice_is_not_truncated_and_exposes_ids(self):
        slice_ = DomainSlice(
            domain="network",
            vt_verdicts=[VtVerdict(kind="domain", value="bad.com", found=True, malicious=9)],
            siem_sets=[("dns_resolutions", ResultSet(query="q", row_count=1, rows=[{"query": "bad.com"}]))],
        )
        text, valid_ids, truncated = pack_evidence(slice_)
        assert "bad.com" in text
        assert truncated is False
        assert valid_ids == {"reputation#1", "dns_resolutions#1"}

    def test_large_slice_shrinks_and_flags_truncation(self):
        big_rows = [{"user": f"u{i}", "action": "failure"} for i in range(5000)]
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=5000, rows=big_rows))],
        )
        # a tiny budget forces the row-cap ladder down
        text, valid_ids, truncated = pack_evidence(slice_, token_budget=200)
        assert truncated is True
        assert "auth_events#1" in text  # header (and thus the set) still present
        assert valid_ids == {"auth_events#1"}
        assert estimate_tokens(text) <= 400  # shrunk near the budget, not the full 5000 rows
