"""Tests for reasoning/answer splitting and verdict parsing."""

from __future__ import annotations

import pytest
from smartops.subagent_analysts.parse import (
    FindingParseError,
    VerdictParseError,
    parse_finding,
    parse_verdict,
    split_reasoning,
)

_GOOD = """the failures cluster on one account from one source, consistent with a \
brute force that then succeeded.
</think>
VERDICT: supports
CONFIDENCE: 0.82
RATIONALE: 14 failures then a success for bostoll from a single external IP.
OBSERVATIONS:
- 14 failed logons in 3 minutes [auth_events#1]
- immediately followed by a success [auth_events#1]
CITATIONS: auth_events#1"""


class TestSplitReasoning:
    def test_splits_on_closing_think(self):
        reasoning, answer = split_reasoning("<think>secret chain</think>VERDICT: refutes")
        assert reasoning == "secret chain"
        assert answer.startswith("VERDICT: refutes")

    def test_no_think_tag_treats_all_as_answer(self):
        reasoning, answer = split_reasoning("VERDICT: inconclusive")
        assert reasoning is None
        assert answer == "VERDICT: inconclusive"


class TestParseVerdict:
    def test_parses_rich_verdict(self):
        v = parse_verdict(_GOOD, domain="identity")
        assert v.stance == "supports"
        assert v.confidence == 0.82
        assert "bostoll" in v.rationale
        assert len(v.key_observations) == 2
        assert v.citations == ["auth_events#1"]
        assert v.reasoning_trace and "brute force" in v.reasoning_trace

    def test_confidence_is_clamped(self):
        out = "</think>VERDICT: refutes\nCONFIDENCE: 3.0"
        assert parse_verdict(out, domain="network").confidence == 1.0

    def test_stance_synonyms_normalise(self):
        assert parse_verdict("VERDICT: Refuted", domain="network").stance == "refutes"
        assert parse_verdict("VERDICT: insufficient evidence", domain="network").stance == "inconclusive"

    def test_a_hedge_that_uses_the_other_stances_word_is_not_misread(self):
        # `_normalise_stance` used to scan for "support" before "refut" or
        # "inconclusive", anywhere in the line -- so a verbose 8B-model line
        # that leads with the real stance but mentions the *other* word in
        # passing got misclassified as the wrong stance entirely.
        out = "VERDICT: inconclusive - insufficient support for compromise"
        assert parse_verdict(out, domain="identity").stance == "inconclusive"

        out2 = "VERDICT: refutes, there is no support for the hypothesis"
        assert parse_verdict(out2, domain="identity").stance == "refutes"

    def test_missing_stance_raises(self):
        with pytest.raises(VerdictParseError):
            parse_verdict("</think>I think the host looks fine, no clear format here.", domain="endpoint")

    def test_defaults_when_optional_fields_absent(self):
        v = parse_verdict("VERDICT: inconclusive", domain="endpoint")
        assert v.confidence == 0.0
        assert v.rationale == ""
        assert v.key_observations == []
        assert v.citations == []

    def test_confidence_without_a_value_does_not_grab_a_digit_from_a_citation(self):
        # `\D*` crosses newlines, so with no numeric confidence given it used
        # to walk past every intervening field and lock onto the "1" in
        # `auth_events#1`, manufacturing confidence=1.0 from a reply that gave
        # none.
        out = (
            "</think>VERDICT: inconclusive\nCONFIDENCE: unclear\n"
            "RATIONALE: no clear pattern.\nCITATIONS: auth_events#1"
        )
        assert parse_verdict(out, domain="identity").confidence == 0.0

    def test_markdown_bolded_block_parses(self):
        # Real observed 8B output: the whole verdict block wrapped in ** emphasis.
        out = (
            "prose... the hypothesis is **supported**.\n</think>\n"
            "**VERDICT:** supports  \n"
            "**CONFIDENCE:** 0.7  \n"
            "**RATIONALE:** Evidence shows BSTOLL-L ran chrome.exe referencing the "
            "CoinHive library.  \n"
            "**OBSERVATIONS:**  \n"
            "- BSTOLL-L ran chrome.exe [processes#1]  \n"
            "**CITATIONS:** processes#1"
        )
        v = parse_verdict(out, domain="endpoint")
        assert v.stance == "supports"
        assert v.confidence == 0.7  # not lost to the ** around the number
        assert v.citations == ["processes#1"]  # no ** prefix
        assert "CoinHive" in v.rationale
        assert "OBSERVATIONS" not in v.rationale  # rationale stops at the next label
        assert v.key_observations == ["BSTOLL-L ran chrome.exe [processes#1]"]


_GOOD_FINDING = """the logons cluster around one account with no failures preceding \
success, and no process or network rows are present in this slice.
</think>
OBSERVATIONS:
- one clean logon for bostoll from 10.0.1.50, no prior failures [auth_events#1]
CONFIDENCE: 0.65
RATIONALE: A single successful logon with no surrounding anomaly pattern.
CITATIONS: auth_events#1"""


class TestParseFinding:
    def test_parses_rich_finding(self):
        f = parse_finding(_GOOD_FINDING, domain="identity")
        assert f.domain == "identity"
        assert f.confidence == 0.65
        assert "logon" in f.rationale
        assert len(f.observations) == 1
        assert f.citations == ["auth_events#1"]
        assert f.reasoning_trace and "cluster" in f.reasoning_trace

    def test_confidence_is_clamped(self):
        out = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCONFIDENCE: 3.0\nCITATIONS: auth_events#1"
        assert parse_finding(out, domain="network").confidence == 1.0

    def test_missing_observations_and_citations_raises(self):
        with pytest.raises(FindingParseError):
            parse_finding("</think>I looked at the evidence and it seems fine.", domain="endpoint")

    def test_citations_alone_are_enough_to_parse(self):
        # No OBSERVATIONS block, but a CITATIONS line is still a recognisable finding.
        out = "</think>RATIONALE: nothing notable.\nCITATIONS: auth_events#1"
        f = parse_finding(out, domain="identity")
        assert f.citations == ["auth_events#1"]
        assert f.observations == []

    def test_defaults_when_optional_fields_absent(self):
        out = "</think>OBSERVATIONS:\n- x [auth_events#1]"
        f = parse_finding(out, domain="endpoint")
        assert f.confidence == 0.0
        assert f.rationale == ""
        assert f.citations == []

    def test_confidence_without_a_value_does_not_grab_a_digit_from_a_citation(self):
        out = (
            "</think>OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "CONFIDENCE: unclear\nCITATIONS: auth_events#1"
        )
        assert parse_finding(out, domain="identity").confidence == 0.0

    def test_markdown_bolded_block_parses(self):
        out = (
            "prose...\n</think>\n"
            "**OBSERVATIONS:**  \n"
            "- BSTOLL-L ran chrome.exe [processes#1]  \n"
            "**CONFIDENCE:** 0.7  \n"
            "**RATIONALE:** Evidence shows chrome.exe referencing the CoinHive library.  \n"
            "**CITATIONS:** processes#1"
        )
        f = parse_finding(out, domain="endpoint")
        assert f.confidence == 0.7
        assert f.citations == ["processes#1"]
        assert "CoinHive" in f.rationale
        assert f.observations == ["BSTOLL-L ran chrome.exe [processes#1]"]
