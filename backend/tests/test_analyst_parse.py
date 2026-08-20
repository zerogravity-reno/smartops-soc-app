"""Tests for reasoning/answer splitting and verdict parsing."""

from __future__ import annotations

import pytest
from smartops.subagent_analysts.parse import (
    VerdictParseError,
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

    def test_missing_stance_raises(self):
        with pytest.raises(VerdictParseError):
            parse_verdict("</think>I think the host looks fine, no clear format here.", domain="endpoint")

    def test_defaults_when_optional_fields_absent(self):
        v = parse_verdict("VERDICT: inconclusive", domain="endpoint")
        assert v.confidence == 0.0
        assert v.rationale == ""
        assert v.key_observations == []
        assert v.citations == []

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
