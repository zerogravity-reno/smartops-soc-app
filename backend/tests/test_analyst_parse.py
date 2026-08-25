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

    def test_a_rationale_sentence_ending_in_a_colon_is_not_a_label(self):
        # The terminator used to be a generic uppercase run (`[A-Z][A-Z ]+:`) under
        # IGNORECASE, so any prose line ending in a colon looked like the next
        # label and truncated the rationale. Only the five real labels end it.
        out = (
            "</think>VERDICT: supports\n"
            "RATIONALE: The host beaconed to a known C2.\n"
            "Note the following: the interval was fixed at 60s, machine-like.\n"
            "CITATIONS: connections#1"
        )
        v = parse_verdict(out, domain="network")
        assert "machine-like" in v.rationale
        assert "CITATIONS" not in v.rationale  # a real label still terminates it

    def test_rationale_still_stops_at_each_real_label(self):
        # Guards against over-correcting: bounding the terminator must not stop it
        # terminating, in either the bare or the emphasised spelling.
        for label in ("OBSERVATIONS", "CITATIONS", "CONFIDENCE", "VERDICT"):
            for line in (f"{label}: x", f"**{label}:** x"):
                out = f"</think>VERDICT: supports\nRATIONALE: kept.\n{line}"
                assert parse_verdict(out, domain="identity").rationale == "kept."


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

    def test_an_observation_containing_a_colon_does_not_drop_the_ones_after_it(self):
        # Worse here than in a rationale: the OBSERVATIONS capture ended at the
        # first prose colon, so every LATER observation vanished -- and with them
        # the inline citations `_finalize_finding` unions into `citations`.
        #
        # The line has to be UN-bulleted to trigger it: a leading `-` is outside
        # the terminator's `[*_`\s]*` prefix class and blocks the match by
        # accident. The 8B model does not reliably bullet every line, so relying
        # on that is relying on a typo.
        out = (
            "</think>OBSERVATIONS:\n"
            "- 14 failed logons in 3 minutes [auth_events#1]\n"
            "The pattern was: burst, pause, burst [auth_events#1]\n"
            "- then a success from the same source [auth_events#2]\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert len(f.observations) == 3
        assert "auth_events#2" in f.observations[2]

    def test_finding_observations_still_stop_at_each_real_label(self):
        for label in ("CONFIDENCE", "RATIONALE", "CITATIONS", "VERDICT"):
            for line in (f"{label}: x", f"**{label}:** x"):
                out = f"</think>OBSERVATIONS:\n- kept [auth_events#1]\n{line}"
                assert parse_finding(out, domain="identity").observations == [
                    "kept [auth_events#1]"
                ]


class TestFindingDisposition:
    """The blind analyst judges its evidence -- blind does not mean silent."""

    def _finding(self, disposition_line: str):
        out = (
            "</think>OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            f"{disposition_line}\n"
            "CONFIDENCE: 0.6\nCITATIONS: auth_events#1"
        )
        return parse_finding(out, domain="identity")

    def test_each_disposition_parses(self):
        for word in ("benign", "suspicious", "malicious", "inconclusive"):
            assert self._finding(f"DISPOSITION: {word}").disposition == word

    def test_a_missing_disposition_is_inconclusive_not_benign(self):
        out = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCITATIONS: auth_events#1"
        assert parse_finding(out, domain="identity").disposition == "inconclusive"

    def test_a_missing_disposition_does_not_discard_the_observations(self):
        """Laxer than parse_verdict on purpose: the grounded rows are still worth keeping."""
        out = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCITATIONS: auth_events#1"
        assert parse_finding(out, domain="identity").observations == ["x [auth_events#1]"]

    def test_a_hedge_that_mentions_another_disposition_reads_the_leading_word(self):
        # Same failure `_normalise_stance` guards against: a substring-only scan
        # would see "suspicious" here and mis-record a judgement the model
        # explicitly declined to make.
        f = self._finding("DISPOSITION: inconclusive, though some rows look suspicious")
        assert f.disposition == "inconclusive"

    def test_markdown_emphasis_does_not_break_it(self):
        assert self._finding("**DISPOSITION:** malicious").disposition == "malicious"

    def test_an_unrecognisable_disposition_falls_back_to_inconclusive(self):
        assert self._finding("DISPOSITION: probably fine?").disposition == "inconclusive"

    def test_disposition_terminates_a_preceding_rationale(self):
        # DISPOSITION joined `_LABEL`, so it must actually end a field.
        out = (
            "</think>OBSERVATIONS:\n- x [auth_events#1]\n"
            "RATIONALE: kept.\nDISPOSITION: benign\nCITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert f.rationale == "kept."
        assert f.disposition == "benign"
