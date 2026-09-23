"""Tests for reasoning/answer splitting, verdict parsing and finding parsing.

Two parsers, two arms. `parse_verdict` is the hypothesis-SHOWN arm (`shown.py`,
the A/B harness) and still reads VERDICT/CONFIDENCE/RATIONALE. `parse_finding` is
the production, hypothesis-BLIND path, which since 2026-08-31 forms no verdict at
all and reads NARRATIVE/OBSERVATIONS/CITATIONS.
"""

from __future__ import annotations

import pytest
from smartops.subagent_analysts.parse import (
    _expand_bare_ids,
    FindingParseError,
    parse_finding,
    split_reasoning,
)
from smartops.subagent_analysts.shown import VerdictParseError, parse_verdict

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
        # label and truncated the rationale. Only the real labels end it.
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
        # terminating, in either the bare or the emphasised spelling. NARRATIVE is
        # in the list although this arm's own prompt never emits it -- `_LABEL` is
        # shared, and a label that stops terminating on one arm stops terminating
        # on both.
        for label in ("OBSERVATIONS", "CITATIONS", "CONFIDENCE", "VERDICT", "NARRATIVE"):
            for line in (f"{label}: x", f"**{label}:** x"):
                out = f"</think>VERDICT: supports\nRATIONALE: kept.\n{line}"
                assert parse_verdict(out, domain="identity").rationale == "kept."


_GOOD_FINDING = """the logons cluster around one account with no failures preceding \
success, and no process or network rows are present in this slice.
</think>
NARRATIVE: auth_events#1 shows bostoll logged on successfully once from 10.0.1.50 \
at 09:14, with no failed logons before it. No process or network rows were in this slice.
OBSERVATIONS:
- one clean logon for bostoll from 10.0.1.50, no prior failures [auth_events#1]
CITATIONS: auth_events#1"""


class TestParseFinding:
    def test_parses_rich_finding(self):
        f = parse_finding(_GOOD_FINDING, domain="identity")
        assert f.domain == "identity"
        assert "10.0.1.50" in f.narrative
        assert "OBSERVATIONS" not in f.narrative  # the narrative stops at the label
        assert len(f.observations) == 1
        assert f.citations == ["auth_events#1"]
        assert f.reasoning_trace and "cluster" in f.reasoning_trace

    def test_the_finding_carries_no_verdict(self):
        """The whole point of the 2026-08-31 change, pinned at the parser.

        A `DomainFinding` used to carry a `disposition` and a `confidence`, and
        `parse_finding` defaulted the disposition to `inconclusive` when the model
        gave none -- so the 2026-08-30 run put a verdict no model had formed onto
        the wire. Both fields are gone from the contract; this asserts the parser
        cannot bring them back by any route.
        """
        f = parse_finding(_GOOD_FINDING, domain="identity")
        assert not hasattr(f, "disposition")
        assert not hasattr(f, "confidence")

    def test_a_disposition_line_the_model_still_emits_is_ignored_not_absorbed(self):
        """`DISPOSITION` stays in `_LABEL` although no prompt asks for it.

        An 8B model that has learned the habit, or a stored generation replayed
        from before the change, still emits the line. Keeping the label means it
        ENDS the narrative instead of being swallowed into it -- the same silent
        truncation `_LABEL` exists to prevent, running the other way.
        """
        out = (
            "</think>NARRATIVE: one clean logon for bostoll.\n"
            "DISPOSITION: benign\n"
            "OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert f.narrative == "one clean logon for bostoll."
        assert "DISPOSITION" not in f.narrative
        assert f.observations == ["one clean logon [auth_events#1]"]

    def test_missing_observations_and_citations_raises(self):
        with pytest.raises(FindingParseError):
            parse_finding("</think>I looked at the evidence and it seems fine.", domain="endpoint")

    def test_citations_alone_are_enough_to_parse(self):
        # No OBSERVATIONS block, but a NARRATIVE and a CITATIONS line are still a
        # recognisable finding. Still an OR between those two, deliberately laxer
        # than `parse_verdict`.
        out = "</think>NARRATIVE: nothing notable in the rows.\nCITATIONS: auth_events#1"
        f = parse_finding(out, domain="identity")
        assert f.citations == ["auth_events#1"]
        assert f.observations == []

    def test_observations_alone_are_enough_to_parse(self):
        out = "</think>NARRATIVE: one logon.\nOBSERVATIONS:\n- x [auth_events#1]"
        f = parse_finding(out, domain="endpoint")
        assert f.observations == ["x [auth_events#1]"]
        assert f.citations == []

    def test_markdown_bolded_block_parses(self):
        out = (
            "prose...\n</think>\n"
            "**NARRATIVE:** BSTOLL-L ran chrome.exe, which referenced the CoinHive "
            "library.  \n"
            "**OBSERVATIONS:**  \n"
            "- BSTOLL-L ran chrome.exe [processes#1]  \n"
            "**CITATIONS:** processes#1"
        )
        f = parse_finding(out, domain="endpoint")
        assert "CoinHive" in f.narrative
        assert f.citations == ["processes#1"]
        assert f.observations == ["BSTOLL-L ran chrome.exe [processes#1]"]

    def test_an_observation_containing_a_colon_does_not_drop_the_ones_after_it(self):
        # Worse here than in a narrative: the OBSERVATIONS capture ended at the
        # first prose colon, so every LATER observation vanished -- and with them
        # the inline citations `_finalize_finding` unions into `citations`.
        #
        # The line has to be UN-bulleted to trigger it: a leading `-` is outside
        # the terminator's `[*_`\s]*` prefix class and blocks the match by
        # accident. The 8B model does not reliably bullet every line, so relying
        # on that is relying on a typo.
        out = (
            "</think>NARRATIVE: a burst of failures then a success.\n"
            "OBSERVATIONS:\n"
            "- 14 failed logons in 3 minutes [auth_events#1]\n"
            "The pattern was: burst, pause, burst [auth_events#1]\n"
            "- then a success from the same source [auth_events#2]\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert len(f.observations) == 3
        assert "auth_events#2" in f.observations[2]

    def test_finding_observations_still_stop_at_each_real_label(self):
        for label in ("NARRATIVE", "CONFIDENCE", "RATIONALE", "CITATIONS", "VERDICT"):
            for line in (f"{label}: x", f"**{label}:** x"):
                out = (
                    "</think>NARRATIVE: a line.\n"
                    f"OBSERVATIONS:\n- kept [auth_events#1]\n{line}"
                )
                assert parse_finding(out, domain="identity").observations == [
                    "kept [auth_events#1]"
                ]


class TestTheNarrativeIsRequired:
    """A missing NARRATIVE raises rather than defaulting to `""`.

    The narrative is what this tier produces. `parse_finding` used to default an
    absent `DISPOSITION` to `inconclusive`, which on the 2026-08-30 live run put
    a verdict no model had formed onto the wire; a silent `""` here would put a
    silence no model had produced there instead, and `HypothesisFindings` cannot
    tell that apart from a domain that genuinely had nothing to say.

    Raising is not discarding: `analyze._invoke_with_one_reask` turns this into
    one bounded re-ask whose last instruction is the required block itself.
    """

    def test_observations_and_citations_without_a_narrative_raise(self):
        out = (
            "</think>OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        with pytest.raises(FindingParseError, match="NARRATIVE"):
            parse_finding(out, domain="identity")

    def test_an_empty_narrative_line_raises_rather_than_capturing_the_next_label(self):
        """The one hole `_LABEL` cannot close on its own.

        Every terminator is anchored to a NEWLINE, so a label that is the very
        first thing after `NARRATIVE:` is not terminated but captured: the `\\s*`
        after the colon gives the newline back and `OBSERVATIONS:\\n- x` becomes
        the narrative. Without `_LABEL_AT_START_RE` this parses "successfully"
        and ships the label block as prose.
        """
        out = (
            "</think>NARRATIVE:\nOBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        with pytest.raises(FindingParseError, match="NARRATIVE"):
            parse_finding(out, domain="identity")

    def test_a_whitespace_only_narrative_raises(self):
        out = (
            "</think>NARRATIVE:    \nOBSERVATIONS:\n- x [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        with pytest.raises(FindingParseError, match="NARRATIVE"):
            parse_finding(out, domain="identity")


class TestTheNarrativeLabelTerminates:
    """`NARRATIVE` had to JOIN `_LABEL`, and the failure mode is silent.

    `parse.py`'s own comment on `_LABEL` says a label that appears in a footer
    but not in the set "silently stops terminating" -- nothing raises, the
    preceding capture simply runs on through it. `prompts._NARRATIVE_ANSWER_BLOCK`
    emits `NARRATIVE:`, so without it in `_LABEL` an OBSERVATIONS capture that
    reaches a NARRATIVE line swallows the whole narrative as an extra
    observation, and that observation is then handed to the grounding gate, the
    operator, and the Analyst Agent.

    `test_the_observations_capture_stops_at_a_narrative_label` is the one that
    FAILS if `NARRATIVE` is dropped from `_LABEL`; the others pin the
    already-working direction so the pair reads as a whole.
    """

    def test_the_observations_capture_stops_at_a_narrative_label(self):
        out = (
            "</think>OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "NARRATIVE: bostoll logged on once from 10.0.1.50 at 09:14.\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert f.observations == ["one clean logon [auth_events#1]"]
        assert f.narrative == "bostoll logged on once from 10.0.1.50 at 09:14."

    def test_a_heading_spelled_narrative_label_terminates_too(self):
        # Observed on blind draw #4 of the 2026-08-25 re-measurement: the model
        # writes the label as a markdown heading. `#` is handled in
        # `_LABEL_PREFIX`, never in `_strip_md` -- header ids need it.
        out = (
            "</think>OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "### NARRATIVE: bostoll logged on once.\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert f.observations == ["one clean logon [auth_events#1]"]
        assert f.narrative == "bostoll logged on once."

    def test_the_narrative_capture_stops_at_the_observations_label(self):
        out = (
            "</think>NARRATIVE: bostoll logged on once from 10.0.1.50 at 09:14.\n"
            "OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert f.narrative == "bostoll logged on once from 10.0.1.50 at 09:14."
        assert f.observations == ["one clean logon [auth_events#1]"]

    def test_a_narrative_sentence_ending_in_a_colon_is_not_a_label(self):
        out = (
            "</think>NARRATIVE: three hosts appear in the rows.\n"
            "They are, in order: BSTOLL-L, DC01 and FS02.\n"
            "OBSERVATIONS:\n- three hosts [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert "FS02" in f.narrative
        assert "OBSERVATIONS" not in f.narrative


_GOOD_FINDING_NARRATIVE_FIRST = """the logons cluster around one account with no \
failures preceding success, and no process or network rows are present in this slice.
</think>
NARRATIVE: bostoll logged on successfully once from 10.0.1.50 at 09:14.
OBSERVATIONS:
- one clean logon for bostoll from 10.0.1.50, no prior failures [auth_events#1]
CITATIONS: auth_events#1"""


class TestParseFindingIsOrderIndependent:
    """`_NARRATIVE_RE` and `_FINDING_OBSERVATIONS_RE` both terminate at the next
    KNOWN label (`_LABEL`) rather than assuming a fixed position relative to one
    another, so both field orders must parse to the same result.

    `_NARRATIVE_ANSWER_BLOCK` asks for NARRATIVE first, so that a model which
    over-produces observations does not lose the narrative to `max_gen_len`
    truncation. The other order still has to work: a stored artifact or an
    in-flight reply may use it, and an 8B model reorders the block anyway. These
    two tests are what make the claim true rather than assumed (see
    docs/sessions/handover_2026-08-30_splunk-back-answer-sheet-and-siem-trace.md).
    """

    _EXPECTED_NARRATIVE = "bostoll logged on successfully once from 10.0.1.50 at 09:14."
    _EXPECTED_OBSERVATIONS = [
        "one clean logon for bostoll from 10.0.1.50, no prior failures [auth_events#1]"
    ]

    def test_narrative_first_round_trips(self):
        f = parse_finding(_GOOD_FINDING_NARRATIVE_FIRST, domain="identity")

        assert f.narrative == self._EXPECTED_NARRATIVE
        assert f.observations == self._EXPECTED_OBSERVATIONS
        assert f.citations == ["auth_events#1"]

    def test_observations_first_still_round_trips(self):
        # Same fixture with NARRATIVE moved after OBSERVATIONS, so the two orders
        # are compared apples-to-apples.
        out = """the logons cluster around one account with no failures preceding \
success, and no process or network rows are present in this slice.
</think>
OBSERVATIONS:
- one clean logon for bostoll from 10.0.1.50, no prior failures [auth_events#1]
NARRATIVE: bostoll logged on successfully once from 10.0.1.50 at 09:14.
CITATIONS: auth_events#1"""
        f = parse_finding(out, domain="identity")

        assert f.narrative == self._EXPECTED_NARRATIVE
        assert f.observations == self._EXPECTED_OBSERVATIONS
        assert f.citations == ["auth_events#1"]


class TestMarkdownHeadingLabels:
    """A label written as a markdown heading must still be a label.

    Observed on blind draw #4 of the 2026-08-25 re-measurement: the model wrote
    `### CONFIDENCE: 0.85`, which neither terminated the OBSERVATIONS block nor
    registered as a field, so the observation list ended -- literally -- with the
    label line. It then travels to the Analyst Agent as if it were a finding.

    The fix is in the terminator's prefix class, NOT in `_strip_md`: `#` is
    load-bearing inside header ids (`auth_events#1`), so stripping it globally
    would destroy every citation in the file.
    """

    def test_a_heading_label_terminates_finding_observations(self):
        out = (
            "</think>NARRATIVE: one clean logon.\n"
            "OBSERVATIONS:\n- one clean logon [auth_events#1]\n"
            "### CITATIONS: auth_events#1"
        )
        f = parse_finding(out, domain="identity")
        assert f.observations == ["one clean logon [auth_events#1]"]
        assert f.citations == ["auth_events#1"]

    def test_a_heading_label_terminates_a_rationale(self):
        out = (
            "</think>VERDICT: supports\nRATIONALE: kept.\n"
            "### CITATIONS: auth_events#1"
        )
        assert parse_verdict(out, domain="identity").rationale == "kept."

    def test_a_heading_label_terminates_verdict_observations(self):
        out = (
            "</think>VERDICT: supports\nOBSERVATIONS:\n- x [auth_events#1]\n"
            "### CITATIONS: auth_events#1"
        )
        v = parse_verdict(out, domain="identity")
        assert v.key_observations == ["x [auth_events#1]"]
        assert v.citations == ["auth_events#1"]

    def test_a_hash_inside_a_header_id_is_untouched(self):
        """The reason this is not fixed in `_strip_md`."""
        out = (
            "</think>NARRATIVE: two sets of rows were present.\n"
            "OBSERVATIONS:\n- rows seen [auth_events#1], [processes#12]\n"
            "CITATIONS: auth_events#1, processes#12"
        )
        f = parse_finding(out, domain="identity")
        assert f.citations == ["auth_events#1", "processes#12"]
        assert "auth_events#1" in f.observations[0]


class TestCitationSeparators:
    """A separator no header id can contain is safe to be generous about.

    `_parse_citations` split on commas only, so `CITATIONS: auth_events#1
    auth_events#2` -- a model following the *spirit* of the prompt and missing
    its punctuation -- became the single token `auth_events#1 auth_events#2`,
    matched nothing in `valid_citation_ids()`, and had its whole finding stripped
    of citations and marked ungrounded by `_finalize_finding`. Flagged as
    unscheduled in the 2026-08-24 review.
    """

    @staticmethod
    def _cites(line: str) -> list[str]:
        return parse_finding(
            f"</think>NARRATIVE: rows were present.\n"
            f"OBSERVATIONS:\n- x [auth_events#1]\n{line}",
            domain="identity",
        ).citations

    def test_comma_separated(self):
        assert self._cites("CITATIONS: auth_events#1, auth_events#2") == [
            "auth_events#1",
            "auth_events#2",
        ]

    def test_space_separated(self):
        assert self._cites("CITATIONS: auth_events#1 auth_events#2") == [
            "auth_events#1",
            "auth_events#2",
        ]

    def test_mixed_and_bracketed(self):
        assert self._cites("CITATIONS: [auth_events#1], auth_events#2  auth_events#3") == [
            "auth_events#1",
            "auth_events#2",
            "auth_events#3",
        ]

    def test_a_single_citation_is_unaffected(self):
        assert self._cites("CITATIONS: auth_events#1") == ["auth_events#1"]


class TestBareHashContinuationsAreRecovered:
    """T12. `auth_events#6, #9, #11` is three citations, not one.

    `analyze._OBSERVATION_CITE_RE` matches `[A-Za-z_]+#\\d+`, so a bare `#N` matched
    nothing and was silently discarded. On the 2026-09-05 replay the identity
    finding cited `(auth_events#6, #9, #11, #13)` and three of its four sets never
    reached the grounding gate. Bare `#N` was the dominant style in two domains of
    three that run.

    Expanded rather than rejected, for the reason `_parse_citations` already
    records one function above: the model's only mistake is punctuation, and the
    penalty was its whole read of the evidence.
    """

    def test_a_continuation_inherits_the_preceding_category(self):
        assert _expand_bare_ids("logins (auth_events#6, #9, #11, #13).") == (
            "logins (auth_events#6, auth_events#9, auth_events#11, auth_events#13)."
        )

    def test_bracketed_lists_expand_too(self):
        assert _expand_bare_ids("traffic [connections#4, #10, #13]") == (
            "traffic [connections#4, connections#10, connections#13]"
        )

    def test_the_nearest_preceding_category_wins(self):
        assert _expand_bare_ids("auth_events#1 then #2 then processes#3 then #4") == (
            "auth_events#1 then auth_events#2 then processes#3 then processes#4"
        )

    def test_a_continuation_with_nothing_to_inherit_is_untouched(self):
        # Inventing a category here would manufacture a citation the model never
        # wrote, which is the failure this whole tier exists to prevent.
        assert _expand_bare_ids("no prefix here #7 and #8") == "no prefix here #7 and #8"

    def test_text_without_ids_is_returned_unchanged(self):
        assert _expand_bare_ids("no hashes at all") == "no hashes at all"

    def test_the_expansion_reaches_the_parsed_finding(self):
        out = (
            "</think>NARRATIVE: auth_events#6 and the others show repeated loopback "
            "logons for two accounts against one host, with no failures among them.\n"
            "OBSERVATIONS:\n"
            "- repeated logons for two accounts (auth_events#6, #9, #11)\n"
            "CITATIONS: auth_events#6, #9, #11"
        )
        f = parse_finding(out, domain="identity")
        assert f.citations == ["auth_events#6", "auth_events#9", "auth_events#11"]
        assert "auth_events#9" in f.observations[0]


class TestTheParserRejectsWhatDestroysGrounding:
    """T13. Two failures, both seen in the 2026-09-02 runs."""

    def test_a_placeholder_observation_is_rejected(self):
        # consent/identity's ONLY observation was "None applicable." -- a sentence
        # where a checkable claim should be, reading downstream as though the
        # domain had been examined and dismissed.
        out = (
            "</think>NARRATIVE: auth_events#1 returned no rows, so no accounts, "
            "addresses or actions were recorded anywhere in the window given.\n"
            "OBSERVATIONS:\n- None applicable.\n"
            "CITATIONS: auth_events#1"
        )
        with pytest.raises(FindingParseError, match="placeholder observation"):
            parse_finding(out, domain="identity")

    def test_observations_that_all_cite_nothing_are_rejected(self):
        out = (
            "</think>NARRATIVE: auth_events#1 shows a burst of loopback logons for "
            "one account, and nothing else in this slice carried any rows at all.\n"
            "OBSERVATIONS:\n- something happened\n- something else happened\n"
            "CITATIONS: auth_events#1"
        )
        with pytest.raises(FindingParseError, match="cited no evidence in any"):
            parse_finding(out, domain="identity")

    def test_one_uncited_line_among_cited_ones_is_not_a_parse_error(self):
        """Deliberately NOT raised here.

        `_FINDING_OBSERVATIONS_RE` sweeps un-bulleted prose inside the block up as
        an observation, so per-line raising rejects a sound reply over a formatting
        artifact -- costing a re-ask and, on a second failure, the domain. The
        single uncited line is dropped downstream by
        `analyze._drop_unsupported_figures`, where it is logged.
        """
        out = (
            "</think>NARRATIVE: auth_events#1 shows a burst of loopback logons for "
            "one account, then one success from the same source address.\n"
            "OBSERVATIONS:\n- a burst of failures [auth_events#1]\n"
            "and then a note with no citation\n"
            "CITATIONS: auth_events#1"
        )
        assert len(parse_finding(out, domain="identity").observations) == 2


class TestTheNarrativeAnchorRuleIsAskedForButNotEnforced:
    """T14 was built, measured, and withdrawn. The measurement is the point.

    The rule -- every substantial narrative paragraph names the evidence set it
    describes -- came from one observation: on the first 2026-09-05 replay
    endpoint wrote a paragraph per set and named each (`Processes#6 (73 rows, 637
    events) ...`), so it looked like a trait the model had and identity lacked.

    On the next replay that was a one-off. FIVE OF SIX generations named no set
    anywhere in the narrative, across all three domains. Enforced, the rule
    rejected every reply twice, exhausted the bounded re-ask, and returned three
    empty findings -- strictly worse than three unanchored narratives. Relaxing it
    to "the narrative names at least one set" was measured on the same six and
    would still have rejected five.

    So the prompt asks and the parser does not enforce. Re-enforce only against a
    measurement showing the model complies.
    """

    def _reply(self, narrative):
        return (
            f"</think>NARRATIVE: {narrative}\n"
            "OBSERVATIONS:\n- a claim [auth_events#1]\n"
            "CITATIONS: auth_events#1"
        )

    def test_an_unanchored_narrative_parses(self):
        narrative = (
            "Two distinct accounts each saw four failed authentication attempts "
            "against the host, every one of them from the loopback address."
        )
        f = parse_finding(self._reply(narrative), domain="identity")
        assert f.narrative.startswith("Two distinct accounts")

    def test_the_prompt_still_asks_for_it(self):
        # Withdrawing the CHECK must not silently withdraw the REQUEST: the rule
        # is still what a checkable narrative looks like, and the day the model
        # complies is the day enforcement becomes affordable again.
        from smartops.subagent_analysts.prompts import _ANSWER_RULES

        flat = " ".join(_ANSWER_RULES.split()).lower()
        assert "name the sets you describe by their header id" in flat
