"""B52 F: VirusTotal as a direct Broker tool, once per indicator per run.

VT was a model subagent dispatched as a plan step; on Yousef's runs the alert's
injected hash went to it on questions that never asked about reputation, and one
hash went 10 times across loops 3-7. `vt_lookup` is code: relevance gated, one
lookup per (kind, value) per run, a repeat answered with the earlier result.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from contracts import (
    AnalystTask,
    Entity,
    FetchStep,
    ResultSet,
    Scope,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
)
from contracts.findings import VtFindings, VtVerdict

from smartops import broker
from smartops.broker import BrokerRequest, _progress, _vt_lookup

HASH = "a" * 64
OTHER = "b" * 64
NOW = datetime(2026, 8, 11, tzinfo=UTC)


def _task(task_id="run1-L2-T1", goal="did host-1 run a bad binary", entities=None) -> AnalystTask:
    return AnalystTask(
        task_id=task_id, hypothesis_id=task_id, goal=goal,
        scope=Scope(entities=entities or [Entity(kind="host", value="host-1"), Entity(kind="file_hash", value=HASH)],
                    time_window=(NOW - timedelta(hours=1), NOW)),
    )


@pytest.fixture
def lookups(monkeypatch):
    """Every lookup that reached VirusTotal; answers `found`, malicious 3."""
    calls: list[str] = []
    status = {"value": SubtaskStatus.OK}

    async def fake(mission, enrich):
        await asyncio.sleep(0)
        e = mission.scope.entities[0]
        calls.append(e.value)
        if status["value"] is SubtaskStatus.ERROR:
            return SubtaskResult(task_id=mission.task_id, status=SubtaskStatus.ERROR, reason="vt down", error="x")
        return SubtaskResult(
            task_id=mission.task_id, status=SubtaskStatus.OK,
            findings=VtFindings(verdicts=[VtVerdict(kind=e.kind, value=e.value, found=True, malicious=3,
                                                    suspicious=0, harmless=1, undetected=60)]),
        )

    monkeypatch.setattr(broker, "enrich_mission", fake)
    monkeypatch.setattr(broker, "enricher_for", lambda family: object())
    return calls, status


def _ask(req, kind, value, reason="is this hash known-bad?"):
    return asyncio.run(_vt_lookup(req, kind, value, reason, "c1"))


def test_a_hash_in_scope_is_looked_up_and_its_result_collected(lookups):
    calls, _ = lookups
    req = BrokerRequest(task=_task())
    text = _ask(req, "file_hash", HASH)
    assert calls == [HASH]
    assert "malicious 3" in text
    assert isinstance(req.collected[0].findings, VtFindings) and req.dispatched == ["vt"]


def test_a_value_named_nowhere_is_refused(lookups):
    calls, _ = lookups
    text = _ask(BrokerRequest(task=_task()), "file_hash", OTHER)
    assert text.startswith("status=refused") and "not named in the question" in text
    assert calls == []


def test_a_value_named_in_the_question_is_allowed(lookups):
    calls, _ = lookups
    _ask(BrokerRequest(task=_task(goal=f"is {OTHER} known malware?")), "file_hash", OTHER)
    assert calls == [OTHER]


def _with_rows(req, name, rows):
    req.collected.append(SubtaskResult(
        task_id="x", status=SubtaskStatus.OK,
        findings=SiemFindings(**{name: [ResultSet(query="q", row_count=len(rows), rows=rows)]}),
    ))


def test_an_ip_pivoted_from_a_retrieved_row_is_allowed(lookups):
    calls, _ = lookups
    req = BrokerRequest(task=_task())
    _with_rows(req, "connections", [{"src": "host-1", "dest": "8.8.4.4"}])
    _ask(req, "ip", "8.8.4.4", "reputation of the address host-1 reached")
    assert calls == ["8.8.4.4"]


def test_an_ip_only_in_a_discovery_set_is_refused(lookups):
    calls, _ = lookups
    req = BrokerRequest(task=_task())
    _with_rows(req, "discovery", [{"dest": "8.8.4.4"}])
    assert _ask(req, "ip", "8.8.4.4").startswith("status=refused")
    assert calls == []


def test_a_later_task_in_the_run_gets_the_earlier_result(lookups):
    calls, _ = lookups
    _ask(BrokerRequest(task=_task("run1-L2-T1")), "file_hash", HASH)
    text = _ask(BrokerRequest(task=_task("run1-L3-FU2")), "file_hash", HASH.upper())
    assert calls == [HASH]
    assert "already looked up in this run by L2-T1" in text and "malicious 3" in text


def test_two_concurrent_siblings_make_one_lookup(lookups):
    calls, _ = lookups

    async def both():
        return await asyncio.gather(
            _vt_lookup(BrokerRequest(task=_task("run1-L2-T1")), "file_hash", HASH, "r", "a"),
            _vt_lookup(BrokerRequest(task=_task("run1-L2-T2")), "file_hash", HASH, "r", "b"),
        )

    first, second = asyncio.run(both())
    assert calls == [HASH]
    assert "is looking up" in second


def test_an_error_is_retried_on_the_next_ask(lookups):
    calls, status = lookups
    status["value"] = SubtaskStatus.ERROR
    _ask(BrokerRequest(task=_task("run1-L2-T1")), "file_hash", HASH)
    status["value"] = SubtaskStatus.OK
    _ask(BrokerRequest(task=_task("run1-L2-T2")), "file_hash", HASH)
    assert calls == [HASH, HASH]


def test_a_private_ip_and_a_missing_reason_are_refused(lookups):
    calls, _ = lookups
    req = BrokerRequest(task=_task(entities=[Entity(kind="ip", value="192.168.1.5")]))
    assert "holds nothing" in _ask(req, "ip", "192.168.1.5")
    assert "needs a reason" in _ask(BrokerRequest(task=_task()), "file_hash", HASH, reason=" ")
    assert calls == []


def test_the_progress_line_lists_the_lookups(lookups):
    req = BrokerRequest(task=_task())
    _ask(req, "file_hash", HASH)
    assert f"vt lookups: file_hash {HASH}" in _progress(req)


def test_plan_fetch_refuses_a_vt_step():
    req = BrokerRequest(task=_task())

    class _Ctx:
        tool_use = {"toolUseId": "p"}
        invocation_state = {"smartops": req}

    text = asyncio.run(broker.plan_fetch(
        steps=[FetchStep(step_id="s1", family="vt", objective="hash reputation")],
        rationale="r", tool_context=_Ctx(),
    ))
    assert "refused" in text.lower() and req.plan is None


def test_a_scripted_run_with_vt_looks_up_the_scope(lookups):
    calls, _ = lookups
    req = BrokerRequest(task=_task())
    asyncio.run(broker._scripted_invoker(["vt"])("prompt", req))
    assert calls == [HASH] and req.plan is None


def test_a_partial_ip_in_the_question_does_not_name_another(lookups):
    calls, _ = lookups
    assert _ask(BrokerRequest(task=_task(goal="did host-1 reach 18.8.4.40?")), "ip", "8.8.4.4").startswith("status=refused")
    assert calls == []


def test_urls_differing_only_in_path_case_are_separate_lookups(lookups):
    calls, _ = lookups
    goal = "were https://example.com/A and https://example.com/a fetched?"
    _ask(BrokerRequest(task=_task("run1-L2-T1", goal=goal)), "url", "https://example.com/A")
    _ask(BrokerRequest(task=_task("run1-L2-T2", goal=goal)), "url", "https://example.com/a")
    assert calls == ["https://example.com/A", "https://example.com/a"]


def test_lookups_in_successive_rounds_on_their_own_loops_do_not_collide(lookups):
    calls, _ = lookups

    async def round_(n):
        return await asyncio.gather(*(
            _vt_lookup(BrokerRequest(task=_task(f"run{n}-L2-T{i}", goal=f"is {h} bad?")), "file_hash", h, "r", f"c{i}")
            for i, h in enumerate((HASH, OTHER))
        ))

    asyncio.run(round_(1))
    asyncio.run(round_(2))  # a fresh loop: a lock bound to the first would raise here
    assert len(calls) == 4


def test_eviction_keeps_a_run_with_a_lookup_in_flight(lookups):
    broker._VT_SEEN["busy"] = {("file_hash", HASH): "L2-T1" + broker._IN_FLIGHT}
    for n in range(broker._RUNS_HELD + 2):
        _ask(BrokerRequest(task=_task(f"r{n}-L2-T1")), "file_hash", HASH)
    assert "busy" in broker._VT_SEEN


@pytest.mark.parametrize("goal, kind, value", [
    ("did host-1 reach notexample.com?", "domain", "example.com"),
    ("was https://example.com/AB fetched?", "url", "https://example.com/A"),
    ("was https://example.com/A fetched?", "url", "https://example.com/a"),
])
def test_a_question_naming_a_longer_or_differently_cased_value_does_not_name_this_one(lookups, goal, kind, value):
    calls, _ = lookups
    assert _ask(BrokerRequest(task=_task(goal=goal)), kind, value).startswith("status=refused")
    assert calls == []


def test_a_domain_named_with_punctuation_is_named(lookups):
    calls, _ = lookups
    _ask(BrokerRequest(task=_task(goal="did host-1 resolve (Example.com)?")), "domain", "example.com")
    assert calls == ["example.com"]


def test_finished_rounds_loops_are_not_held(lookups):
    for n in range(3):
        asyncio.run(_vt_lookup(BrokerRequest(task=_task(f"q{n}-L2-T1")), "file_hash", HASH, "r", "c"))
    asyncio.run(_vt_lookup(BrokerRequest(task=_task("q9-L2-T1")), "file_hash", HASH, "r", "c"))
    assert len(broker._VT_LOCKS) <= 1  # only the last round's loop is left
