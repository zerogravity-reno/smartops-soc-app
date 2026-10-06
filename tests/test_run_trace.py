"""The webapp's side of the Analyst <-> Tool Broker join (`webapp/services/run_trace.py`)."""

import json

from contracts import TaskInputFile

from webapp.services import run_trace

WINDOW = {"start": "2026-09-27T13:04:55.000+03:00", "end": "2026-09-27T17:04:55.000+03:00"}


def test_plan_tasks_become_a_task_file_and_unsendable_ones_are_recorded():
    tasks = [
        {"task_id": "T1", "question": "q1", "entity": {"type": "hostname", "value": "ar-f6eddb5b-df6"}, "time_window": WINDOW},
        {"task_id": "T3", "question": "q3", "entity": {"type": "environment", "value": "ar-f6eddb5b-df6"}, "time_window": WINDOW},
    ]
    task_file, dropped = run_trace.to_task_file(tasks, "run1", 2)

    assert [t["task_id"] for t in task_file["tasks"]] == ["run1-L2-T1"]
    sent = task_file["tasks"][0]
    assert sent["entity"] == [{"type": "host", "value": "ar-f6eddb5b-df6"}]
    assert sent["hypothesis_id"] == sent["task_id"]
    [lost] = dropped
    assert lost["task_id"] == "T3" and "environment" in lost["why"] and lost["question"] == "q3"


def test_a_partly_usable_task_is_sent_and_the_narrowing_is_recorded():
    tasks = [{"task_id": "T1", "question": "q", "time_window": WINDOW,
              "entity": [{"type": "host", "value": "h"}, {"type": "environment", "value": "c"}]}]
    task_file, dropped = run_trace.to_task_file(tasks, "r", 2)
    assert task_file["tasks"][0]["entity"] == [{"type": "host", "value": "h"}]
    assert [d["task_id"] for d in dropped] == ["T1"] and "environment" in dropped[0]["why"]


def test_follow_ups_inherit_the_entities_and_the_widest_window():
    sent = [
        {"entity": [{"type": "host", "value": "h"}], "time_window": WINDOW},
        {"entity": [{"type": "host", "value": "h"}, {"type": "ip", "value": "1.2.3.4"}],
         "time_window": {"start": "2026-09-01T00:00:00Z", "end": "2026-09-27T12:00:00Z"}},
    ]
    [task] = run_trace.follow_up_tasks([{"task_id": "FU1", "question": "q"}, "junk"], sent)

    assert task["entity"] == [{"type": "host", "value": "h"}, {"type": "ip", "value": "1.2.3.4"}]
    assert task["time_window"] == {"start": "2026-09-01T00:00:00Z", "end": WINDOW["end"]}


def test_record_appends_and_links_resolve_through_latest(tmp_path, monkeypatch):
    monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))
    run_trace.record("run1", "analyst_plan", 1, plan={"tasks": []})
    run_trace.record("run1", "synthesis", 2, output={})
    lines = (tmp_path / "run1" / "investigation.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["step"] for line in lines] == ["analyst_plan", "synthesis"]

    report = {
        "trace_id": "b" * 32,
        "plan": {"rationale": "dns then processes", "steps": [
            {"step_id": "s1", "family": "siem", "objective": "resolve", "completion": {"categories": ["dns_resolutions"]}},
            {"step_id": "s2", "family": "siem", "objective": "procs", "completion": {"categories": []}},
        ]},
        "step_outcomes": [{"step": {"step_id": "s1"}, "completed": True, "rows_retrieved": 12,
                           "confirmed_empty": False, "status": "ok", "reason": None}],
        "dispatched": ["siem"],
        "classification": {"rationale": "only SIEM telemetry was needed"},
        "plan_repairs": ["dropped an unconfigured family"],
        "cost": {"total_spend_micro_usd": 487647},
        "results": [{"task_id": "run1-L2-T1:siem:tu1", "status": "ok", "reason": None, "error": None, "gaps": ["edr"],
                     "queries_run": [{"query": "index=windows_lab x"}], "blocked_queries": ["index=* y"]}],
    }
    for stamp, trace in (("old", "a" * 32), ("new", "b" * 32)):
        (tmp_path / "run1-L2-T1" / stamp).mkdir(parents=True)
        (tmp_path / "run1-L2-T1" / stamp / "report.json").write_text(json.dumps({**report, "trace_id": trace}))
    (tmp_path / "run1-L2-T1" / "latest.txt").write_text("new")

    [run] = run_trace.broker_runs(["run1-L2-T1"])
    assert run["trace_id"] == "b" * 32 and run["run_dir"].endswith("new")
    assert [(s["step_id"], s["completed"], s["rows_retrieved"]) for s in run["steps"]] == [("s1", True, 12), ("s2", None, None)]
    assert (run["classification"], run["plan_repairs"], run["spend_micro_usd"]) == (
        "only SIEM telemetry was needed", ["dropped an unconfigured family"], 487647)
    assert run["results"] == [{"family": "siem", "status": "ok", "reason": None, "error": None, "gaps": ["edr"],
                               "queries": ["index=windows_lab x"], "blocked": ["index=* y"]}]
    assert run_trace.broker_runs(["missing"]) == [{"task_id": "missing", "run_dir": None}]


def test_file_and_command_entities_reach_the_broker_but_a_data_source_does_not():
    tasks = [
        {"task_id": "T1", "question": "q", "entity": {"type": "file", "value": "OneDrive.exe"}, "time_window": WINDOW},
        {"task_id": "T2", "question": "q", "entity": {"type": "command", "value": "JABlAG4AdgA="}, "time_window": WINDOW},
        {"task_id": "T3", "question": "q", "entity": {"type": "log", "value": "Splunk ES logs"}, "time_window": WINDOW},
    ]
    task_file, dropped = run_trace.to_task_file(tasks, "r", 2)
    assert [t["entity"] for t in task_file["tasks"]] == [
        [{"type": "file_name", "value": "OneDrive.exe"}], [{"type": "command_line", "value": "JABlAG4AdgA="}]]
    assert [d["task_id"] for d in dropped] == ["T3"] and "log" in dropped[0]["why"]
    # The engine accepts what the handoff now sends.
    TaskInputFile.model_validate(task_file)


def test_a_task_with_no_searchable_entity_is_scoped_to_the_alert_and_says_so():
    context = {"normalized_seed": {"entities": {"hostname": "ar-f6eddb5b-df6", "user": "Mariam"}}}
    scope = run_trace.alert_entities(context)
    tasks = [
        {"task_id": "T4", "question": "similar Get-Process runs?", "time_window": WINDOW,
         "entity": {"type": "log", "value": "Splunk ES logs"}},
        {"task_id": "T5", "question": "script block logging?", "time_window": WINDOW,
         "entity": {"type": "scheduled_task|group_policy", "value": "svcupdate.dat"}},
    ]
    task_file, notes = run_trace.to_task_file(tasks, "r", 2, scope)
    alert = [{"type": "host", "value": "ar-f6eddb5b-df6"}, {"type": "user", "value": "Mariam"}]
    assert [t["entity"] for t in task_file["tasks"]] == [alert, alert]
    assert [n["task_id"] for n in notes] == ["T4", "T5"]
    assert "log is not a value to match: sent scoped to the alert's host=ar-f6eddb5b-df6" in notes[0]["why"]
    # Without an alert to fall back on it is still dropped, and says why.
    task_file, dropped = run_trace.to_task_file(tasks[:1], "r", 2)
    assert task_file["tasks"] == [] and "log" in dropped[0]["why"]


def test_spellings_of_known_types_are_recognised():
    tasks = [{"task_id": "T1", "question": "q", "time_window": WINDOW, "entity": [
        {"type": "ip_address", "value": "192.168.40.211"}, {"type": "file_path", "value": "%TEMP%\\svcupdate.dat"},
        {"type": "process|user", "value": "powershell.exe"}]}]
    task_file, dropped = run_trace.to_task_file(tasks, "r", 2)
    assert [e["type"] for e in task_file["tasks"][0]["entity"]] == ["ip", "file_name", "process"] and dropped == []


def test_a_placeholder_window_costs_only_its_own_task():
    tasks = [
        {"task_id": "T1", "question": "q", "entity": {"type": "host", "value": "h"}, "time_window": WINDOW},
        {"task_id": "T2", "question": "q", "entity": {"type": "host", "value": "h"},
         "time_window": {"start": "REPLACE_START", "end": "REPLACE_END"}},
        {"task_id": "T3", "question": "q", "entity": {"type": "host", "value": "h"},
         "time_window": {"start": "2026-09-27T13:00:00", "end": "2026-09-27T14:00:00"}},  # naive
    ]
    task_file, dropped = run_trace.to_task_file(tasks, "r", 2)
    assert [t["task_id"] for t in task_file["tasks"]] == ["r-L2-T1"]
    assert sorted(d["task"]["task_id"] for d in dropped) == ["T2", "T3"]


def test_the_handshake_names_what_went_missing():
    runs = [{"task_id": "a", "run_dir": "x"}, {"task_id": "b", "run_dir": None}]
    payload = {"payloads": [{"task_id": "a"}, {"task_id": "z"}]}
    h = run_trace.handshake(["a", "b"], runs, payload)
    assert (h["not_fetched"], h["not_returned"], h["unexpected"]) == (["b"], ["b"], ["z"])
    assert run_trace.handshake(["a"], runs[:1], None)["not_returned"] == ["a"]


def test_notable_event_time_is_the_event_not_the_search():
    # Run 600721d3: ES ran the search at 13:04:17Z; the process ran at 11:50:44Z.
    ev = {"_time": "2026-10-06T16:04:17.000+03:00", "firstTime": "2026-10-06T14:50:44"}
    assert run_trace.notable_event_time(ev) == "2026-10-06T11:50:44+00:00"
    assert run_trace.notable_event_time({"_time": ev["_time"], "firstTime": "1791287444"}) == "2026-10-06T11:50:44+00:00"
    assert run_trace.notable_event_time({"_time": ev["_time"]}) == "2026-10-06T13:04:17+00:00"
    assert run_trace.notable_event_time({"_time": ev["_time"], "firstTime": "garbage"}) == "2026-10-06T13:04:17+00:00"
