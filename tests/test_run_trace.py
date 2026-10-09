"""The webapp's side of the Analyst <-> Tool Broker join (`webapp/services/run_trace.py`)."""

from datetime import UTC, datetime
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


def test_record_appends_and_reports_resolve_in_the_round_folder(tmp_path, monkeypatch):
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
    # One run folder (O5): run1/L2/T1/report.json, found by the task id it names.
    (tmp_path / "T1").mkdir()
    (tmp_path / "T1" / "report.json").write_text(json.dumps({**report, "task_id": "run1-L2-T1", "trace_id": "b" * 32}))

    [run] = run_trace.broker_runs(["run1-L2-T1"], tmp_path)
    assert run["trace_id"] == "b" * 32 and run["run_dir"].endswith("T1")
    assert [(s["step_id"], s["completed"], s["rows_retrieved"]) for s in run["steps"]] == [("s1", True, 12), ("s2", None, None)]
    assert (run["classification"], run["plan_repairs"], run["spend_micro_usd"]) == (
        "only SIEM telemetry was needed", ["dropped an unconfigured family"], 487647)
    assert run["results"] == [{"family": "siem", "status": "ok", "reason": None, "error": None, "gaps": ["edr"],
                               "queries": ["index=windows_lab x"], "blocked": ["index=* y"]}]
    assert run_trace.broker_runs(["missing"], tmp_path) == [{"task_id": "missing", "run_dir": None}]


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


def test_every_task_carries_the_alerts_host_and_hash_and_a_pid_is_a_process_id():
    # 148b0e69: T3 sent `process=2900` and searched `index=*`; T2 could not choose VT.
    sha = "1C84C8632C5269F24876ED9F49FA810B49F77E1E92E8918FC164C34B020F9A94"
    context = {"normalized_seed": {"entities": {"hostname": "ar-f6eddb5b-df6", "user": "Mariam"},
                                   "file": {"sha256": f"MD5=2E0CCB27064856E3D55017FA2D33A7B9,SHA256={sha},IMPHASH=BF7A"}}}
    scope = run_trace.alert_entities(context)
    tasks = [{"task_id": "T3", "question": "what did PID 2900 do?", "time_window": WINDOW,
              "entity": {"type": "process", "value": "2900"}}]
    task_file, _ = run_trace.to_task_file(tasks, "r", 2, scope)
    assert task_file["tasks"][0]["entity"] == [
        {"type": "process_id", "value": "2900"},
        {"type": "host", "value": "ar-f6eddb5b-df6"},
        {"type": "file_hash", "value": sha},
    ]
    TaskInputFile.model_validate(task_file)


def test_a_name_with_its_pid_is_sent_as_two_entities():
    # 874ab334: `powershell.exe (PID 12345)` went to the Broker as one process name.
    tasks = [{"task_id": "T1", "question": "what ran?", "time_window": WINDOW,
              "entity": {"type": "process", "value": "powershell.exe (PID 12345)"}}]
    task_file, _ = run_trace.to_task_file(tasks, "r", 2)
    assert task_file["tasks"][0]["entity"] == [
        {"type": "process", "value": "powershell.exe"},
        {"type": "process_id", "value": "12345"},
    ]
    TaskInputFile.model_validate(task_file)


def test_the_alerts_process_guid_rides_with_a_pid():
    # 5aae1a35: PID 220 was setup.exe and six forwarder processes in one day.
    guid = "{66ac357b-3e84-6ac5-5dff-030000000e00}"
    context = {"normalized_seed": {"entities": {"hostname": "ar-f6eddb5b-df6"},
                                   "process": {"process_name": "setup.exe", "process_guid": guid}}}
    scope = run_trace.alert_entities(context)
    assert {"type": "process_guid", "value": guid} in scope

    tasks = [{"task_id": "T1", "question": "parent of PID 220?", "time_window": WINDOW,
              "entity": {"type": "process_id", "value": "220"}}]
    task_file, _ = run_trace.to_task_file(tasks, "r", 2, scope)
    assert {"type": "process_guid", "value": guid} in task_file["tasks"][0]["entity"]
    TaskInputFile.model_validate(task_file)


def _window_task(start, end):
    return [{"task_id": "T1", "question": "q", "entity": {"type": "host", "value": "h"},
             "time_window": {"start": start, "end": end}}]


def test_a_window_is_widened_to_the_event_and_never_runs_past_now():
    event = "2026-10-06T18:41:51.000Z"
    file, notes = run_trace.to_task_file(_window_task("2026-10-06T18:41:51Z", "2026-10-06T18:42:51Z"), "r", 2, event_time=event)
    assert file["tasks"][0]["time_window"] == {"start": "2026-10-06T17:41:51Z", "end": "2026-10-06T19:41:51Z"}
    assert "event +/- 1h" in notes[0]["why"] and notes[0]["sent"]

    # A wider lookback the Analyst chose keeps its start.
    file, _ = run_trace.to_task_file(_window_task("2026-10-04T18:41:51Z", "2026-10-06T18:41:51Z"), "r", 2, event_time=event)
    assert file["tasks"][0]["time_window"] == {"start": "2026-10-04T18:41:51Z", "end": "2026-10-06T19:41:51Z"}

    file, _ = run_trace.to_task_file(_window_task("2026-10-06T17:00:00Z", "2999-01-01T00:00:00Z"), "r", 2, event_time=event)
    assert run_trace._instant(file["tasks"][0]["time_window"]["end"]) <= datetime.now(UTC)

    # No event time: passed through as before.
    file, notes = run_trace.to_task_file(_window_task("2026-10-06T18:41:51Z", "2026-10-06T18:42:51Z"), "r", 2)
    assert file["tasks"][0]["time_window"]["start"] == "2026-10-06T18:41:51Z" and not notes


def test_a_lookup_with_a_zero_length_window_is_sent_at_event_plus_minus_an_hour():
    # c90ca5f9's T1, as the Analyst wrote it: start == end, at the event (B19).
    t1 = {"task_id": "T1", "question": "What is the full path of svcupdate.dat?",
          "entity": {"type": "file", "value": "svcupdate.dat"},
          "time_window": {"start": "2026-10-06T11:51:16Z", "end": "2026-10-06T11:51:16Z"}}
    no_window = {**t1, "task_id": "T2", "time_window": None}
    file, notes = run_trace.to_task_file([t1, no_window], "r", 2, event_time="2026-10-06T11:51:16.000Z")
    assert [t["time_window"] for t in file["tasks"]] == [{"start": "2026-10-06T10:51:16Z", "end": "2026-10-06T12:51:16Z"}] * 2
    assert all(n["sent"] for n in notes)

    # With no event to widen to, it is still unusable, and costs only itself.
    file, notes = run_trace.to_task_file([t1], "r", 2)
    assert not file["tasks"] and "start first" in notes[0]["why"]


def test_notables_fold_by_rule_and_host_in_first_seen_order():
    rows = [
        {"index": 0, "time": "t0", "rule_name": "A", "dest": "h1", "urgency": "low", "user": "u1", "src": ""},
        {"index": 1, "time": "t1", "rule_name": "B", "dest": "h1", "urgency": "medium", "user": "", "src": ""},
        {"index": 2, "time": "t2", "rule_name": "A", "dest": "h1", "urgency": "high", "user": "u2", "src": ""},
        {"index": 3, "time": "t3", "rule_name": "A", "dest": "h2", "urgency": "low", "user": "", "src": ""},
        {"index": 4, "time": "t4", "rule_name": "A", "dest": "h1", "urgency": "medium", "user": "u1", "src": ""},
    ]
    groups = run_trace.group_notables(rows)

    assert [(g["rule_name"], g["dest"], g["count"]) for g in groups] == [("A", "h1", 3), ("B", "h1", 1), ("A", "h2", 1)]
    a = groups[0]
    assert a["urgency"] == "high" and a["time"] == "t0" and a["users"] == ["u1", "u2"]
    assert [e["index"] for e in a["events"]] == [0, 2, 4]


def test_the_queue_and_the_import_read_one_row_per_event():
    # ESCU rules raised each event 12 times; the queue's index must match the import's.
    base = run_trace.notables_spl()
    assert base.index("| dedup search_name dest firstTime") < base.index("| sort -_time")
    ruled = run_trace.notables_spl("*x*")
    assert ruled.index('search_name="*x*"') < ruled.index("| dedup")
