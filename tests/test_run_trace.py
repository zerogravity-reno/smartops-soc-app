"""The webapp's side of the Analyst <-> Tool Broker join (`webapp/services/run_trace.py`)."""

import json

from webapp.services import run_trace

WINDOW = {"start": "2026-09-27T13:04:55.000+03:00", "end": "2026-09-27T17:04:55.000+03:00"}


def test_plan_tasks_become_a_task_file_and_unsendable_ones_are_recorded():
    tasks = [
        {"task_id": "T1", "question": "q1", "entity": {"type": "hostname", "value": "ar-f6eddb5b-df6"}, "time_window": WINDOW},
        {"task_id": "T3", "question": "q3", "entity": {"type": "command", "value": "powershell.exe -C ..."}, "time_window": WINDOW},
    ]
    task_file, dropped = run_trace.to_task_file(tasks, "run1", 2)

    assert [t["task_id"] for t in task_file["tasks"]] == ["run1-L2-T1"]
    sent = task_file["tasks"][0]
    assert sent["entity"] == [{"type": "host", "value": "ar-f6eddb5b-df6"}]
    assert sent["hypothesis_id"] == sent["task_id"]
    [lost] = dropped
    assert lost["task_id"] == "T3" and "command" in lost["why"] and lost["question"] == "q3"


def test_a_partly_usable_task_is_sent_and_the_narrowing_is_recorded():
    tasks = [{"task_id": "T1", "question": "q", "time_window": WINDOW,
              "entity": [{"type": "host", "value": "h"}, {"type": "command", "value": "c"}]}]
    task_file, dropped = run_trace.to_task_file(tasks, "r", 2)
    assert task_file["tasks"][0]["entity"] == [{"type": "host", "value": "h"}]
    assert [d["task_id"] for d in dropped] == ["T1"] and "command" in dropped[0]["why"]


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
        "results": [{"task_id": "run1-L2-T1:siem:tu1", "status": "ok", "reason": None, "gaps": ["edr"],
                     "queries_run": [{"query": "index=windows_lab x"}], "blocked_queries": ["index=* y"]}],
    }
    for stamp, trace in (("old", "a" * 32), ("new", "b" * 32)):
        (tmp_path / "run1-L2-T1" / stamp).mkdir(parents=True)
        (tmp_path / "run1-L2-T1" / stamp / "report.json").write_text(json.dumps({**report, "trace_id": trace}))
    (tmp_path / "run1-L2-T1" / "latest.txt").write_text("new")

    [run] = run_trace.broker_runs(["run1-L2-T1"])
    assert run["trace_id"] == "b" * 32 and run["run_dir"].endswith("new")
    assert [(s["step_id"], s["completed"], s["rows_retrieved"]) for s in run["steps"]] == [("s1", True, 12), ("s2", None, None)]
    assert run["results"] == [{"family": "siem", "status": "ok", "reason": None, "gaps": ["edr"],
                               "queries": ["index=windows_lab x"], "blocked": ["index=* y"]}]
    assert run_trace.broker_runs(["missing"]) == [{"task_id": "missing", "run_dir": None}]


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
