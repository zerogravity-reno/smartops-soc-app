"""One investigation through the whole app, offline: POST /api/run, then the UI's
event stream until the run ends. Only the Analyst model is faked; the API, the
plan handoff and a real scripted Broker round run for real."""

import json
import warnings

with warnings.catch_warnings():
    # ponytail: starlette wants httpx2 for TestClient; httpx still works. Drop when httpx2 is a dependency.
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient
from test_analyst_loop import FakeModel

from smartops import analyst, broker, main

PLAN = {"hypotheses": [{"id": "H1", "verdict": "TRUE_POSITIVE"}, {"id": "H2", "verdict": "BENIGN"}],
        "tasks": [{"task_id": "T1", "question": "Did BSTOLL-L resolve coinhive.com?",
                   "entity": {"type": "host", "value": "BSTOLL-L"},
                   "time_window": {"start": "2018-08-20T00:00:00Z", "end": "2018-08-21T00:00:00Z"}}]}


def test_an_alert_runs_from_the_api_through_a_real_broker_round(monkeypatch, tmp_path):
    monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))
    monkeypatch.setattr(analyst, "_model", FakeModel((PLAN, "stop")))
    monkeypatch.setattr(analyst, "round_args", lambda **kw: broker.round_args(scripted=True, **kw))

    with TestClient(main.app) as client:
        run_id = client.post("/api/run", json={"max_loops": 2}).json()["run_id"]
        with client.stream("GET", f"/api/run/stream/{run_id}") as stream:
            events = [json.loads(line[6:]) for line in stream.iter_lines() if line.startswith("data: ")]

    types = [e["type"] for e in events]
    assert types[:3] == ["analyst", "analyst", "handoff"]
    assert "broker_log" in types and types[-2:] == ["broker", "error"]
    # ponytail: offline there is no Splunk and no sub-analyst model, so the round hands
    # back no payload and synthesis never runs (test_analyst_loop covers it). Reaching
    # a verdict here needs a fake siem MCP server and a fake sub-analyst model.
    assert "broker wrote no analyst payload" in events[-1]["message"]
    assert (tmp_path / run_id / "L2" / "tasks.json").is_file()
