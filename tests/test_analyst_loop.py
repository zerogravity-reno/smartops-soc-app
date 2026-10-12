"""The Analyst's round loop, with the model and the Broker stubbed: the event order the UI reads."""

import json
from queue import Queue

from smartops import analyst


def test_one_round_to_a_verdict_streams_the_stages_in_order(monkeypatch, tmp_path):
    monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))
    plan = {"hypotheses": [{"id": "H1", "verdict": "TRUE_POSITIVE"}, {"id": "H2", "verdict": "BENIGN"}],
            "tasks": [{"task_id": "T1", "question": "q"}]}
    synth = {"hypothesis_scores": {"H1": 95, "H2": 10}, "evidence_refs": ["T1:endpoint"]}
    answers = iter([plan, synth])
    monkeypatch.setattr(analyst, "_ask", lambda system, user: {
        "reasoning": "r", "answer": json.dumps(next(answers)), "prompt_tokens": 1, "generation_tokens": 1,
        "stop_reason": "stop"})
    payload = {"payloads": [{"task_id": "r1-L2-T1", "findings": [{"domain": "endpoint", "observations": ["x"]}]}]}

    def broker_round(tasks, run_id, loop_num, q, ctrl, scope, event_time):
        analyst.emit(q, "handoff", {}, loop=loop_num)
        analyst.emit(q, "broker_log", {"line": "fetch plan"}, loop=loop_num)
        runs = [{"task_id": "r1-L2-T1", "run_dir": "d", "steps": [{"step_id": "s1", "completed": True}]}]
        return payload, {"tasks": tasks, "broker_runs": runs, "handshake": {}}

    monkeypatch.setattr(analyst, "_broker_round", broker_round)
    q = Queue()
    analyst.investigate("r1", {"normalized_seed": {}}, 15, q, lambda: None, {})

    events = [q.get_nowait() for _ in range(q.qsize())]
    assert [e["type"] for e in events] == ["analyst", "analyst", "handoff", "broker_log", "broker", "payload",
                                           "synthesis", "synthesis", "verdict", "done"]
    assert events[-2]["data"]["status"] == "VERDICT_REACHED"
    steps = [json.loads(line)["step"] for line in (tmp_path / "r1" / "investigation.jsonl").read_text().splitlines()]
    assert steps == ["analyst_plan", "broker", "synthesis"]
