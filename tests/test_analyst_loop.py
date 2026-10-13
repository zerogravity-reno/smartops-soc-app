"""The Analyst's round loop, with the model and the Broker stubbed: the event order the UI reads."""

import json
from queue import Queue

import pytest

from smartops import analyst
from smartops.subagent_analysts.model import AnalystResponse

PLAN = {"hypotheses": [{"id": "H1", "verdict": "TRUE_POSITIVE"}, {"id": "H2", "verdict": "BENIGN"}],
        "tasks": [{"task_id": "T1", "question": "q"}]}
PAYLOAD = {"payloads": [{"task_id": "r1-L2-T1", "findings": [{"domain": "endpoint", "observations": ["x"]}]}]}


class FakeModel:
    """Answers in order; each is (json, stop_reason) or a raw generation string."""

    max_gen_len = 16_384

    def __init__(self, *answers):
        self.answers = iter(answers)

    def invoke(self, system, user):
        answer, stop = next(self.answers)
        text = "thinking</think>" + json.dumps(answer) if isinstance(answer, dict) else answer
        return AnalystResponse(generation=text, prompt_tokens=6877, generation_tokens=100, stop_reason=stop)


@pytest.fixture
def run(monkeypatch, tmp_path):
    monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))
    rounds = []

    def broker_round(tasks, run_id, loop_num, q, ctrl, scope, event_time):
        rounds.append(loop_num)
        analyst.emit(q, "handoff", {}, loop=loop_num)
        analyst.emit(q, "broker_log", {"line": "fetch plan"}, loop=loop_num)
        runs = [{"task_id": "r1-L2-T1", "run_dir": "d", "steps": [{"step_id": "s1", "completed": True}]}]
        return PAYLOAD, {"tasks": tasks, "broker_runs": runs, "handshake": {}}

    monkeypatch.setattr(analyst, "_broker_round", broker_round)

    def go(*answers):
        monkeypatch.setattr(analyst, "_model", FakeModel(*answers))
        q = Queue()
        analyst.investigate("r1", {"normalized_seed": {}}, 15, q, lambda: None, {})
        events = [q.get_nowait() for _ in range(q.qsize())]
        records = [json.loads(line) for line in (tmp_path / "r1" / "investigation.jsonl").read_text().splitlines()]
        return events, records, rounds

    return go


def test_one_round_to_a_verdict_streams_the_stages_in_order(run):
    synth = {"hypothesis_scores": {"H1": 95, "H2": 10}, "evidence_refs": ["T1:endpoint"]}
    events, records, _ = run((PLAN, "stop"), (synth, "stop"))

    assert [e["type"] for e in events] == ["analyst", "analyst", "handoff", "broker_log", "broker", "payload",
                                           "synthesis", "synthesis", "verdict", "done"]
    assert events[-2]["data"]["status"] == "VERDICT_REACHED"
    assert [r["step"] for r in records] == ["analyst_plan", "broker", "synthesis"]


def test_a_cut_off_synthesis_ends_the_run_as_a_model_failure_not_a_verdict(run):
    # ea38cb13: a complete generation must close </think>; an incomplete one is
    # a silent REQUIRES_INVESTIGATION with no follow-ups (T15).
    events, _, _ = run((PLAN, "stop"), ("the model loops on the same thought " * 50, "length"))

    assert [e["type"] for e in events][-2:] == ["synthesis", "error"]  # no gated synthesis, no verdict
    end = events[-1]
    assert end["message"] == "Loop 2 synthesis was cut off at 16,384 tokens (stop_reason=length)"
    assert end["cut_off"] == {"stage": "synthesis", "loop": 2, "max_gen_len": 16384, "prompt_tokens": 6877}


def test_a_cut_off_plan_records_its_whole_generation_and_sends_nothing(run):
    events, records, rounds = run(("x" * 40 + "</think>" + '{"hypotheses": [', "length"))

    assert rounds == [] and events[-1]["cut_off"]["stage"] == "planning"
    [cut] = records
    assert cut["step"] == "cut_off" and cut["loop"] == 1 and cut["stage"] == "planning"
    assert (cut["reasoning"], cut["answer"], cut["think_closed"]) == ("x" * 40, '{"hypotheses": [', True)
    assert (cut["stop_reason"], cut["max_gen_len"], cut["generation_tokens"]) == ("length", 16384, 100)
