"""G13: Analyst must never accept an evaluation-shaped or tasks-free answer in Loop 1.

If the model answers without tasks (whether evaluation-shaped or hypotheses-only),
the code must re-ask once. If the re-ask also returns no tasks, it must abort with an error —
never emit a verdict before the Broker has run.
"""

import json
import queue
import threading
from unittest.mock import MagicMock, patch

import pytest

from smartops import analyst
from smartops.analyst import CutOff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PLAN_RESPONSE = {
    "hypotheses": [
        {"id": "H1", "verdict": "TRUE_POSITIVE",  "description": "Attacker used obfuscated PS"},
        {"id": "H2", "verdict": "FALSE_POSITIVE",  "description": "IT admin running maintenance"},
        {"id": "H3", "verdict": "BENIGN",           "description": "Scheduled backup script"},
    ],
    "tasks": [
        {"task_id": "T1", "question": "What process spawned powershell?",
         "entity": {"type": "host", "value": "AR-HOST"}, "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"}},
    ],
    "semantic_alignment": "ALIGNED",
    "model_reasoning": "Needs Broker evidence.",
}

_HYPOTHESES_ONLY_RESPONSE = {
    "hypotheses": [
        {"id": "H1", "verdict": "TRUE_POSITIVE",  "description": "Attacker used obfuscated PS"},
        {"id": "H2", "verdict": "FALSE_POSITIVE",  "description": "IT admin running maintenance"},
        {"id": "H3", "verdict": "BENIGN",           "description": "Scheduled backup script"},
    ],
    "tasks": [],
    "semantic_alignment": "ALIGNED",
    "model_reasoning": "I made hypotheses but forgot tasks.",
}

_EVAL_RESPONSE = {
    "status": "VERDICT_REACHED",
    "verdict": "BENIGN",
    "verdict_confidence": 90,
    "verdict_reasoning": "Looks benign from alert text alone.",
    "hypothesis_scores": {"H1": 10, "H2": 20, "H3": 90},
    "evidence_refs": [],
    "evidence_gaps": [],
    "follow_up_tasks": [],
}

_ALERT_CONTEXT = {
    "normalized_seed": {"event_time": "2026-10-01T11:00:00Z"},
    "alert_scope": {"entity": [{"type": "host", "value": "AR-HOST"}]},
}


def _make_ask_response(payload: dict) -> dict:
    return {
        "answer": json.dumps(payload),
        "reasoning": "",
        "prompt_tokens": 100,
        "generation_tokens": 200,
        "stop_reason": "stop",
    }


def _drain(q: queue.Queue) -> list:
    events = []
    while True:
        try:
            events.append(q.get_nowait())
        except queue.Empty:
            break
    return events


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_eval_shaped_loop1_triggers_reask_and_plan_is_accepted():
    """If Loop 1 returns evaluation JSON, the code must re-ask once.
    If the re-ask returns a valid plan, the run continues normally (Broker runs).
    No 'verdict' event must be emitted before the Broker."""
    calls = []

    def fake_ask(system_prompt, user_msg, stage):
        calls.append(user_msg)
        if len(calls) == 1:
            return _make_ask_response(_EVAL_RESPONSE)   # first: bad (eval format)
        return _make_ask_response(_PLAN_RESPONSE)        # re-ask: good plan

    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}

    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst, "_broker_round", return_value=({}, {"error": "stop-test"})),
        patch.object(analyst.telemetry, "record") as mock_record,
    ):
        analyst.investigate(
            run_id="test-g13",
            alert_context=_ALERT_CONTEXT,
            max_loops=1,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )

    events = _drain(q)
    types = [e["type"] for e in events]

    # Must have re-asked (two _ask calls)
    assert len(calls) == 2, f"Expected 2 _ask calls (initial + re-ask), got {len(calls)}"

    # Re-ask prompt reinforces planning instruction without confusing evaluation vocabulary
    assert "PLANNING INSTRUCTION" in calls[1]
    assert "at least one atomic investigation task" in calls[1]

    # No direct 'verdict' event before broker
    assert "verdict" not in types, (
        f"A 'verdict' event must NOT be emitted before the Broker runs. Events: {types}"
    )

    # Telemetry should only record analyst_plan once with the successful plan (Comment 3)
    plan_records = [c for c in mock_record.call_args_list if c.args[1] == "analyst_plan"]
    assert len(plan_records) == 1, f"Expected exactly 1 analyst_plan telemetry record, got {len(plan_records)}"


def test_hypotheses_with_empty_tasks_triggers_reask_and_proceeds():
    """Comment 1 & 4: A response with hypotheses but tasks: [] must trigger a re-ask,
    preventing 0-task Broker failure."""
    calls = []

    def fake_ask(system_prompt, user_msg, stage):
        calls.append(user_msg)
        if len(calls) == 1:
            return _make_ask_response(_HYPOTHESES_ONLY_RESPONSE)   # hypotheses present, tasks empty
        return _make_ask_response(_PLAN_RESPONSE)                  # re-ask succeeds with tasks

    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}

    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst, "_broker_round", return_value=({}, {"error": "stop-test"})),
        patch.object(analyst.telemetry, "record"),
    ):
        analyst.investigate(
            run_id="test-g13-hypotheses-empty-tasks",
            alert_context=_ALERT_CONTEXT,
            max_loops=1,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )

    assert len(calls) == 2, "Must re-ask when tasks is empty, even if hypotheses are present"


def test_empty_tasks_after_reask_aborts_with_error():
    """Comment 1: If after re-ask tasks is still empty, the run must abort with error."""

    def fake_ask(system_prompt, user_msg, stage):
        return _make_ask_response(_HYPOTHESES_ONLY_RESPONSE)  # still returns tasks: []

    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}

    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst.telemetry, "record"),
    ):
        analyst.investigate(
            run_id="test-g13-still-no-tasks",
            alert_context=_ALERT_CONTEXT,
            max_loops=1,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )

    events = _drain(q)
    types = [e["type"] for e in events]
    assert "error" in types
    err_event = next(e for e in events if e["type"] == "error")
    assert "no tasks after re-ask" in err_event["message"]


def test_eval_shaped_loop1_then_eval_again_aborts_with_error():
    """If both the initial call and the re-ask return evaluation JSON, the run
    must abort with an error — never emit a verdict."""

    def fake_ask(system_prompt, user_msg, stage):
        return _make_ask_response(_EVAL_RESPONSE)   # always returns eval format

    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}

    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst.telemetry, "record"),
    ):
        analyst.investigate(
            run_id="test-g13-abort",
            alert_context=_ALERT_CONTEXT,
            max_loops=1,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )

    events = _drain(q)
    types = [e["type"] for e in events]

    assert "verdict" not in types, "Must NOT emit verdict when both calls return eval format"
    assert "error" in types, f"Must emit an error event. Got: {types}"


def test_cutoff_during_reask_propagates_or_aborts():
    """Comment 4: CutOff raised during the re-ask is cleanly caught and emits an error event."""
    calls = []

    def fake_ask(system_prompt, user_msg, stage):
        calls.append(user_msg)
        if len(calls) == 1:
            return _make_ask_response(_EVAL_RESPONSE)
        raise CutOff(stage="planning", max_gen_len=16384, result={"reasoning": "", "answer": "", "prompt_tokens": 150, "generation_tokens": 16384})

    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}

    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst.telemetry, "record") as mock_record,
    ):
        analyst.investigate(
            run_id="test-g13-cutoff-reask",
            alert_context=_ALERT_CONTEXT,
            max_loops=1,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )

    events = _drain(q)
    types = [e["type"] for e in events]
    assert "error" in types
    err_event = next(e for e in events if e["type"] == "error")
    assert "cut off" in err_event["message"].lower()

    # Telemetry should record the cut_off event
    cutoff_records = [c for c in mock_record.call_args_list if c.args[1] == "cut_off"]
    assert len(cutoff_records) == 1


def test_valid_plan_in_loop1_does_not_trigger_reask():
    """A correct planning response must NOT trigger a re-ask."""
    calls = []

    def fake_ask(system_prompt, user_msg, stage):
        calls.append(user_msg)
        return _make_ask_response(_PLAN_RESPONSE)

    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}

    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst, "_broker_round", return_value=({}, {"error": "stop-test"})),
        patch.object(analyst.telemetry, "record"),
    ):
        analyst.investigate(
            run_id="test-g13-ok",
            alert_context=_ALERT_CONTEXT,
            max_loops=1,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )

    assert len(calls) == 1, f"Valid plan must cause exactly 1 _ask call, got {len(calls)}"
