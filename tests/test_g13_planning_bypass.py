"""G13: Analyst must never accept an evaluation-shaped answer in Loop 1 as a verdict.

If the model answers with hypothesis_scores / VERDICT_REACHED instead of a plan,
the code must re-ask once. If the re-ask also fails, it must abort with an error —
never emit a verdict before the Broker has run.
"""

import json
import queue
import threading
from unittest.mock import MagicMock, patch

import pytest

from smartops import analyst


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
        patch.object(analyst.telemetry, "record"),
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

    # The re-ask message must warn the model it was in eval format
    assert "EVALUATION format" in calls[1], "Re-ask message must mention EVALUATION format"

    # No direct 'verdict' event before broker
    assert "verdict" not in types, (
        f"A 'verdict' event must NOT be emitted before the Broker runs. Events: {types}"
    )

    # Re-ask message should include [SYSTEM] correction
    assert "[SYSTEM]" in calls[1]


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
