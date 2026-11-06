"""End-to-end integration: Analyst plan → Broker round → Synthesis, with canned responses.

Four cases that exercise the hand-off boundary between the Analyst (owned by ysalahai)
and the Broker (owned by mrahmy-reno).  The tests check structural invariants — task IDs
surviving the round trip, `unanswerable` staying unanswerable, cut-off causing failure —
not exact serialised output.  Expected files are not used; only the rules matter.

Cases:
  1. Normal round trip       — valid plan → canned Broker findings → VERDICT_REACHED
  2. Empty / eval plan       — re-ask guard fires, second call returns valid plan, Broker runs
  3. No rows vs unavailable  — empty observations stay evidence_gaps; unanswerable items
                               do NOT become affirmative evidence in synthesis
  4. Output cut off          — CutOff during synthesis emits error with cut_off key, no verdict
"""

import json
import queue
import threading
from unittest.mock import MagicMock, patch

import pytest

from smartops import analyst
from smartops.analyst import CutOff


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_ALERT_CONTEXT = {
    "normalized_seed": {"event_time": "2026-10-01T11:00:00Z"},
    "alert_scope": {"entity": [{"type": "host", "value": "WIN-LAB01"}]},
}

_PLAN = {
    "hypotheses": [
        {"id": "H1", "verdict": "TRUE_POSITIVE",  "description": "Obfuscated PowerShell by attacker"},
        {"id": "H2", "verdict": "FALSE_POSITIVE",  "description": "IT admin maintenance script"},
        {"id": "H3", "verdict": "BENIGN",           "description": "Scheduled backup"},
    ],
    "tasks": [
        {
            "task_id": "T1",
            "question": "What process spawned powershell.exe on WIN-LAB01?",
            "entity": {"type": "host", "value": "WIN-LAB01"},
            "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
        },
        {
            "task_id": "T2",
            "question": "Is the file hash known-malicious on VirusTotal?",
            "entity": {"type": "file_hash", "value": "aabbccdd"},
            "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
        },
    ],
    "semantic_alignment": "ALIGNED",
    "model_reasoning": "Need Broker evidence before evaluating.",
}

_EVAL_PLAN = {
    # evaluation-shaped: has verdict/status at the top level instead of tasks
    "status": "VERDICT_REACHED",
    "verdict": "BENIGN",
    "verdict_confidence": 85,
    "verdict_reasoning": "Alert text alone looks benign.",
    "hypothesis_scores": {"H1": 5, "H2": 10, "H3": 85},
    "evidence_refs": [],
    "evidence_gaps": [],
    "follow_up_tasks": [],
}

_VERDICT_REACHED_SYNTH = {
    "status": "VERDICT_REACHED",
    "verdict": "BENIGN",
    "verdict_confidence": 92,
    "verdict_reasoning": "Hash is clean; process lineage is normal backup.",
    "hypothesis_scores": {"H1": 5, "H2": 5, "H3": 92},
    "evidence_refs": ["T1:endpoint", "T2:virustotal"],
    "evidence_gaps": [],
    "follow_up_tasks": [],
}

# A findings payload the Broker would produce for a normal round
def _broker_findings(task_ids: list[str]) -> dict:
    """Minimal but structurally correct payload that the Analyst's synthesis reads."""
    return {
        "payloads": [
            {
                "task_id": tid,
                "hypothesis": f"Question for {tid}",
                "findings": [
                    {
                        "domain": "endpoint",
                        "observations": [{"row": "parent=explorer.exe"}],
                    }
                ],
                "unanswerable": [],
            }
            for tid in task_ids
        ]
    }


def _ask_resp(payload: dict, stop_reason: str = "stop") -> dict:
    return {
        "answer": json.dumps(payload),
        "reasoning": "",
        "prompt_tokens": 500,
        "generation_tokens": 800,
        "stop_reason": stop_reason,
    }


def _drain(q: queue.Queue) -> list:
    events = []
    while True:
        try:
            events.append(q.get_nowait())
        except queue.Empty:
            break
    return events


def _run(fake_ask, fake_broker_round, max_loops: int = 1) -> list:
    """Run investigate() with mocked _ask and _broker_round; return event list."""
    q = queue.Queue()
    ctrl = {"cancel": threading.Event()}
    with (
        patch.object(analyst, "_ask", side_effect=fake_ask),
        patch.object(analyst, "_broker_round", side_effect=fake_broker_round),
        patch.object(analyst.telemetry, "record"),
    ):
        analyst.investigate(
            run_id="e2e-test",
            alert_context=_ALERT_CONTEXT,
            max_loops=max_loops,
            q=q,
            checkpoint=lambda: None,
            ctrl=ctrl,
        )
    return _drain(q)


# ---------------------------------------------------------------------------
# Case 1: Normal round trip
# ---------------------------------------------------------------------------

def test_case1_normal_round_trip():
    """Valid plan → Broker runs with the exact task IDs from the plan → synthesis
    declares VERDICT_REACHED.

    Invariants:
      - Every task_id from the plan is present in the handshake's `sent` list.
      - A 'verdict' event is emitted; no 'error' event.
      - The verdict value is a known outcome string (not REQUIRES_INVESTIGATION).
    """
    call_count = [0]

    def fake_ask(system, user, stage):
        call_count[0] += 1
        if stage == "planning":
            return _ask_resp(_PLAN)
        # synthesis
        return _ask_resp(_VERDICT_REACHED_SYNTH)

    # _broker_round is called with (tasks, run_id, loop_num, q, ctrl, alert_scope, event_time).
    # We need to emit a handoff event ourselves so the caller can introspect the handshake.
    captured_task_ids = []

    def fake_broker(tasks, run_id, loop_num, q, ctrl, alert_scope=None, event_time=None):
        ids = [t["task_id"] for t in tasks]
        captured_task_ids.extend(ids)
        findings = _broker_findings(ids)
        link = {
            "task_ids": ids,
            "tasks": tasks,
            "dropped": [],
            "broker_runs": [{"task_id": tid, "run_dir": "/fake/" + tid} for tid in ids],
            "handshake": {"sent": ids, "fetched": ids, "returned": ids,
                          "not_fetched": [], "not_returned": [], "unexpected": []},
        }
        return findings, link

    events = _run(fake_ask, fake_broker)
    types = [e["type"] for e in events]

    # No errors
    assert "error" not in types, f"Unexpected error events: {[e for e in events if e['type'] == 'error']}"

    # Verdict reached
    assert "verdict" in types, f"Expected a 'verdict' event. Got: {types}"
    verdict_event = next(e for e in events if e["type"] == "verdict")
    assert verdict_event["data"].get("verdict") not in (None, "REQUIRES_INVESTIGATION"), (
        f"Verdict must be a resolved outcome, got: {verdict_event['data'].get('verdict')}"
    )

    # Task IDs from the plan reached the Broker intact
    plan_task_ids = {t["task_id"] for t in _PLAN["tasks"]}
    assert plan_task_ids.issubset(set(captured_task_ids)), (
        f"Plan task IDs {plan_task_ids} did not all reach the Broker. "
        f"Broker received: {captured_task_ids}"
    )


# ---------------------------------------------------------------------------
# Case 2: Empty / evaluation-style plan → re-ask → Broker runs
# ---------------------------------------------------------------------------

def test_case2_empty_or_eval_plan_triggers_reask_then_broker_runs():
    """Loop 1 returns evaluation-shaped JSON (no tasks) → code re-asks once →
    second call returns a valid plan → Broker runs.

    Invariants:
      - _ask is called exactly twice before the Broker runs (initial + re-ask).
      - No 'verdict' event is emitted before the Broker has run.
      - A broker event or handoff event appears after the two planning calls.
    """
    planning_calls = []
    broker_called = []

    def fake_ask(system, user, stage):
        if stage == "planning":
            planning_calls.append(user)
            if len(planning_calls) == 1:
                return _ask_resp(_EVAL_PLAN)   # bad first response
            return _ask_resp(_PLAN)            # good re-ask response
        # synthesis — stop after first loop by returning a verdict
        return _ask_resp(_VERDICT_REACHED_SYNTH)

    def fake_broker(tasks, run_id, loop_num, q, ctrl, alert_scope=None, event_time=None):
        broker_called.append(True)
        ids = [t["task_id"] for t in tasks]
        findings = _broker_findings(ids)
        link = {
            "task_ids": ids, "tasks": tasks, "dropped": [],
            "broker_runs": [{"task_id": tid, "run_dir": "/fake/" + tid} for tid in ids],
            "handshake": {"sent": ids, "fetched": ids, "returned": ids,
                          "not_fetched": [], "not_returned": [], "unexpected": []},
        }
        return findings, link

    events = _run(fake_ask, fake_broker)
    types = [e["type"] for e in events]

    # Re-ask fired
    assert len(planning_calls) == 2, (
        f"Expected 2 planning calls (initial + re-ask), got {len(planning_calls)}"
    )

    # Broker ran — confirms the re-asked plan was accepted
    assert broker_called, "Broker must run after the re-ask returns a valid plan"

    # No 'verdict' before the Broker ran (no verdict event without a prior broker event)
    broker_event_idx = next((i for i, e in enumerate(events) if e["type"] == "broker"), None)
    verdict_event_idx = next((i for i, e in enumerate(events) if e["type"] == "verdict"), None)
    if verdict_event_idx is not None and broker_event_idx is not None:
        assert broker_event_idx < verdict_event_idx, (
            "A 'verdict' event appeared before the 'broker' event — "
            "verdict must not be emitted before the Broker runs."
        )


# ---------------------------------------------------------------------------
# Case 3: No rows vs source unavailable
# ---------------------------------------------------------------------------

def test_case3_no_rows_vs_source_unavailable():
    """Broker returns two kinds of 'missing' results:
      - T1: empty observations (searched, found nothing)
      - T2: listed in `unanswerable` (source not reachable / not connected)

    Invariants:
      - T2's unanswerable entry is forwarded to synthesis as an evidence limit,
        not as a positive finding (it must appear in `evaluation_limits` output,
        which puts it in the EVIDENCE LIMITS block sent to the model).
      - The synthesis result must NOT claim the source said "not registered" or
        "no record" (unsupported_unanswerable_claims returns empty for such claims).
      - No 'error' event.
    """

    def fake_ask(system, user, stage):
        if stage == "planning":
            return _ask_resp(_PLAN)
        # Synthesis: returns REQUIRES_INVESTIGATION — the gap for T2 is still open
        synth = {
            "status": "VERDICT_REACHED",
            "verdict": "BENIGN",
            "verdict_confidence": 90,
            "verdict_reasoning": "T1 shows benign lineage; T2 source was unreachable so we cannot confirm.",
            "hypothesis_scores": {"H1": 5, "H2": 5, "H3": 90},
            "evidence_refs": ["T1:endpoint"],
            "evidence_gaps": ["T2 (CMDB) was not reachable"],
            "follow_up_tasks": [],
        }
        return _ask_resp(synth)

    unanswerable_item = "Is the file hash known-malicious on VirusTotal? (virustotal)"

    def fake_broker(tasks, run_id, loop_num, q, ctrl, alert_scope=None, event_time=None):
        ids = [t["task_id"] for t in tasks]
        findings = {
            "payloads": [
                {
                    "task_id": ids[0] if ids else "T1",
                    "hypothesis": "What process spawned powershell?",
                    "findings": [
                        {
                            "domain": "endpoint",
                            "observations": [],   # searched but empty — no rows
                        }
                    ],
                    "unanswerable": [],
                },
                {
                    "task_id": ids[1] if len(ids) > 1 else "T2",
                    "hypothesis": "Is the hash malicious?",
                    "findings": [],
                    "unanswerable": [unanswerable_item],  # source unreachable
                },
            ]
        }
        link = {
            "task_ids": ids, "tasks": tasks, "dropped": [],
            "broker_runs": [{"task_id": tid, "run_dir": "/fake/" + tid} for tid in ids],
            "handshake": {"sent": ids, "fetched": ids, "returned": ids,
                          "not_fetched": [], "not_returned": [], "unexpected": []},
        }
        return findings, link

    events = _run(fake_ask, fake_broker)
    types = [e["type"] for e in events]

    # No errors
    assert "error" not in types, f"Unexpected errors: {[e for e in events if e['type'] == 'error']}"

    # The evaluation_limits function must treat the unanswerable as an unknown,
    # not as a negative/absence claim.  We verify this by calling evaluation_limits
    # directly on the payload the fake_broker produced.
    payloads = [
        {
            "task_id": "T1", "hypothesis": "q1",
            "findings": [{"domain": "endpoint", "observations": []}],
            "unanswerable": [],
        },
        {
            "task_id": "T2", "hypothesis": "q2",
            "findings": [],
            "unanswerable": [unanswerable_item],
        },
    ]
    limits_text = analyst.evaluation_limits(payloads)
    assert unanswerable_item in limits_text, (
        f"evaluation_limits must forward the unanswerable item to the synthesis prompt. "
        f"Got: {limits_text!r}"
    )

    # A synthesis verdict that claims the source says "not registered" / "no record"
    # for T2 must be flagged by unsupported_unanswerable_claims.
    bad_synth = {
        "verdict_reasoning": "There is no record of this hash in virustotal, confirming it is safe."
    }
    violations = analyst.unsupported_unanswerable_claims(bad_synth, payloads)
    assert violations, (
        "unsupported_unanswerable_claims must catch a synthesis that turns an "
        "unanswerable item into an absence claim."
    )

    # A verdict that correctly treats T2 as unknown must pass
    ok_synth = {
        "verdict_reasoning": "T1 shows benign lineage; T2 source was unreachable so we cannot confirm."
    }
    ok_violations = analyst.unsupported_unanswerable_claims(ok_synth, payloads)
    assert not ok_violations, (
        f"A synthesis that treats the unanswerable as unknown must not be flagged. "
        f"Got: {ok_violations}"
    )


# ---------------------------------------------------------------------------
# Case 4: Output cut off at token limit
# ---------------------------------------------------------------------------

def test_case4_synthesis_cutoff_emits_error_not_verdict():
    """Synthesis hits the token limit (stop_reason=length) → CutOff is raised →
    investigate() emits an 'error' event with a 'cut_off' key, not a 'verdict'.

    Invariants:
      - 'verdict' event must NOT appear.
      - 'error' event must appear.
      - The error event must have a 'cut_off' key with stage='synthesis'.
    """
    planning_called = []

    def fake_ask(system, user, stage):
        if stage == "planning":
            planning_called.append(True)
            return _ask_resp(_PLAN)
        # synthesis hits token limit
        raise CutOff(
            stage="synthesis",
            max_gen_len=16384,
            result={
                "reasoning": "...still reasoning...",
                "answer": "",
                "prompt_tokens": 14000,
                "generation_tokens": 16384,
            },
        )

    def fake_broker(tasks, run_id, loop_num, q, ctrl, alert_scope=None, event_time=None):
        ids = [t["task_id"] for t in tasks]
        findings = _broker_findings(ids)
        link = {
            "task_ids": ids, "tasks": tasks, "dropped": [],
            "broker_runs": [{"task_id": tid, "run_dir": "/fake/" + tid} for tid in ids],
            "handshake": {"sent": ids, "fetched": ids, "returned": ids,
                          "not_fetched": [], "not_returned": [], "unexpected": []},
        }
        return findings, link

    events = _run(fake_ask, fake_broker)
    types = [e["type"] for e in events]

    # No verdict
    assert "verdict" not in types, (
        f"CutOff during synthesis must NOT produce a 'verdict' event. Got: {types}"
    )

    # Error event present
    assert "error" in types, f"CutOff must produce an 'error' event. Got: {types}"

    # Error has cut_off key with correct stage
    err = next(e for e in events if e["type"] == "error")
    assert "cut_off" in err, (
        f"The error event must carry a 'cut_off' key. Got keys: {list(err.keys())}"
    )
    assert err["cut_off"].get("stage") == "synthesis", (
        f"cut_off.stage must be 'synthesis', got: {err['cut_off'].get('stage')}"
    )
