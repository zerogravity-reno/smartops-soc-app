"""Tests for Analyst edge cases T23, T28, T29, T30, G4, and Issue 1.2."""

import pytest
from contracts import TaskInputFile
from smartops import analyst


# ── T28 ─────────────────────────────────────────────────────────────────────

def test_t28_gaps_as_string_does_not_split_into_character_tasks():
    """T28: If synthesis outputs evidence_gaps as a string instead of a list of strings,
    follow_up_tasks must not create one task per character."""
    sent = [{
        "task_id": "T1",
        "question": "What happened?",
        "entity": [{"type": "host", "value": "WIN01"}],
        "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
    }]
    gaps_str = "Who executed svcupdate.dat?"

    tasks = analyst.follow_up_tasks(follow_ups=[], sent=sent, gaps=gaps_str)

    # Must produce exactly 1 task with the whole string, NOT 27 character tasks
    assert len(tasks) == 1
    assert tasks[0]["question"] == "Who executed svcupdate.dat?"
    assert tasks[0]["task_id"] == "G1"


# ── T29 ─────────────────────────────────────────────────────────────────────

def test_t29_duplicate_task_ids_are_disambiguated():
    """T29: If follow-ups contain duplicate task_id values, to_task_file must
    make them unique so TaskInputFile.model_validate passes."""
    tasks = [
        {
            "task_id": "FU1",
            "question": "Question 1",
            "entity": {"type": "host", "value": "WIN01"},
            "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
        },
        {
            "task_id": "FU1",  # duplicate ID
            "question": "Question 2",
            "entity": {"type": "host", "value": "WIN01"},
            "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
        },
    ]

    task_file, dropped = analyst.to_task_file(tasks, run_id="run-1", loop=2)

    # TaskInputFile validation must succeed without duplicate error
    validated = TaskInputFile.model_validate(task_file)
    task_ids = [t.task_id for t in validated.tasks]

    assert len(task_ids) == 2
    assert len(set(task_ids)) == 2
    assert task_ids[0] == "run-1-L2-FU1"
    assert task_ids[1] == "run-1-L2-FU1_2"


# ── T30 ─────────────────────────────────────────────────────────────────────

def test_t30_task_ids_are_sanitized_against_traversals_and_colons():
    """T30: Task IDs containing path traversal or colons are sanitized."""
    tasks = [
        {
            "task_id": "../../bad_dir",
            "question": "Traversal test",
            "entity": {"type": "host", "value": "WIN01"},
            "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
        },
        {
            "task_id": "T1:endpoint",
            "question": "Colon test",
            "entity": {"type": "host", "value": "WIN01"},
            "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
        },
    ]

    task_file, dropped = analyst.to_task_file(tasks, run_id="run-2", loop=2)
    validated = TaskInputFile.model_validate(task_file)
    task_ids = [t.task_id for t in validated.tasks]

    assert ".." not in task_ids[0]
    assert "/" not in task_ids[0]
    assert ":" not in task_ids[1]
    assert task_ids[0] == "run-2-L2-______bad_dir"
    assert task_ids[1] == "run-2-L2-T1_endpoint"


def test_t30_long_task_id_is_bounded_to_128_chars():
    """T30: A model task_id of 128 characters must not produce a final id longer than 128 chars.
    TaskInputFile must accept it (it was rejecting 140-char ids)."""
    long_id = "X" * 128  # model returns a full 128-char id
    tasks = [{
        "task_id": long_id,
        "question": "Long ID test",
        "entity": {"type": "host", "value": "WIN01"},
        "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
    }]

    task_file, dropped = analyst.to_task_file(tasks, run_id="run-3", loop=1)
    validated = TaskInputFile.model_validate(task_file)
    final_id = validated.tasks[0].task_id

    assert len(final_id) <= 128, f"task_id too long: {len(final_id)} chars: {final_id!r}"


# ── T23 ─────────────────────────────────────────────────────────────────────

def test_t23_event_time_is_converted_to_utc():
    """T23: _instant converts a timezone-aware event_time to UTC correctly.
    13:50:45+02:00 must become 11:50:45Z, not be passed through as-is."""
    from smartops.context import _instant
    from datetime import timezone

    dt = _instant("2026-10-06T13:50:45+02:00")
    assert dt is not None
    utc_str = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert utc_str == "2026-10-06T11:50:45Z", f"Expected UTC 11:50:45Z, got {utc_str}"


# ── Issue 1.2 ────────────────────────────────────────────────────────────────

def test_issue_12_unanswerable_question_not_re_asked():
    """Issue 1.2: A question the broker marked unanswerable must be treated as 'already asked'
    and not re-submitted as a follow-up in the next round."""
    sent = [{
        "task_id": "T1",
        "question": "Is 192.168.1.5 registered in CMDB?",
        "entity": [{"type": "ip", "value": "192.168.1.5"}],
        "time_window": {"start": "2026-10-01T10:00:00Z", "end": "2026-10-01T12:00:00Z"},
    }]
    # The broker returned this as unanswerable (CMDB not connected)
    unanswerable_as_tasks = [
        {"question": "Is 192.168.1.5 registered in CMDB?", "entity": [], "time_window": None}
    ]
    # Synthesis wants to re-ask the same question
    follow_ups = [{
        "task_id": "FU1",
        "question": "Is 192.168.1.5 registered in CMDB?",
    }]

    tasks = analyst.follow_up_tasks(
        follow_ups=follow_ups,
        sent=sent,
        asked=sent + unanswerable_as_tasks,
    )

    # The unanswerable question must be dropped — not re-sent
    assert len(tasks) == 0, f"Expected 0 tasks, got {len(tasks)}: {tasks}"
