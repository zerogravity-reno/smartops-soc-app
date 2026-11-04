"""Tests for Analyst edge cases T23, T28, T29, and T30."""

import pytest
from contracts import TaskInputFile
from smartops import analyst


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
