from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from contracts import AnalystTask, Entity, Scope, TaskClassification


def make_scope(**overrides):
    now = datetime(2026, 8, 9, tzinfo=timezone.utc)
    defaults = dict(
        entities=[Entity(kind="host", value="host-1")],
        time_window=(now - timedelta(hours=1), now),
    )
    return Scope(**{**defaults, **overrides})


def make_task(**overrides):
    defaults = dict(
        task_id="t1",
        hypothesis_id="h1",
        goal="did host-1 execute a malicious binary",
        scope=make_scope(),
    )
    return AnalystTask(**{**defaults, **overrides})


class TestAnalystTask:
    def test_valid_task(self):
        task = make_task()
        assert task.goal == "did host-1 execute a malicious binary"
        assert task.scope.entities == [Entity(kind="host", value="host-1")]
        assert task.schema_version == 1

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError):
            AnalystTask(hypothesis_id="h1", goal="check something", scope=make_scope())  # missing task_id

    def test_empty_goal_rejected(self):
        with pytest.raises(ValidationError):
            make_task(goal="")

    def test_no_tool_specific_fields(self):
        # the whole point of this contract: it must never grow a field that
        # names a product, index, or tool -- only what the Analyst can specify.
        # `schema_version` is metadata, not intent: this is the Analyst -> Broker
        # interface and its producer doesn't exist yet, so extension by the
        # producer has to be a versioned event rather than a break.
        assert set(AnalystTask.model_fields) == {
            "schema_version",
            "task_id",
            "hypothesis_id",
            "goal",
            "scope",
        }


class TestTaskClassification:
    def test_valid_classification(self):
        classification = TaskClassification(tool_families=["edr", "vt"], rationale="mentions a host and a hash")
        assert classification.tool_families == ["edr", "vt"]

    def test_empty_tool_families_is_valid(self):
        # a task can be unworkable for every known domain -- not an error.
        classification = TaskClassification(tool_families=[], rationale="no domain-relevant indicators")
        assert classification.tool_families == []

    def test_tool_families_defaults_to_empty(self):
        classification = TaskClassification(rationale="nothing to classify")
        assert classification.tool_families == []

    def test_invalid_tool_family_rejected(self):
        with pytest.raises(ValidationError):
            TaskClassification(tool_families=["not-a-real-family"], rationale="oops")

    def test_missing_rationale_rejected(self):
        with pytest.raises(ValidationError):
            TaskClassification(tool_families=["edr"])
