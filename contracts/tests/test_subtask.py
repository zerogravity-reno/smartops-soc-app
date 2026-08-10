from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from contracts import (
    Evidence,
    Scope,
    SubagentAnswer,
    SubagentMission,
    SubtaskResult,
    SubtaskStatus,
)


def make_scope(**overrides):
    now = datetime(2026, 8, 4, tzinfo=timezone.utc)
    defaults = dict(entities=["host-1"], time_window=(now - timedelta(hours=1), now))
    return Scope(**{**defaults, **overrides})


def make_mission(**overrides):
    defaults = dict(
        task_id="t1",
        hypothesis_id="h1",
        tool_family="edr",
        goal="check for lateral movement from host-1",
        scope=make_scope(),
    )
    return SubagentMission(**{**defaults, **overrides})


class TestScope:
    def test_valid_scope(self):
        scope = make_scope()
        assert scope.entities == ["host-1"]

    def test_empty_entities_rejected(self):
        with pytest.raises(ValidationError):
            make_scope(entities=[])

    def test_blank_entity_rejected(self):
        with pytest.raises(ValidationError):
            make_scope(entities=["host-1", ""])

    def test_whitespace_only_entity_rejected(self):
        with pytest.raises(ValidationError):
            make_scope(entities=["   "])

    def test_inverted_time_window_rejected(self):
        now = datetime(2026, 8, 4, tzinfo=timezone.utc)
        with pytest.raises(ValidationError):
            make_scope(time_window=(now, now - timedelta(hours=1)))

    def test_naive_datetime_rejected(self):
        now = datetime(2026, 8, 4)  # no tzinfo
        with pytest.raises(ValidationError):
            make_scope(time_window=(now - timedelta(hours=1), now))


class TestSubagentMission:
    def test_valid_mission(self):
        mission = make_mission()
        assert mission.tool_family == "edr"
        assert mission.schema_version == 1
        assert mission.budget_cost == 1

    def test_invalid_tool_family_rejected(self):
        with pytest.raises(ValidationError):
            make_mission(tool_family="not-a-real-tool")

    def test_empty_goal_rejected(self):
        with pytest.raises(ValidationError):
            make_mission(goal="")

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError):
            SubagentMission(
                hypothesis_id="h1",
                tool_family="edr",
                goal="check for lateral movement",
                scope=make_scope(),
            )  # missing task_id

    def test_mission_carries_no_preauthored_tool_call(self):
        # the contract must never grow fields that let upstream code pre-author
        # the exact tool action/parameters -- only goal + scope are allowed.
        assert set(SubagentMission.model_fields) == {
            "schema_version",
            "task_id",
            "hypothesis_id",
            "tool_family",
            "goal",
            "scope",
            "context",
            "budget_cost",
        }


class TestSubagentAnswer:
    def test_error_status_requires_error_message(self):
        with pytest.raises(ValidationError):
            SubagentAnswer(status=SubtaskStatus.ERROR, summary="failed")

    def test_non_error_status_forbids_error_message(self):
        with pytest.raises(ValidationError):
            SubagentAnswer(status=SubtaskStatus.OK, summary="fine", error="oops")

    def test_ok_answer(self):
        answer = SubagentAnswer(status=SubtaskStatus.OK, summary="found 1 alert", citation_ids=["ev-1"])
        assert answer.citation_ids == ["ev-1"]


class TestSubtaskResult:
    def test_from_answer_assembles_result(self):
        now = datetime(2026, 8, 4, tzinfo=timezone.utc)
        evidence = [Evidence(id="ev-1", tool_family="edr", raw={"pid": 123}, collected_at=now)]
        answer = SubagentAnswer(status=SubtaskStatus.OK, summary="found 1 alert", citation_ids=["ev-1"])

        result = SubtaskResult.from_answer(task_id="t1", answer=answer, evidence=evidence)

        assert result.task_id == "t1"
        assert result.evidence == evidence
        assert result.citation_ids == ["ev-1"]

    def test_dangling_citation_rejected(self):
        with pytest.raises(ValidationError):
            SubtaskResult(
                task_id="t1",
                status=SubtaskStatus.OK,
                summary="found 1 alert",
                citation_ids=["ev-does-not-exist"],
                evidence=[],
            )

    def test_duplicate_evidence_ids_rejected(self):
        now = datetime(2026, 8, 4, tzinfo=timezone.utc)
        dupes = [
            Evidence(id="ev-1", tool_family="edr", raw={"a": 1}, collected_at=now),
            Evidence(id="ev-1", tool_family="edr", raw={"a": 2}, collected_at=now),
        ]
        with pytest.raises(ValidationError):
            SubtaskResult(task_id="t1", status=SubtaskStatus.OK, summary="found 1 alert", evidence=dupes)

    def test_raw_evidence_never_required_in_summary(self):
        # regression guard: nothing about the schema requires (or lets) raw tool
        # output to be embedded in `summary` -- only a digest + citation ids.
        assert "raw" not in SubagentAnswer.model_fields
