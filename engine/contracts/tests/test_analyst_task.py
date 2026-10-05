from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from contracts import AnalystTask, Entity, Scope, TaskClassification


def make_scope(**overrides):
    now = datetime(2026, 8, 9, tzinfo=UTC)
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


class TestTheIdsAreSafeToUseAsPaths:
    """`task_id` becomes a directory name, so it is attacker-reachable input now.

    `broker.save_run_artifacts()` writes `<runs_dir>/<task_id>/<stamp>/` and
    `main._resolve_run_dir()` reads `<runs_dir>/<task_id>/latest.txt`. That was
    harmless while the only producer was the CLI building `cli-<timestamp>`
    itself; it stopped being harmless when `contracts.TaskInput` made `task_id`
    arrive from a JSON file written by another team.

    Measured before the rule existed: `task_id="../../etc/passwd"` validated
    fine and would have written a run directory outside the runs tree.
    """

    @pytest.mark.parametrize(
        "bad",
        [
            "../../etc/passwd",   # the traversal itself
            "..",                 # the parent directory
            ".",                  # the current directory
            ".hidden",            # a dotfile
            "a/b",                # posix separator
            "a\b",               # windows separator
            "has:colon",          # the mission-id separator
            "with space",
            "tab\there",
            "newline\nhere",
            "",                   # empty
        ],
    )
    def test_an_unsafe_task_id_is_refused(self, bad):
        with pytest.raises(ValidationError):
            make_task(task_id=bad)

    @pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "has:colon", ".."])
    def test_the_same_rule_applies_to_hypothesis_id(self, bad):
        with pytest.raises(ValidationError):
            make_task(hypothesis_id=bad)

    @pytest.mark.parametrize(
        "good",
        [
            "cli-20260902T102145",          # what the CLI mints
            "botsv3_coinhive",              # a BENCHMARK_CASES id
            "botsv3-coinhive-consent",      # the example task file
            "T1",                           # the received template
            "t1",
            "a.b",                          # an interior dot is fine
            "run.2018-08-20_v2",
        ],
    )
    def test_every_id_actually_in_use_still_validates(self, good):
        """The rule must not break anything that already exists -- the CLI's own
        format, the benchmark cases, and both task files."""
        assert make_task(task_id=good, hypothesis_id=good).task_id == good

    def test_an_over_long_id_is_refused(self):
        """A path component caps around 255 bytes, and an identifier is not a
        payload."""
        with pytest.raises(ValidationError, match="over the"):
            make_task(task_id="a" * 200)

    def test_the_message_says_why_rather_than_just_invalid(self):
        """These arrive from another team's generator, so the error has to be
        actionable without reading our source."""
        with pytest.raises(ValidationError, match="directory name"):
            make_task(task_id="../evil")

    def test_mission_ids_are_deliberately_not_held_to_this(self):
        """`SubtaskResult.task_id` holds `<task_id>:<family>:<toolUseId>`, which
        contains colons by construction. Tightening it would break both the
        mission format and reading the saved runs used as replay fixtures."""
        from contracts import SubtaskResult, SubtaskStatus

        result = SubtaskResult(task_id="t1:siem:tooluse_abc", status=SubtaskStatus.OK)

        assert result.task_id == "t1:siem:tooluse_abc"
