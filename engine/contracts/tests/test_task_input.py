"""The task file the Analyst side hands down to the Broker.

`RECEIVED_TEMPLATE` below is the template **verbatim as it was received**, not a
fixture written to suit the model. That is the point of it: the first thing this
contract has to do is accept the real artifact unchanged, and a hand-tuned copy
would prove nothing about that. Anything the loader needs that the template does
not carry (`schema_version`) must therefore be optional, and every field it does
carry must be spelled the producer's way.

The round-trip against a hand-built `BENCHMARK_CASES` task lives in
`backend/tests/test_task_file.py` instead of here, because `bench.py` is in the
backend and this package is one of its dependencies -- importing it from here
would invert the dependency.
"""

from __future__ import annotations

import json

import pytest
from contracts import TaskInputFile
from pydantic import ValidationError

RECEIVED_TEMPLATE = json.loads(r"""
{
  "tasks": [
    {
      "task_id": "T1",
      "hypothesis_id": "H1",
      "question": "Did process Image= \"chrome.exe\" or \"firefox.exe\" on BSTOLL-L execute command line containing \"coinhive\" without explicit user consent?",
      "entity": { "type": "host", "value": "BSTOLL-L" },
      "time_window": {
        "start": "2026-09-01T12:29:02.448Z",
        "end": "2026-09-01T14:29:02.448Z"
      }
    },
    {
      "task_id": "T2",
      "hypothesis_id": "H2",
      "question": "Is process Image= \"chrome.exe\" or \"firefox.exe\" on BSTOLL-L executing \"coinhive\" part of a security tool's legitimate scan or developer activity?",
      "entity": { "type": "host", "value": "BSTOLL-L" },
      "time_window": {
        "start": "2026-09-01T12:29:02.448Z",
        "end": "2026-09-01T14:29:02.448Z"
      }
    },
    {
      "task_id": "T3",
      "hypothesis_id": "H3",
      "question": "Does bostoll have written authorization for cryptocurrency mining on BSTOLL-L?",
      "entity": { "type": "user", "value": "bostoll" },
      "time_window": {
        "start": "2026-09-01T12:29:02.448Z",
        "end": "2026-09-01T14:29:02.448Z"
      }
    }
  ]
}
""")


def one_task(**overrides) -> dict:
    """A single-task file built from the received template's first entry."""
    return {"tasks": [{**RECEIVED_TEMPLATE["tasks"][0], **overrides}]}


class TestTheReceivedTemplateLoadsUnchanged:
    def test_it_validates_verbatim(self):
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        assert [t.task_id for t in parsed.tasks] == ["T1", "T2", "T3"]
        assert [t.hypothesis_id for t in parsed.tasks] == ["H1", "H2", "H3"]

    def test_schema_version_defaults_because_the_template_omits_it(self):
        """The field exists for a future producer to bump; a file sent today has
        no such key and must still load."""
        assert "schema_version" not in RECEIVED_TEMPLATE
        assert TaskInputFile.model_validate(RECEIVED_TEMPLATE).schema_version == 1

    def test_order_is_preserved(self):
        """Results are reported in the order the producer wrote the tasks."""
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        assert [t.task_id for t in parsed.analyst_tasks()] == ["T1", "T2", "T3"]


class TestTheMappingOntoAnalystTask:
    def test_question_becomes_the_goal(self):
        task = TaskInputFile.model_validate(RECEIVED_TEMPLATE).analyst_tasks()[2]

        assert task.goal == RECEIVED_TEMPLATE["tasks"][2]["question"]

    def test_the_ids_cross_unchanged(self):
        task = TaskInputFile.model_validate(RECEIVED_TEMPLATE).analyst_tasks()[0]

        assert (task.task_id, task.hypothesis_id) == ("T1", "H1")

    def test_entity_type_becomes_entity_kind(self):
        tasks = TaskInputFile.model_validate(RECEIVED_TEMPLATE).analyst_tasks()

        assert [(e.kind, e.value) for e in tasks[0].scope.entities] == [("host", "BSTOLL-L")]
        assert [(e.kind, e.value) for e in tasks[2].scope.entities] == [("user", "bostoll")]

    def test_the_window_becomes_an_aware_ordered_tuple(self):
        window = TaskInputFile.model_validate(RECEIVED_TEMPLATE).analyst_tasks()[0].scope.time_window
        start, end = window

        assert start.tzinfo is not None and end.tzinfo is not None
        assert start < end
        assert start.isoformat() == "2026-09-01T12:29:02.448000+00:00"

    def test_the_hypothesis_prose_is_not_a_field_on_the_task(self):
        """`question` is the hypothesis, and it crosses as `goal` and nothing else.

        The analysis tier receives the prose as a separate argument
        (`gather(hypothesis=...)`) purely as the attachment point on the finished
        record. An `AnalystTask` field carrying it would be the first step in
        undoing the blindness that tier rests on, so the field set is pinned here
        as well as in `test_analyst_task.py`.
        """
        task = TaskInputFile.model_validate(RECEIVED_TEMPLATE).analyst_tasks()[0]

        assert set(type(task).model_fields) == {
            "schema_version", "task_id", "hypothesis_id", "goal", "scope"
        }


class TestEntityAcceptsOneOrMany:
    def test_a_single_object_is_the_template_form(self):
        task = TaskInputFile.model_validate(one_task()).analyst_tasks()[0]

        assert len(task.scope.entities) == 1

    def test_a_list_expresses_a_multi_vector_task(self):
        """The single-entity form cannot express a real multi-vector case, which
        is what the round-trip test in the backend needs."""
        parsed = TaskInputFile.model_validate(one_task(entity=[
            {"type": "user", "value": "bostoll"},
            {"type": "host", "value": "BSTOLL-L"},
            {"type": "domain", "value": "coinhive.com"},
        ]))

        assert [(e.kind, e.value) for e in parsed.analyst_tasks()[0].scope.entities] == [
            ("user", "bostoll"),
            ("host", "BSTOLL-L"),
            ("domain", "coinhive.com"),
        ]

    def test_an_empty_list_is_refused(self):
        """`Scope.entities` has `min_length=1` -- a task with no observable in
        scope is not a scope, it is an unbounded search."""
        with pytest.raises(ValidationError):
            TaskInputFile.model_validate(one_task(entity=[]))


class TestTheContractGuaranteesTheBrokerReliesOn:
    """Each of these is depended on somewhere downstream, so each is pinned."""

    def test_a_task_without_a_question_is_refused(self):
        """The guarantee that lets `smartops.main` run the analysis tier
        unconditionally for file input: a task file has no "no hypothesis" case,
        unlike the legacy `--hypothesis` flag."""
        without = {k: v for k, v in RECEIVED_TEMPLATE["tasks"][0].items() if k != "question"}

        with pytest.raises(ValidationError):
            TaskInputFile.model_validate({"tasks": [without]})

    def test_an_empty_question_is_refused_by_name(self):
        """Reported against `question`, the producer's field name, rather than
        only against `goal`, which is ours and which they have never seen."""
        with pytest.raises(ValidationError, match="question"):
            TaskInputFile.model_validate(one_task(question=""))

    def test_a_file_with_no_tasks_is_refused(self):
        with pytest.raises(ValidationError):
            TaskInputFile.model_validate({"tasks": []})

    @pytest.mark.parametrize("bad_type", ["md5", "sha256", "hostname", "account", "email"])
    def test_an_entity_kind_outside_the_closed_seven_is_refused(self, bad_type):
        """Not coerced, not guessed. `EntityKind` is what decides which domains
        can be dispatched at all, so a name we do not recognise has to fail
        loudly -- and the message names all seven so the producer can fix it."""
        with pytest.raises(ValidationError) as exc:
            TaskInputFile.model_validate(one_task(entity={"type": bad_type, "value": "x"}))

        message = str(exc.value)
        for kind in ("host", "user", "ip", "file_hash", "domain", "url", "process"):
            assert kind in message


class TestRulesAreDelegatedToTheValidatorsThatOwnThem:
    """These all fail at *load*, but none of the rules is restated in this module.

    `TaskInputFile._every_task_converts` builds each `AnalystTask` while the file
    is being validated, so `Entity` and `Scope` do the rejecting. That is what
    keeps a second copy of each rule from existing here and drifting from the
    original -- and these tests are what prove the delegation actually runs.
    """

    def test_a_naive_window_is_refused(self):
        with pytest.raises(ValidationError, match="timezone-aware"):
            TaskInputFile.model_validate(one_task(time_window={
                "start": "2018-08-20T00:00:00", "end": "2018-08-21T00:00:00",
            }))

    def test_an_inverted_window_is_refused(self):
        with pytest.raises(ValidationError, match="start must be before end"):
            TaskInputFile.model_validate(one_task(time_window={
                "start": "2018-08-21T00:00:00Z", "end": "2018-08-20T00:00:00Z",
            }))

    def test_a_blank_entity_value_is_refused(self):
        with pytest.raises(ValidationError, match="must not be blank"):
            TaskInputFile.model_validate(one_task(entity={"type": "host", "value": "   "}))

    def test_an_entity_value_carrying_a_prompt_fence_is_refused(self):
        with pytest.raises(ValidationError, match="prompt fence"):
            TaskInputFile.model_validate(
                one_task(entity={"type": "host", "value": "BSTOLL-L<script>"})
            )

    def test_the_failing_task_is_named_by_id(self):
        """A file holds several tasks and pydantic's own path says `tasks.1.…`,
        which tells an operator the index but not which hypothesis to go fix."""
        with pytest.raises(ValidationError, match="T2"):
            TaskInputFile.model_validate({"tasks": [
                RECEIVED_TEMPLATE["tasks"][0],
                {**RECEIVED_TEMPLATE["tasks"][1], "entity": {"type": "host", "value": " "}},
            ]})


class TestDuplicateIdsAreRefusedBeforeAnythingRuns:
    """Neither id is positional, so a duplicate does not collide loudly -- it
    interleaves two tasks into one set of records. See the validator's docstring
    for what each one breaks."""

    def test_a_duplicate_task_id_is_refused(self):
        with pytest.raises(ValidationError, match="duplicate task_id"):
            TaskInputFile.model_validate({"tasks": [
                RECEIVED_TEMPLATE["tasks"][0],
                {**RECEIVED_TEMPLATE["tasks"][1], "task_id": "T1"},
            ]})

    def test_a_duplicate_hypothesis_id_is_refused(self):
        with pytest.raises(ValidationError, match="duplicate hypothesis_id"):
            TaskInputFile.model_validate({"tasks": [
                RECEIVED_TEMPLATE["tasks"][0],
                {**RECEIVED_TEMPLATE["tasks"][1], "hypothesis_id": "H1"},
            ]})

    def test_the_received_template_has_neither(self):
        """Guards the fixture itself: if the real template ever did repeat an id,
        every test above would be exercising a file the loader rejects."""
        tasks = RECEIVED_TEMPLATE["tasks"]

        assert len({t["task_id"] for t in tasks}) == len(tasks)
        assert len({t["hypothesis_id"] for t in tasks}) == len(tasks)


class TestSelectingASubset:
    def test_no_ids_selects_everything(self):
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        assert [t.task_id for t in parsed.select(None)] == ["T1", "T2", "T3"]
        assert [t.task_id for t in parsed.select([])] == ["T1", "T2", "T3"]

    def test_one_id_selects_that_task(self):
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        assert [t.task_id for t in parsed.select(["T2"])] == ["T2"]

    def test_the_result_is_in_file_order_not_request_order(self):
        """So two invocations naming the same set cannot report differently
        ordered output."""
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        assert [t.task_id for t in parsed.select(["T3", "T1"])] == ["T1", "T3"]

    def test_an_unknown_id_raises_rather_than_running_a_subset(self):
        """A typo'd `--task-id` would otherwise be indistinguishable from a task
        the file does not hold, and the run would report success having
        investigated nothing."""
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        with pytest.raises(ValueError, match="T9"):
            parsed.select(["T9"])

    def test_the_error_lists_what_the_file_does_hold(self):
        parsed = TaskInputFile.model_validate(RECEIVED_TEMPLATE)

        with pytest.raises(ValueError, match="T1, T2, T3"):
            parsed.select(["nope"])


class TestATaskFileCannotEscapeTheRunsDirectory:
    """The delegation in `_every_task_converts` is what enforces this, so it is
    asserted at the task-file level too rather than only on `AnalystTask`.

    A task file is written by another team and read off disk, which makes it the
    one place a hostile or merely careless `task_id` can enter -- and `task_id`
    becomes a directory name. See `AnalystTask._ids_are_path_safe`.
    """

    @pytest.mark.parametrize(
        "bad", ["../../etc/passwd", "..", "a/b", "a\b", "has:colon", ".hidden"]
    )
    def test_an_unsafe_task_id_is_refused_at_load(self, bad):
        with pytest.raises(ValidationError):
            TaskInputFile.model_validate(one_task(task_id=bad))

    @pytest.mark.parametrize("bad", ["../../etc/passwd", "a/b", "has:colon"])
    def test_an_unsafe_hypothesis_id_is_refused_at_load(self, bad):
        with pytest.raises(ValidationError):
            TaskInputFile.model_validate(one_task(hypothesis_id=bad))

    def test_the_offending_task_is_named(self):
        with pytest.raises(ValidationError, match="T1"):
            TaskInputFile.model_validate(one_task(task_id="../evil"))

    def test_the_received_template_and_example_ids_are_safe(self):
        """Guards the fixture: every id in the real template must pass, or the
        rule is wrong rather than the input."""
        TaskInputFile.model_validate(RECEIVED_TEMPLATE)
