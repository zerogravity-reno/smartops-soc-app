"""The file-based form of an `AnalystTask`, as the producing team sends it.

`AnalystTask` is the Analyst -> Broker interface *in memory*. This module is the
same handover **on disk**: the shape of the JSON file the Analyst side emits, one
entry per hypothesis it wants tested.

**Field names here are the producer's, not ours.** `question`, `entity`, `type`
and `time_window` are what the received template calls them, and they are spelled
that way deliberately: `contracts/schemas/task-input.v1.schema.json` is generated
from these models and published for the producing team to validate against, so
the schema has to speak their vocabulary. Every rename onto our vocabulary
happens in `TaskInput.to_analyst_task()` -- one place, explicit, rather than
scattered through field aliases where a reader cannot see the mapping at all.

**Nothing here re-implements a rule that already exists.** `to_analyst_task()`
builds the real `Entity` and `Scope`, so entity-value structure, the closed
seven-member `EntityKind`, timezone-awareness and window ordering are all
enforced by the validators that already own them. `TaskInputFile` runs that
conversion for every task at load time (see `_every_task_converts`), so a
malformed file fails when it is read rather than when it is used -- without a
second copy of any rule to drift from the first.
"""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import BaseModel, Field, ValidationError, model_validator

from contracts.analyst_task import AnalystTask
from contracts.subtask import Entity, EntityKind, Scope


class TaskEntity(BaseModel):
    """One observable in a task's scope, in the producer's spelling.

    `type` rather than `kind` because that is what the template sends. Typed as
    `EntityKind` and not `str`, so an unknown value (`md5`, `hostname`,
    `account`, `email`) is refused at load with pydantic naming all seven
    permitted members. That refusal is the point: mapping a name we do not
    recognise onto one we do would be a silent coercion of the thing that
    decides which domains can be dispatched at all.
    """

    type: EntityKind
    value: str = Field(min_length=1)

    def to_entity(self) -> Entity:
        """The contract's own `Entity`, whose validators check the value."""
        return Entity(kind=self.type, value=self.value)


class TaskTimeWindow(BaseModel):
    """A task's window as the template sends it: two named ISO 8601 instants.

    Deliberately not validated here. `Scope._window_is_ordered_and_aware` already
    rejects a naive or inverted window, and it is the one that has to be right --
    a second copy of the rule in this module could only ever disagree with it.
    `to_tuple()` feeds `Scope`, and `TaskInputFile` builds one at load so the
    rejection still happens while the file is being read.
    """

    start: datetime
    end: datetime

    def to_tuple(self) -> tuple[datetime, datetime]:
        return (self.start, self.end)


class TaskInput(BaseModel):
    """One hypothesis the producer wants investigated.

    `question` is required, and that is a contract guarantee the Broker relies
    on: it is both the retrieval intent (it becomes `AnalystTask.goal`) and the
    hypothesis prose that `HypothesisFindings.hypothesis` records. A task file
    therefore never has a "no hypothesis" case, unlike the legacy `--hypothesis`
    CLI flag it replaces, so `smartops.main` runs the analysis tier
    unconditionally for file input.

    `entity` accepts **one object or a list of them**. The received template
    sends a single object; the list form is our extension, and it is load-bearing
    rather than speculative -- a single entity cannot express a real multi-vector
    task (`bench.BOTSV3_HARD_MULTI_VECTOR_TASK` has five), which is the case used
    to prove this loader reproduces a hand-built task before a live run is spent.
    A producer sending one object is unaffected. Raised as an open question for
    the producing team rather than assumed settled.
    """

    # `min_length=1` here restates what `AnalystTask` and `Entity` already
    # enforce, and that is the one deliberate exception to this module's "no
    # duplicated rules" rule. Two reasons, both about the producer rather than
    # about us: the published JSON Schema is generated from these models, so
    # without the constraint the schema would tell the producing team nothing
    # about whether an empty `question` is acceptable; and delegation alone
    # reports an empty one against `goal`, which is our field name for it and
    # not a name the producer has ever seen. Every *substantive* rule is still
    # delegated -- see `_every_task_converts`.
    task_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    question: str = Field(min_length=1)
    entity: TaskEntity | list[TaskEntity]
    time_window: TaskTimeWindow

    def entities(self) -> list[TaskEntity]:
        """`entity` as a list, whichever form it arrived in."""
        return list(self.entity) if isinstance(self.entity, list) else [self.entity]

    def to_scope(self) -> Scope:
        return Scope(
            entities=[e.to_entity() for e in self.entities()],
            time_window=self.time_window.to_tuple(),
        )

    def to_analyst_task(self) -> AnalystTask:
        """The whole producer -> Broker mapping, in one readable place.

        `question` -> `goal`: the Broker and its domain subagents are told what
        to find out, in the producer's own words.

        **`question` is NOT passed as anything else on this object, and must not
        be.** It is also the hypothesis prose, but the hypothesis reaches the
        analysis tier as a separate argument (`analyze.gather(hypothesis=...)`)
        purely as the attachment point on the finished record. The domain
        analysts never see it: `gather_finding(model, scope, slice_)` has no
        parameter that could carry one, and `build_facts_user_turn(scope,
        evidence_text)` has no slot for it either. That blindness is enforced by
        those signatures, and it is the property the analysis tier rests on -- so
        an `AnalystTask` field carrying the hypothesis would not merely be
        redundant, it would be the beginning of undoing it. `AnalystTask`'s own
        docstring excludes hypothesis prose for the same reason.
        """
        return AnalystTask(
            task_id=self.task_id,
            hypothesis_id=self.hypothesis_id,
            goal=self.question,
            scope=self.to_scope(),
        )


class TaskInputFile(BaseModel):
    """A file of tasks handed to the Broker: `{"tasks": [...]}`.

    `schema_version` defaults to 1 because the received template does not carry
    the field, so a file sent today validates unchanged. It is declared anyway,
    for the same reason `AnalystTask` declares one: the producer is a component
    that does not exist in this repo, and extension by it should be a versioned
    event rather than a break.
    """

    schema_version: int = 1
    tasks: list[TaskInput] = Field(min_length=1)

    @model_validator(mode="after")
    def _ids_are_unique(self) -> Self:
        """Reject a repeated `task_id` or `hypothesis_id` within one file.

        Not hygiene -- these two ids are how everything a run produces is filed,
        and neither is positional, so a duplicate does not collide loudly. It
        interleaves. `task_id` names the run directory and its `latest.txt`
        pointer, and it is the prefix of every `Evidence.id`
        (`subtask.evidence_id()`), so two tasks sharing one would mint colliding
        evidence ids and leave one run's pointer overwritten by the other's.
        `hypothesis_id` is the join key the Analyst Agent uses to tie a payload
        back to the claim it was formed without, so a duplicate makes two
        payloads indistinguishable at exactly the boundary that has to tell them
        apart.

        Same reasoning and same shape as `FetchPlan._step_ids_are_unique`:
        rejecting the file before anything is dispatched turns an unrecoverable,
        silent mess into one loud failure.
        """
        for field in ("task_id", "hypothesis_id"):
            seen: dict[str, int] = {}
            for task in self.tasks:
                value = getattr(task, field)
                seen[value] = seen.get(value, 0) + 1
            collisions = [f"{v!r} appears {n} times" for v, n in seen.items() if n > 1]
            if collisions:
                raise ValueError(f"duplicate {field} in task file: {'; '.join(collisions)}")
        return self

    @model_validator(mode="after")
    def _every_task_converts(self) -> Self:
        """Build each task's `AnalystTask` now, and fail the file if one cannot.

        This is what makes the module's "no duplicated rules" claim work. Every
        real constraint on a task -- entity value structure, the seven-member
        `EntityKind`, a timezone-aware and ordered window, non-empty ids and goal
        -- lives on `Entity`, `Scope` and `AnalystTask`. Running the conversion
        here means those owners do the rejecting, at load, rather than this
        module restating them and drifting.

        The task_id is named in the message because a file holds several tasks
        and pydantic's own path (`tasks.2.entity.type`) tells an operator the
        index but not which hypothesis they need to go fix.
        """
        for index, task in enumerate(self.tasks):
            try:
                task.to_analyst_task()
            except ValidationError as exc:
                raise ValueError(
                    f"task {task.task_id!r} (tasks[{index}]) is not a valid "
                    f"investigative task: {exc}"
                ) from exc
        return self

    def select(self, task_ids: list[str] | None) -> list[TaskInput]:
        """The named tasks in **file order**, or all of them when nothing is named.

        File order rather than the order the ids were requested in, so that
        `--task-id T3 --task-id T1` reports the same way round as the file does
        and two invocations naming the same set cannot produce differently
        ordered output.

        Raises on an unknown id rather than silently running a subset: a typo'd
        `--task-id` would otherwise look exactly like a task the file does not
        contain, and the run would report success having investigated nothing.
        """
        if not task_ids:
            return list(self.tasks)
        wanted = set(task_ids)
        unknown = sorted(wanted - {task.task_id for task in self.tasks})
        if unknown:
            available = ", ".join(task.task_id for task in self.tasks)
            raise ValueError(
                f"no task with id {', '.join(repr(u) for u in unknown)} in this file "
                f"-- it holds: {available}"
            )
        return [task for task in self.tasks if task.task_id in wanted]
