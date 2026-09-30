"""AnalystTask: the Analyst's tool-agnostic output for one hypothesis, and the
input to the Task Broker.

Deliberately carries only what the Analyst can specify without naming a
product, index, or field: a goal and a scope (see `Analyst Agent` Asana card).

The Broker turns this into zero or more `SubagentMission`s by *calling a domain
specialist's tool* -- that tool call IS the classification decision. There is no
separate classification step: an earlier design ran one LLM call to pick tool
families and then dispatched, which is two calls making the same decision, and
`smartops.planner.plan_missions()` was retired with it. See `smartops.broker`.

Until an Analyst agent exists, `smartops.main` mimics this handover, which is
what the `schema_version` below is for.
"""

import re

from pydantic import BaseModel, Field, field_validator

from contracts.subtask import Scope, ToolFamily

MAX_ID_LENGTH = 128
"""Upper bound on `task_id` / `hypothesis_id`. An identifier is not a payload.

Comfortably above anything a producer would generate and below the ~255-byte
limit a filesystem puts on a single path component -- which matters because
`task_id` becomes a directory name (see `_SAFE_ID`).
"""

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
"""What a `task_id` or `hypothesis_id` may contain.

**This is a path-safety rule, not a style rule.** `task_id` is not merely an
identifier: `smartops.broker.save_run_artifacts()` writes a run to
`<runs_dir>/<task_id>/<stamp>/` and `main._resolve_run_dir()` reads
`<runs_dir>/<task_id>/latest.txt`, so the value becomes a filesystem path
component. It is also the prefix of every `Evidence.id` (`evidence_id()`) and
the first segment of every mission id (`<task_id>:<family>:<toolUseId>`, minted
in `smartops.broker`).

That was harmless while the only producer was `smartops.main`, which built
`cli-<timestamp>` itself. It stopped being harmless when `contracts.TaskInput`
made `task_id` arrive from a JSON file written by another team: `../../etc/foo`
validated fine and would have written a run directory outside the runs tree.

So the allowlist, and each exclusion earns its place:

* `/` and `\\` -- path separators, the traversal itself.
* A leading `.` -- rejects `..` and `.` outright (the anchor requires the first
  character to be alphanumeric) along with dotfiles, without having to special-
  case the two names.
* `:` -- the mission-id separator. A colon here would make
  `<task_id>:<family>:<toolUseId>` ambiguous to parse, and on Windows it is also
  an alternate-data-stream marker in a path.
* Whitespace and control characters -- fall outside the class, so a newline or
  tab cannot reach a directory name, a log line, or a telemetry attribute.

Applied to `AnalystTask` only, deliberately. `SubtaskResult.task_id` holds
mission ids, which contain colons by construction, and `BrokerReport.task_id` is
loaded from artifacts written before this rule existed -- tightening either would
break reading the saved runs used as replay fixtures.
"""


def _validated_id(value: str, field: str) -> str:
    if len(value) > MAX_ID_LENGTH:
        raise ValueError(
            f"{field} is {len(value)} characters, over the {MAX_ID_LENGTH}-character "
            f"limit -- an identifier this long is far more likely to be pasted junk"
        )
    if not _SAFE_ID.match(value):
        raise ValueError(
            f"{field} {value!r} is not a safe identifier: it must start with a letter "
            f"or digit and contain only letters, digits, '.', '-' and '_'. This value "
            f"becomes a directory name under the runs directory and a segment of every "
            f"evidence id, so path separators, ':' , leading dots and whitespace are "
            f"refused"
        )
    return value


class AnalystTask(BaseModel):
    """One hypothesis's worth of investigative intent, before any domain
    classification has happened.

    This is the Analyst -> Broker interface. It is versioned because the Analyst
    that produces it does not exist yet: the Broker (its only consumer) defines
    the shape it needs, and extension by the producer should be a normal event
    rather than a break. Deliberately excludes hypothesis prose, prior findings,
    and round/priority -- each would be a guess about what an unbuilt Analyst
    wants, and the first two are further attacker-influenceable input to defend.
    """

    schema_version: int = 1
    task_id: str = Field(min_length=1)
    hypothesis_id: str = Field(min_length=1)
    goal: str = Field(min_length=1)
    scope: Scope

    @field_validator("task_id", "hypothesis_id")
    @classmethod
    def _ids_are_path_safe(cls, value: str, info) -> str:
        """Both ids, because both cross into places a raw string should not.

        See `_SAFE_ID` for why this is a safety rule rather than a naming
        convention. Enforced here, on the Analyst -> Broker contract, so that it
        holds for every producer at once -- the CLI's own `cli-<timestamp>`, a
        `contracts.TaskInputFile` written by another team, and whatever the real
        Analyst agent eventually sends.
        """
        return _validated_id(value, info.field_name)


class TaskClassification(BaseModel):
    """Forced structured-output shape for the Broker's own account of its run.

    This is the Broker's *self-report*, not the record of what happened.
    `BrokerOutcome.dispatched` is observed independently at the moment of each
    dispatch, and the two are compared precisely because a model's account of its
    reasoning can diverge from its behaviour -- `broker_task()` logs a warning
    when it does, and trusts the observed list.

    `tool_families` being empty is not a *validation* error -- Pydantic accepts
    it. But don't read that as "safe to ignore": for a real investigative task an
    empty result almost always means the Broker failed to match a domain, not
    that the task is genuinely irrelevant to every specialist. `broker_task()`
    warns on it for that reason.

    Distinct from `SubtaskStatus.rejected`, which is a subagent's verdict on a
    mission it actually received. A family absent from `tool_families` was never
    engaged at all, so there is no such verdict to inspect.

    The Broker may also produce *no* structured output -- Strands ends a
    turn-limited or token-limited run with a `stop_reason` and raises nothing. In
    that case `broker_task()` synthesizes this from what was observed rather than
    discarding evidence the dispatches already collected and paid for, and marks
    the rationale as unavailable.
    """

    tool_families: list[ToolFamily] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
