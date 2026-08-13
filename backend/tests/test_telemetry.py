from datetime import UTC, datetime, timedelta

from smartops.budget import Reservation
from smartops.telemetry import record_cost, record_result_status, trace_attributes_for

from contracts import Entity, Scope, SubagentMission, SubtaskResult, SubtaskStatus


def _mission() -> SubagentMission:
    now = datetime.now(UTC)
    return SubagentMission(
        task_id="task-1",
        hypothesis_id="hyp-1",
        tool_family="edr",
        goal="check host for persistence mechanisms",
        scope=Scope(
            entities=[Entity(kind="host", value="host-1")],
            time_window=(now - timedelta(hours=1), now),
        ),
    )


def test_trace_attributes_for_mission():
    attrs = trace_attributes_for(_mission())
    assert attrs == {
        "task_id": "task-1",
        "hypothesis_id": "hyp-1",
        "tool_family": "edr",
    }


def test_record_cost_is_a_noop_without_configured_telemetry():
    # No configure_telemetry() call -> no active recording span. Must not raise.
    reservation = Reservation(role="subagent:edr", task_id="task-1", model="claude-haiku-4-5", reserved_micro_usd=100)
    record_cost(reservation, actual_micro_usd=42)


def test_record_result_status_is_a_noop_without_configured_telemetry():
    result = SubtaskResult(task_id="task-1", status=SubtaskStatus.NO_DATA, summary="nothing found")
    record_result_status(result)
