"""Wires up Strands' native OpenTelemetry observability rather than
hand-rolling spans (see the 2026-08-06 session doc's observability
research + decision).

Strands auto-instruments spans for every LLM call and tool invocation on
any `Agent` the moment a tracer provider exists -- `configure_telemetry()`
is only responsible for *where those spans go* and for the handful of
things Strands doesn't already know about: our business-level IDs and our
own `Budget` ledger.

Zero-config by default: prints spans to the console if no OTLP collector is
configured, so this works out of the box in local dev with no external
service. Point `OTEL_EXPORTER_OTLP_ENDPOINT` at a real collector (Langfuse,
Phoenix, CloudWatch, ...) later and nothing in this module changes -- that
portability is the whole reason to use Strands' built-in instrumentation
instead of a hand-rolled one.
"""

from __future__ import annotations

import os
import threading

from contracts import SubagentMission, SubtaskResult, SubtaskStatus
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from strands.telemetry import StrandsTelemetry

from smartops.budget import Reservation

_configured = False
_configure_lock = threading.Lock()


def configure_telemetry() -> None:
    """Call once per process, before the first `Agent` is constructed.
    Idempotent -- safe to call from multiple entry points, including
    concurrently: the check-and-set is guarded by a lock, so two threads
    racing to configure telemetry for the first time can't both pass the
    check and double-initialize `StrandsTelemetry`/its exporters.
    """
    global _configured
    with _configure_lock:
        if _configured:
            return
        telemetry = StrandsTelemetry()
        telemetry.setup_console_exporter()
        if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            telemetry.setup_otlp_exporter()
        _configured = True


def trace_attributes_for(mission: SubagentMission) -> dict[str, str]:
    """Business-level identifiers to pass as `Agent(trace_attributes=...)`
    when constructing a subagent's `Agent` for this mission, so every span
    it produces carries them. This is the whole answer to "traceability"
    from the research -- correlating a trace back to `task_id`/
    `hypothesis_id` needs no separate correlation system, Strands attaches
    these to every child span automatically.
    """
    return {
        "task_id": mission.task_id,
        "hypothesis_id": mission.hypothesis_id,
        "tool_family": mission.tool_family,
    }


def record_cost(reservation: Reservation, actual_micro_usd: int) -> None:
    """Mirrors a settled `Budget` charge onto the current span, so cost is
    visible inline in a trace and not only in the Budget ledger. Call this
    right after `Budget.settle()` returns.

    A no-op if telemetry was never configured or there's no active span --
    this must never be the thing that breaks a subagent call.
    """
    span = trace.get_current_span()
    if not span.is_recording():
        return
    span.set_attribute("cost.role", reservation.role)
    span.set_attribute("cost.estimated_micro_usd", reservation.reserved_micro_usd)
    span.set_attribute("cost.actual_micro_usd", actual_micro_usd)


def record_result_status(result: SubtaskResult) -> None:
    """Reflects a subagent's terminal `SubtaskStatus` onto the current span
    as OTel span status, so failures surface directly in a trace view
    instead of requiring a separate look at the ledger or logs.
    """
    span = trace.get_current_span()
    if not span.is_recording():
        return
    if result.status == SubtaskStatus.ERROR:
        span.set_status(Status(StatusCode.ERROR, description=result.error))
    else:
        span.set_attribute("subtask.status", result.status.value)
