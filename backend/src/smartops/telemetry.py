"""Wires up Strands' native OpenTelemetry observability rather than
hand-rolling spans (see the 2026-08-06 session doc's observability
research + decision).

Strands auto-instruments spans for every LLM call and tool invocation on
any `Agent` the moment a tracer provider exists -- `configure_telemetry()`
is only responsible for *where those spans go* and for the handful of
things Strands doesn't already know about: our business-level IDs and our
own `Budget` ledger.

Exports nothing by default. Pass `console=True` for local dev, or point
`OTEL_EXPORTER_OTLP_ENDPOINT` at a real collector (Langfuse, Phoenix,
CloudWatch, ...) and nothing in this module changes -- that portability is the
whole reason to use Strands' built-in instrumentation instead of a hand-rolled
one. Langfuse is auto-detected by Strands from that endpoint and changes how it
records span content, with no code on our side.

Silent-by-default is deliberate: Strands' GenAI spans can carry prompt and
response content, so a console exporter left on would put SOC investigation
data into plaintext container logs.

Note for when a real model call lands: Strands' span-content redaction is
opt-in and OFF by default -- set `gen_ai_unredacted_attributes=` (empty value)
in `OTEL_SEMCONV_STABILITY_OPT_IN` to redact `gen_ai.input.messages`,
`gen_ai.output.messages`, and `gen_ai.system_instructions`. Not wired up here
because no model call happens yet, so no span currently carries content.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Iterator

from contracts import AnalystTask, SubagentMission, SubtaskResult, SubtaskStatus
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from strands.telemetry import StrandsTelemetry

from smartops.budget import Reservation

TRACER_NAME = "smartops"

_configured = False
_configure_lock = threading.Lock()


def configure_telemetry(*, console: bool = False) -> None:
    """Call once per process, before the first `Agent` is constructed.

    Idempotent -- safe to call from multiple entry points, including
    concurrently: the check-and-set is guarded by a lock, so two threads
    racing to configure telemetry for the first time can't both pass the
    check and double-initialize `StrandsTelemetry`/its exporters. The guard is
    load-bearing, not belt-and-braces: `StrandsTelemetry`'s setup methods are
    idempotent per call, but calling one twice adds a *duplicate* span
    processor, so every span would be exported twice.

    `console` defaults to False because Strands' GenAI spans can carry prompt
    and response content, and this is a SOC tool -- investigation data must not
    land in container stdout just because someone imported us. Opt in
    explicitly for local debugging.
    """
    global _configured
    with _configure_lock:
        if _configured:
            return
        telemetry = StrandsTelemetry()
        if console:
            telemetry.setup_console_exporter()
        if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            telemetry.setup_otlp_exporter()
        _configured = True


@contextmanager
def investigation_span(task: AnalystTask) -> Iterator[trace.Span]:
    """Root span for one investigation.

    Strands auto-instruments each `Agent` and tool call, but those spans are
    siblings with no common parent -- so a trace showed the Broker's model call
    and each subagent's model call as unrelated roots, with nothing tying them to
    one investigation. This is that parent.

    It also gives `record_cost()` somewhere to land for the Broker's own charge:
    `broker_task()` settles after `invoke()` has returned, so it is outside every
    Strands span, and without a span of our own the cost attribute was silently
    dropped.

    A no-op when telemetry was never configured -- `get_tracer()` then returns a
    non-recording tracer, so this costs nothing in tests or credential-less runs.
    """
    tracer = trace.get_tracer(TRACER_NAME)
    with tracer.start_as_current_span(
        "smartops.investigation",
        attributes={
            "task_id": task.task_id,
            "hypothesis_id": task.hypothesis_id,
            "scope.entity_kinds": sorted(task.scope.kinds()),
            "scope.entity_count": len(task.scope.entities),
        },
    ) as span:
        yield span


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
