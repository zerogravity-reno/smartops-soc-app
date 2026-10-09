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

⚠️ Real model calls happen now, so this is live rather than theoretical:
Strands' span-content redaction is opt-in and OFF by default. Set
`gen_ai_unredacted_attributes=` (empty value) in `OTEL_SEMCONV_STABILITY_OPT_IN`
to redact `gen_ai.input.messages`, `gen_ai.output.messages` and
`gen_ai.system_instructions` before pointing this at any collector -- otherwise
prompts and responses, which for us means SOC evidence, are exported verbatim.

The analyst tier is instrumented by hand (`analysis_span`, `analyst_span`)
because Strands cannot reach it: those three calls drive a Bedrock
custom-imported model through raw `invoke_model` with no `Agent` involved, so
auto-instrumentation produces nothing and a trace covered the fetch half only.
Our spans carry the judgement and the token counts, never the reasoning trace.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.trace import Status, StatusCode
from strands.telemetry import StrandsTelemetry

from contracts import AnalystTask, SubagentMission, SubtaskResult, SubtaskStatus
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


TRACEPARENT_ENV_VAR = "TRACEPARENT"


@contextmanager
def round_span(batch_id: str | None) -> Iterator[trace.Span]:
    """One CLI invocation -- a Broker round -- as one span, under the webapp's trace.

    The webapp passes a W3C `traceparent` in `TRACEPARENT`, one trace per
    investigation. Every `investigation_span` and `analysis_span` of the round
    opens inside this one, so the whole investigation is one trace. On 874ab334
    it was 9: each task was its own root (O5). Without the variable this is a
    plain root, which still joins a round's tasks.
    """
    carrier = {"traceparent": os.environ.get(TRACEPARENT_ENV_VAR, "").strip()}
    parent = propagate.extract(carrier) if carrier["traceparent"] else None
    attributes = {"batch_id": batch_id} if batch_id else {}
    with trace.get_tracer(TRACER_NAME).start_as_current_span(
        "smartops.round", context=parent, attributes=attributes
    ) as span:
        yield span


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


def record_run_id(run_id: str) -> None:
    """Stamp the run directory's name onto the current span.

    Called after the artifacts are written, because that is when the id exists --
    `save_run_artifacts()` mints the timestamped directory, so nothing upstream of
    it can know the name. Spans accept attributes until they end, and this one is
    still open.

    **Why it matters that both trace roots carry this.** The fetch tier and the
    analyze tier are separate traces on purpose (see `analysis_span`), joined by
    their attributes rather than by a parent. They carried `task_id` and
    `hypothesis_id`, and neither identifies a RUN: a task_id is reused every time
    the same case is investigated again -- `botsv3_coinhive` has four runs under
    one id. Two traces joined on task_id alone can therefore belong to different
    investigations, which is the failure this closes.

    A no-op with no recording span, same discipline as `record_cost`.
    """
    span = trace.get_current_span()
    if not span.is_recording():
        return
    span.set_attribute("run_id", run_id)


@contextmanager
def analysis_span(
    task_id: str,
    hypothesis_id: str,
    *,
    run_id: str | None = None,
    fetch_trace_id: str | None = None,
) -> Iterator[trace.Span]:
    """Root span for the analyze tier.

    Both this and `investigation_span` open under `round_span`, so a round is one
    trace (O5). This is a sibling of `investigation_span`, not its child, because that span
    opens inside `broker_task()` and has closed by the time `main` calls
    `gather()`. Nesting would mean either hoisting the fetch span up into `main`
    -- which puts a tracing concern in the CLI and leaves `broker_task` untraced
    when called as a library -- or leaving it open across a boundary it does not
    own.

    The two roots are joined by their attributes rather than by a parent, and
    **`run_id` is the one that actually identifies the run.** `task_id` and
    `hypothesis_id` are carried too, but a task_id is reused across runs of the
    same case, so those two alone would let traces from different investigations
    look joinable. `fetch_trace_id` additionally records which fetch trace produced
    the evidence -- it comes from `BrokerReport.trace_id`, which `broker_task`
    stamped from inside its own span, so a reader holding the analyze trace can
    jump straight to the retrieval rather than search for it.

    Analyst spans nest under this one for free: `gather()` fans out with
    `asyncio.to_thread`, which copies the current `contextvars` context into each
    worker thread, and OTel's context is a contextvar.
    """
    tracer = trace.get_tracer(TRACER_NAME)
    attributes = {"task_id": task_id, "hypothesis_id": hypothesis_id}
    # Omitted rather than empty-stringed when unknown, so a missing join key reads
    # as absent instead of as a real value that matches nothing.
    if run_id:
        attributes["run_id"] = run_id
    if fetch_trace_id:
        attributes["fetch.trace_id"] = fetch_trace_id
    with tracer.start_as_current_span("smartops.analysis", attributes=attributes) as span:
        yield span


@contextmanager
def analyst_span(domain: str) -> Iterator[trace.Span]:
    """One domain analyst's call: pack, invoke, parse, ground.

    Hand-rolled because Strands cannot instrument this tier. The rest of the
    system rides on Strands' auto-instrumentation of `Agent`, but the analysts
    drive a Bedrock custom-imported model through raw `invoke_model` -- no
    `Agent`, so no spans -- which left a trace covering the fetch half only.

    Attribute names follow OTel's GenAI semantic conventions where one exists
    (`gen_ai.*`), so a collector that already understands Strands' spans reads
    these the same way. `record_analyst_finding()` fills them in.
    """
    tracer = trace.get_tracer(TRACER_NAME)
    with tracer.start_as_current_span(
        f"smartops.analyst.{domain}",
        attributes={"analyst.domain": domain, "gen_ai.operation.name": "chat"},
    ) as span:
        yield span


def record_analyst_finding(finding: Any) -> None:
    """Stamp a `DomainFinding`'s outcome onto the current span.

    What a reader wants from an analyst span is what the finding contains and
    what it cost, so both go on. This tier carries no verdict -- see
    `DomainFinding`'s docstring -- so there is no `disposition`/`confidence` to
    stamp any more; `narrative_chars` replaces them as the cheapest signal of
    whether a translation actually happened, alongside the observation and
    citation counts. `reasoning_trace` deliberately does NOT go on: it is the
    model's private chain of thought, kept for audit and never re-fed, and a
    span export is not an audit store -- Strands' span-content redaction is
    opt-in and off by default, so a trace shipped to a collector would carry it
    in plaintext.

    A no-op with no active recording span, same discipline as `record_cost`: this
    must never be the thing that breaks an analysis.
    """
    span = trace.get_current_span()
    if not span.is_recording():
        return
    span.set_attribute("analyst.observation_count", len(finding.observations))
    span.set_attribute("analyst.citation_count", len(finding.citations))
    span.set_attribute("analyst.narrative_chars", len(finding.narrative))
    span.set_attribute("gen_ai.usage.input_tokens", finding.prompt_tokens)
    span.set_attribute("gen_ai.usage.output_tokens", finding.generation_tokens)


def current_trace_id() -> str | None:
    """The active span's trace id as 32 lowercase hex characters, or `None`.

    The reverse of `investigation_span`'s span attributes. Those make trace ->
    run resolvable; this is what makes run -> trace resolvable, by giving
    `BrokerReport.trace_id` something to record. Without it a saved report named
    no trace at all, so an operator holding `report.json` could not reach the
    spans that produced it.

    `None` rather than a zero id when telemetry was never configured: the tracer
    is then non-recording and its context carries the all-zero invalid trace id,
    which would be a real-looking value pointing at nothing. Same no-op
    discipline as `record_cost`.
    """
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return format(context.trace_id, "032x")


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
