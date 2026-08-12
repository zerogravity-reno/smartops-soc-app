"""Turning captured tool output into typed `Findings`. Code only, never a model.

This is the second layer of the two-layer payload. The model authors a small
assessment and says which CIM category each of its queries was after; **code**
supplies every row, from what the tools actually returned.

Neither half can forge the other: a model that never sees the rows cannot invent
them, and code that never reads the prompt cannot be talked into re-categorising.
"""

from __future__ import annotations

import logging
from typing import Any

from contracts import CimCategory, Findings, QueryRun, ResultSet, SiemFindings

logger = logging.getLogger(__name__)

_CIM_BUCKETS: tuple[CimCategory, ...] = (
    "dns_resolutions",
    "connections",
    "processes",
    "auth_events",
)


def _normalise(query: str | None) -> str:
    """Whitespace-insensitive key for matching a reported query to an executed one.

    The model retypes its query into `queries_run`, and retyping reliably changes
    spacing. Matching on the raw string would miss almost every time.
    """
    return " ".join((query or "").split())


def _rows_of(payload: Any) -> list[dict[str, Any]]:
    """Rows inside a tool result, without knowing the server's envelope.

    Tries the common shapes and gives up honestly rather than guessing: an
    unrecognised payload yields no rows and is reported as a zero-row result set,
    which is visible, instead of being silently reshaped into something wrong.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("results", "rows", "records", "events"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def project_siem(calls: list[Any], queries_run: list[QueryRun]) -> SiemFindings:
    """Bucket each executed call's rows into the CIM category its query was tagged with.

    Matching is on the query text, not on call order: the collector skips failed
    calls while the model may still list them, so index alignment breaks exactly
    when something has gone wrong -- the worst time to lose attribution.

    A result set whose query the model never tagged goes to `uncategorised`
    rather than being dropped. Silently discarding retrieved rows would be the
    worse failure, and an unexpectedly full `uncategorised` bucket is a signal
    worth seeing.
    """
    by_query: dict[str, CimCategory | None] = {
        _normalise(q.query): q.category for q in queries_run
    }

    buckets: dict[str, list[ResultSet]] = {name: [] for name in _CIM_BUCKETS}
    buckets["uncategorised"] = []

    for call in calls:
        rows = _rows_of(call.payload)
        result_set = ResultSet(
            query=call.query or f"<{call.tool}: query not recoverable from tool input>",
            row_count=len(rows),
            rows=rows,
        )

        category = by_query.get(_normalise(call.query)) if call.query else None
        if category in _CIM_BUCKETS:
            buckets[category].append(result_set)
        else:
            logger.info(
                "tool=%s | result set not tagged with a CIM category, filing as uncategorised",
                call.tool,
            )
            buckets["uncategorised"].append(result_set)

    return SiemFindings(**buckets)


def project(family: str, calls: list[Any], queries_run: list[QueryRun]) -> Findings | None:
    """The family's typed payload, or `None` where the family has no projector.

    `vt` is deliberately absent: its findings are built in
    `broker.enrich_mission()` straight from parsed `Verdict`s, on a path that
    calls no model at all.
    """
    if family == "siem":
        return project_siem(calls, queries_run)
    return None
