"""Turning captured tool output into typed `Findings`. Code only, never a model.

This is the second layer of the two-layer payload. The model authors a small
assessment and says which CIM category each of its queries was after; **code**
supplies every row, from what the tools actually returned.

Neither half can forge the other: a model that never sees the rows cannot invent
them, and code that never reads the prompt cannot be talked into re-categorising.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from contracts.findings import VtFindings, VtVerdict

from contracts import CimCategory, Findings, QueryRun, ResultSet, SiemFindings

logger = logging.getLogger(__name__)

_CIM_BUCKETS: tuple[CimCategory, ...] = (
    "dns_resolutions",
    "connections",
    "processes",
    "auth_events",
)

# Matches `Verdict.summary()` (virustotal.py:106-110). `\b` rather than `^`: a
# single lookup can report several indicators on separate lines, and `^` without
# MULTILINE matched only the first, silently dropping the rest.
_VT_SUMMARY_RE = re.compile(
    r"\b(?P<kind>\w+)=(?P<value>\S+):\s+"
    r"(?:(?P<unknown>unknown to VirusTotal)|"
    r"(?P<malicious>\d+)\s+malicious\s+/\s+(?P<suspicious>\d+)\s+suspicious\s+of\s+(?P<engines>\d+)\s+engines)"
)


def _text_of(payload: Any) -> str:
    """The human-readable text a tool returned, whatever envelope carries it.

    The model-free enricher returns `Verdict.summary()` as a bare string, but the
    same tool reached through a live `Agent` comes back wrapped:
    `{"status": ..., "content": [{"text": ...}], ...}`. `str()` on that dict
    yields a `repr` in which the summary is embedded in quoting and punctuation,
    which is how every model-driven VirusTotal lookup silently failed to parse
    while the enricher path worked -- the two paths carry identical text.
    """
    if isinstance(payload, dict):
        content = payload.get("content")
        if isinstance(content, list):
            parts = [
                block["text"]
                for block in content
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            ]
            if parts:
                return "\n".join(parts)
    return str(payload) if payload is not None else ""


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
    """Bucket each executed call's rows into the CIM category its query was tagged with."""
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


def project_vt(calls: list[Any]) -> VtFindings:
    """Project captured VT tool calls into VtFindings."""
    verdicts: list[VtVerdict] = []
    for c in calls:
        payload = getattr(c, "payload", c)
        tool_name = getattr(c, "tool", "vt_lookup")
        query_val = getattr(c, "query", None)

        if isinstance(payload, dict) and "verdicts" in payload:
            for v in payload["verdicts"]:
                if isinstance(v, VtVerdict):
                    verdicts.append(v)
                elif isinstance(v, dict):
                    verdicts.append(VtVerdict(**v))
            continue

        # `finditer`, not `search`: one lookup can report several indicators, and
        # taking only the first silently dropped the rest.
        matches = list(_VT_SUMMARY_RE.finditer(_text_of(payload)))
        if not matches:
            # DELIBERATELY no verdict. This branch used to synthesise
            # `found=False, malicious=0` from the tool name, which reads as "this
            # indicator is unknown to VirusTotal" -- a real VT answer -- when what
            # actually happened is that the response could not be parsed. That is
            # the precise error the subagent prompt forbids: "A tool call that
            # FAILS is not a finding. Never report a failed lookup as though it
            # showed the subject to be clean." It fired on every live lookup:
            # coinhive.com, 11/91 malicious, projected as a clean unknown.
            logger.warning(
                "tool=%s query=%s | VirusTotal payload carried no parseable verdict "
                "summary; recording NO verdict rather than a false 'unknown'",
                tool_name,
                query_val,
            )
            continue

        for match in matches:
            kind = match.group("kind")
            value = match.group("value")
            if match.group("unknown"):
                verdicts.append(
                    VtVerdict(
                        kind=kind,
                        value=value,
                        found=False,
                        malicious=0,
                        suspicious=0,
                        harmless=0,
                        undetected=0,
                        reputation=None,
                    )
                )
            else:
                malicious = int(match.group("malicious"))
                suspicious = int(match.group("suspicious"))
                engines = int(match.group("engines"))
                harmless = max(0, engines - malicious - suspicious)
                verdicts.append(
                    VtVerdict(
                        kind=kind,
                        value=value,
                        found=True,
                        malicious=malicious,
                        suspicious=suspicious,
                        harmless=harmless,
                        undetected=0,
                        reputation=None,
                    )
                )
    return VtFindings(verdicts=verdicts)


def project(family: str, calls: list[Any], queries_run: list[QueryRun]) -> Findings | None:
    """The family's typed payload, or `None` where the family has no projector."""
    if family == "siem":
        return project_siem(calls, queries_run)
    return None
