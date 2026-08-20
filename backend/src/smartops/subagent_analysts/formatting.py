"""Project fetched rows into compact, token-lean evidence lines.

The reasoning model has a 32k window and no tolerance for wasted tokens, so code
-- never the model -- renders each record type as one dense line per row, picking
the salient fields for that CIM category. This is the "prompt per field" concern:
an `auth_events` row is rendered by its auth-relevant fields, a `processes` row by
its process-lineage fields, and so on.

Rows are raw Splunk output (`ResultSet.rows`, a list of dicts) whose exact field
names vary by sourcetype and CIM data model, so every projector reads through a
small candidate list with fallbacks and never assumes one schema. Rows are the
code-assembled `ResultSet.rows`; `Evidence.raw` blobs are never rendered here.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from contracts import CimCategory, ResultSet, VtVerdict

# How much of a command line survives into a line. A full command line can be
# hundreds of characters; the reasoning signal is in its head (the binary and its
# first arguments), and an un-truncated one would blow the row budget on one row.
_CMDLINE_LIMIT = 200


def _first(row: dict[str, Any], *keys: str, default: str = "-") -> str:
    """First present, non-empty value among `keys`, as a string.

    Case-insensitive on the key, because Splunk field casing is not stable across
    sourcetypes (`user` vs `User`, `dest_ip` vs `dest_IP`). Falls back to
    `default` so a missing field renders as `-` rather than dropping the column
    and misaligning the line.
    """
    lower = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        value = lower.get(key.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "…"


def _format_auth_event(row: dict[str, Any]) -> str:
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"user={_first(row, 'user', 'src_user', 'Account_Name')} "
        f"src={_first(row, 'src', 'src_ip', 'Source_Network_Address')} "
        f"dest={_first(row, 'dest', 'dest_host', 'Computer', 'host')} "
        f"action={_first(row, 'action', 'status', 'signature')} "
        f"app={_first(row, 'app', 'sourcetype')}"
    )


def _format_dns_resolution(row: dict[str, Any]) -> str:
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"query={_first(row, 'query', 'domain', 'name')}"
        f"→{_first(row, 'answer', 'answers', 'ip', 'dest_ip')} "
        f"rtype={_first(row, 'record_type', 'query_type', 'type')}"
    )


def _format_connection(row: dict[str, Any]) -> str:
    src = _first(row, "src", "src_ip")
    src_port = _first(row, "src_port", default="")
    dest = _first(row, "dest", "dest_ip")
    dest_port = _first(row, "dest_port", default="")
    src_full = f"{src}:{src_port}" if src_port not in ("", "-") else src
    dest_full = f"{dest}:{dest_port}" if dest_port not in ("", "-") else dest
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"{src_full}→{dest_full} "
        f"proto={_first(row, 'transport', 'protocol', 'proto')} "
        f"bytes={_first(row, 'bytes', 'bytes_out', 'bytes_in')} "
        f"action={_first(row, 'action', 'status')}"
    )


def _format_process(row: dict[str, Any]) -> str:
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"host={_first(row, 'dest', 'host', 'Computer')} "
        f"user={_first(row, 'user', 'User')} "
        f"process={_first(row, 'process_name', 'process_exec', 'Image')} "
        f"parent={_first(row, 'parent_process_name', 'parent_process', 'ParentImage')} "
        f"cmdline={_truncate(_first(row, 'process', 'command_line', 'CommandLine'), _CMDLINE_LIMIT)}"
    )


def _format_generic(row: dict[str, Any]) -> str:
    """Fallback for uncategorised rows: a compact key=value of the first few keys.

    Uncategorised result sets have no known schema (the model never tagged their
    query with a CIM category), so there is no salient-field projection to apply.
    Rendering a bounded head of the row keeps the rows visible -- they were
    retrieved and paid for -- without letting one wide row spend the whole budget.
    """
    items = list(row.items())[:8]
    return " ".join(f"{k}={_truncate(str(v), 80)}" for k, v in items) or "(empty row)"


_FORMATTERS: dict[CimCategory, Any] = {
    "auth_events": _format_auth_event,
    "dns_resolutions": _format_dns_resolution,
    "connections": _format_connection,
    "processes": _format_process,
}


def format_row(category: str, row: dict[str, Any]) -> str:
    """One line for one row, using the projector for its CIM category."""
    return _FORMATTERS.get(category, _format_generic)(row)


def format_result_set(
    category: str, result_set: ResultSet, *, index: int, row_cap: int = 20
) -> str:
    """Render one `ResultSet` as a citable header plus its projected rows.

    The header `# {category}#{index} · query="…" · rows=N` is the citation anchor:
    the analyst is told to cite evidence as `[{category}#{index}]`. `row_cap`
    bounds how many rows are shown; an over-cap set says how many it withheld
    rather than truncating silently. An empty set is still rendered -- "we asked
    and it came back empty" is a finding the analyst must be able to see.
    """
    header = (
        f"# {category}#{index} · query=\"{_truncate(result_set.query, 160)}\" "
        f"· rows={result_set.row_count}"
    )
    if not result_set.rows:
        return f"{header}\n(no rows returned)"

    shown = result_set.rows[:row_cap]
    lines = [format_row(category, row) for row in shown]
    if len(result_set.rows) > row_cap:
        lines.append(f"… ({len(result_set.rows) - row_cap} more rows not shown)")
    return header + "\n" + "\n".join(lines)


def format_vt_verdicts(verdicts: Iterable[VtVerdict], *, index: int = 1) -> str:
    """Render VirusTotal reputation verdicts as one line each.

    Flagged indicators (any malicious/suspicious) sort first, so the signal is at
    the top of the block where it survives any downstream truncation.
    """
    ordered = sorted(
        verdicts, key=lambda v: (v.malicious + v.suspicious), reverse=True
    )
    header = f"# reputation#{index} · source=virustotal · indicators={len(ordered)}"
    if not ordered:
        return f"{header}\n(no indicators looked up)"
    lines = [
        f"{v.kind}={v.value} "
        f"{'FOUND' if v.found else 'unknown'} "
        f"mal={v.malicious} susp={v.suspicious} harmless={v.harmless} "
        f"rep={v.reputation if v.reputation is not None else '-'}"
        for v in ordered
    ]
    return header + "\n" + "\n".join(lines)
