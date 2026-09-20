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

from collections.abc import Iterable, Sequence
from typing import Any

from smartops.guards import escape_untrusted

from contracts import CimCategory, ResultSet, VtVerdict

# How much of a command line survives into a line. A full command line can be
# hundreds of characters; the reasoning signal is in its head (the binary and its
# first arguments), and an un-truncated one would blow the row budget on one row.
_CMDLINE_LIMIT = 200


def _sanitise(value: str) -> str:
    """Neutralise a value that came from telemetry before it becomes prompt text.

    Every row value originates in logs an attacker can influence, and the
    evidence region is fenced but NOT escaped (`prompts.build_user_turn`), on
    the reasoning that the block is code-formatted. That is true of the
    structure and false of the values -- which is how a payload in a `user`
    field was able to close `</evidence>`, put an instruction outside the fence,
    and forge a second evidence block under a header id that was already in
    `valid_citation_ids()`. A verdict resting entirely on those forged rows
    cited a resolvable id and passed the grounding gate.

    Two steps, and the order matters:

    1. Collapse whitespace. This is the half that closes the forgery -- without
       a newline a payload cannot start a line that looks like a header or a
       tag, and both the header syntax (`# category#N`) and the fence are only
       meaningful at the start of a line. It also keeps one row on one line,
       which the line-per-row format already assumes.
    2. Escape `&`, `<`, `>` via the shared `guards.escape_untrusted`. Escaped
       rather than stripped, matching that function's recorded reasoning: the
       tampering stays legible in the artifact instead of vanishing.

    Applied per value rather than to the finished block so it can never mangle
    the structural characters the projectors emit themselves (`→`, `·`, `#`).
    """
    return escape_untrusted(" ".join(value.split()))


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
            return _sanitise(str(value))
    return default


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "…"


def _count_suffix(row: dict[str, Any]) -> str:
    """` count=N` when the row is an aggregate, otherwise nothing.

    `| stats count by ...` is the dominant triage SPL shape -- `count` appears
    on 1,260 of 1,887 `processes` rows and 138 `auth_events` rows across the
    saved runs. Dropping it left the identity analyst asked to spot "many
    failures for one account" from rows whose only quantity had been deleted.

    Appended rather than given a fixed column because it is present on roughly
    two thirds of rows, not all of them, and a `count=-` on every single-event
    row would spend budget saying nothing.
    """
    value = _first(row, "count", default="")
    return f" count={value}" if value not in ("", "-") else ""


def _format_auth_event(row: dict[str, Any]) -> str:
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"user={_first(row, 'user', 'src_user', 'Account_Name', 'AccountName', 'userPrincipalName')} "
        f"src={_first(row, 'src', 'src_ip', 'Source_Network_Address', 'ipAddress', 'Workstation_Name')} "
        f"dest={_first(row, 'dest', 'dest_host', 'Computer', 'host')} "
        f"action={_first(row, 'action', 'status', 'signature', 'failureReason')} "
        # `code`/`logon_type` are the discriminating pair: without them, a
        # CachedInteractive unlock (EventCode 4624, Logon_Type 11) and a real
        # password spray render as identical near-blank rows. Both raw Windows
        # spellings appear across BOTS v3 sourcetypes (`Logon_Type` on some,
        # `LogonType` on others); `logon_type` is the CIM-normalised alias.
        f"code={_first(row, 'EventCode', 'signature_id', 'event_id')} "
        f"logon_type={_first(row, 'Logon_Type', 'LogonType', 'logon_type')} "
        f"app={_first(row, 'app', 'sourcetype')}"
        f"{_count_suffix(row)}"
    )


def _format_dns_resolution(row: dict[str, Any]) -> str:
    # `query{}` / `name{}` / `answer{}` are Splunk Stream's multivalue field
    # spellings -- the literal braces are part of the JSON key, so a candidate
    # list naming only `query` misses every Stream DNS row (66 of them across
    # the saved runs).
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"src={_first(row, 'src', 'src_ip', 'host')} "
        f"query={_first(row, 'query', 'query{}', 'domain', 'name', 'name{}')}"
        f"→{_first(row, 'answer', 'answer{}', 'answers', 'ip', 'dest_ip')} "
        f"rtype={_first(row, 'record_type', 'query_type', 'type')} "
        f"rcode={_first(row, 'reply_code', 'response_code', 'rcode')}"
        f"{_count_suffix(row)}"
    )


def _format_connection(row: dict[str, Any]) -> str:
    src = _first(row, "src", "src_ip")
    src_port = _first(row, "src_port", default="")
    dest = _first(row, "dest", "dest_ip")
    dest_port = _first(row, "dest_port", default="")
    src_full = f"{src}:{src_port}" if src_port not in ("", "-") else src
    dest_full = f"{dest}:{dest_port}" if dest_port not in ("", "-") else dest
    # Both directions, never one. `bytes_in` and `bytes_out` co-occur on real
    # rows, and collapsing them to whichever candidate matched first rendered
    # `bytes=12` for a row carrying 900,000 inbound -- inverting the very
    # exfiltration signal the network prompt asks the analyst to look for.
    volume = " ".join(
        f"{label}={value}"
        for label, value in (
            ("bytes_in", _first(row, "bytes_in", default="")),
            ("bytes_out", _first(row, "bytes_out", default="")),
        )
        if value not in ("", "-")
    ) or f"bytes={_first(row, 'bytes')}"
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"{src_full}→{dest_full} "
        f"proto={_first(row, 'transport', 'protocol', 'proto')} "
        f"{volume} "
        f"uri={_truncate(_first(row, 'uri_path', 'uri', 'url', 'site'), 120)} "
        f"action={_first(row, 'action', 'status', 'http_method')}"
        f"{_count_suffix(row)}"
    )


def _format_process(row: dict[str, Any]) -> str:
    # Windows Security 4688 writes `New_Process_Name` / `Creator_Process_Name` /
    # `Account_Name`, and the same event arrives under three casings depending
    # on sourcetype (`New_Process_Name`, `NewProcessName`, `new_process_name`).
    # None were candidates, which is why 1,648 of 1,887 real process rows lost
    # data -- while `projection.py:_infer_cim_category` already matched on
    # `new_process_name` to decide the row WAS a process event. The categoriser
    # and the projector disagreed about the shape of the same record.
    return (
        f"{_first(row, 'time', '_time', 'timestamp')} "
        f"host={_first(row, 'dest', 'host', 'Computer', 'ComputerName')} "
        f"user={_first(row, 'user', 'User', 'Account_Name', 'AccountName', 'SubjectUserName')} "
        f"process={_first(row, 'process_name', 'New_Process_Name', 'NewProcessName', 'new_process_name', 'process_exec', 'Image')} "
        f"parent={_first(row, 'parent_process_name', 'Creator_Process_Name', 'ParentProcessName', 'creator_process_name', 'parent_process', 'ParentImage')} "
        f"code={_first(row, 'EventCode', 'signature_id', 'event_id')} "
        f"cmdline={_truncate(_first(row, 'process', 'Process_Command_Line', 'process_command_line', 'command_line', 'cmd_line', 'CommandLine'), _CMDLINE_LIMIT)}"
        f"{_count_suffix(row)}"
    )


def _format_generic(row: dict[str, Any]) -> str:
    """Fallback for uncategorised rows: a compact key=value of the first few keys.

    Uncategorised result sets have no known schema (the model never tagged their
    query with a CIM category), so there is no salient-field projection to apply.
    Rendering a bounded head of the row keeps the rows visible -- they were
    retrieved and paid for -- without letting one wide row spend the whole budget.
    """
    items = list(row.items())[:8]
    return " ".join(
        f"{_sanitise(str(k))}={_truncate(_sanitise(str(v)), 80)}" for k, v in items
    ) or "(empty row)"


_FORMATTERS: dict[CimCategory, Any] = {
    "auth_events": _format_auth_event,
    "dns_resolutions": _format_dns_resolution,
    "connections": _format_connection,
    "processes": _format_process,
}


_PLACEHOLDER_CHARS = frozenset("-→:")
"""Characters a projector emits as pure structure, carrying no row data.

`-` is `_first`'s default and `→`/`:` are the joiners in the connection and DNS
lines, so a token built only from these (`-→-`) is an empty column pair rather
than content.
"""


def _projection_is_empty(line: str) -> bool:
    """True when a projector filled none of its columns from the row.

    Checks the rendered line rather than the row's keys, for two reasons: the
    candidate lists stay the single source of truth (no second copy to drift),
    and a *recognised* key carrying an empty value renders exactly as blank as
    an unrecognised one -- both should fall back.

    Two subtleties, both learned from a test failure rather than guessed:

    - The leading timestamp is dropped before the check. A row that projected
      nothing but `_time` has had its substance dropped just the same, and that
      was the single most common real `processes` shape.
    - Not all content is a `key=value` pair. `_format_connection` carries its
      most important field as the bare `src:port→dest:port` tuple, so an
      earlier version of this check saw only `proto=-`/`bytes=-`/`action=-`,
      declared a fully populated connection row empty, and discarded the tuple
      by falling back. A bare token counts as content unless it is built
      purely from `_PLACEHOLDER_CHARS`.
    """
    tokens = line.split()[1:]
    if not tokens:
        return True
    for token in tokens:
        _, sep, value = token.partition("=")
        if sep:
            if value not in ("", "-"):
                return False
        elif set(token) - _PLACEHOLDER_CHARS:
            return False
    return True


def format_row(category: str, row: dict[str, Any]) -> str:
    """One line for one row, using the projector for its CIM category.

    Falls back to `_format_generic` when the category's projector recognised
    nothing in the row. **This fallback is the fix for a silent-loss bug, not a
    convenience.** A categorised row whose field names were all unknown used to
    render as a structurally valid, entirely empty line (`- host=- user=-
    process=- parent=- cmdline=-`) while the header above it still advertised
    `rows=20`. The analyst was shown blanks, and because the grounding gate
    verifies only that a citation's header id was *emitted* -- never that the
    block beneath it had content -- a fabricated claim citing that block passed
    the gate. Degrading to key=value keeps such rows visible and auditable
    instead of vanishing, for whatever sourcetype arrives next.
    """
    formatter = _FORMATTERS.get(category)
    if formatter is None:
        return _format_generic(row)
    line = formatter(row)
    return _format_generic(row) if _projection_is_empty(line) else line


def _event_total(rows: Sequence[dict[str, Any]]) -> int | None:
    """Total events a set represents, or `None` when it is not an aggregate set.

    `| stats count by ...` rows are GROUPS, not events: `rows=72` on an
    `auth_events` set can stand for several thousand logons. Nothing said so, and
    the analyst was left to sum a `count=` column in prose across rows it may not
    even have been shown. Measured on `cli-20260823T112627`: a 72-row set whose
    counts total 7,656 was reported as "1,063 successes" in the narrative and
    "1,083" in an observation drawn from the same set -- wrong, and inconsistent
    with itself inside one finding.

    So code sums it, which is this package's standing division of labour: code
    supplies every number, the model authors none. The sum runs over ALL rows,
    not the capped subset, because the rows the cap withheld are exactly the ones
    the analyst cannot count.

    A row with no `count` is one event -- `_count_suffix` omits the field for
    single-event rows rather than writing `count=1`, so a mixed set (the common
    case) still totals correctly. `None` means no row carried a count at all: the
    set is not an aggregate and `rows=N` already IS the event total, so a second
    number would only invite the reader to look for a difference that is not there.
    """
    if not any(_first(row, "count", default="") not in ("", "-") for row in rows):
        return None
    total = 0
    for row in rows:
        raw = _first(row, "count", default="")
        try:
            total += int(str(raw)) if raw not in ("", "-") else 1
        except (TypeError, ValueError):
            total += 1
    return total


def format_result_set(
    category: str, result_set: ResultSet, *, index: int, row_cap: int = 20
) -> str:
    """Render one `ResultSet` as a citable header plus its projected rows.

    The header `# {category}#{index} · rows=N` is the citation anchor: the
    analyst is told to cite evidence as `[{category}#{index}]`. `row_cap` bounds
    how many rows are shown; an over-cap set says how many it withheld rather
    than truncating silently. An empty set is still rendered -- "we asked and it
    came back empty" is a finding the analyst must be able to see, and `rows=0`
    is what says so.

    **The query is deliberately NOT in the header.** It used to be, and it was
    the channel through which the hypothesis reached an analyst that is
    structurally blind to it: the fetch subagent writes its SPL *to test the
    hypothesis*, so `query="… site="coinhive.com""` tells the analyst exactly
    what someone was hunting. Measured on `cli-20260825T100434`, 11 of the
    network slice's 35 headers named the hypothesis subject -- and so did 2 of
    the identity slice's, a domain with no business knowing that theory existed.
    `blind_compare.py`'s anchoring experiment could not see it: it holds evidence
    fixed across arms, so the leak was a constant in every arm including the
    blind control.

    The query is untouched in `ResultSet.query`, `report.json`, `evidence.json`,
    and `contracts.Exhibit.query` -- it left the prompt, not the audit trail. The
    Analyst Agent, which is not blind and is the party checking a judgement,
    still gets it via the exhibit.
    """
    header = f"# {category}#{index} · rows={result_set.row_count}"
    events = _event_total(result_set.rows)
    if events is not None:
        header += f" · events={events}"
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
