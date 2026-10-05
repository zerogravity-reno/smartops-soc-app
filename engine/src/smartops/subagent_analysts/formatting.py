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
from datetime import UTC, datetime
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
    # `tstats` names its columns `Dataset.field` (`Processes.parent_process_path`).
    # The bare field is a fallback key, so an exact key on the row still wins.
    for k, v in row.items():
        lower.setdefault(str(k).lower().rpartition(".")[2], v)
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
    value = _first(row, *_COUNT_FIELD, default="")
    return f" count={value}" if value not in ("", "-") else ""


# Per-category field candidates, named once and read by two consumers: the row
# formatters below and the aggregate that reports on the rows the cap withheld.
# They used to live inline in each formatter's f-string, which was fine while
# the formatters were the only reader -- an aggregate that restated them would
# drift the first time a Splunk sourcetype spelled a field differently and only
# one copy learned about it.
#
# Order is meaningful: it is the order the aggregate reports dimensions in.
# `time` is first in every category and is handled apart from the rest -- it
# yields a range, not a distribution.
_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "auth_events": {
        "time": ("time", "_time", "timestamp"),
        "user": ("user", "src_user", "Account_Name", "AccountName", "userPrincipalName"),
        "src": ("src", "src_ip", "Source_Network_Address", "ipAddress", "Workstation_Name"),
        "dest": ("dest", "dest_host", "Computer", "host"),
        "action": ("action", "status", "signature", "failureReason"),
        # `code`/`logon_type` are the discriminating pair: without them, a
        # CachedInteractive unlock (EventCode 4624, Logon_Type 11) and a real
        # password spray render as identical near-blank rows. Both raw Windows
        # spellings appear across BOTS v3 sourcetypes (`Logon_Type` on some,
        # `LogonType` on others); `logon_type` is the CIM-normalised alias.
        "code": ("EventCode", "signature_id", "event_id"),
        "logon_type": ("Logon_Type", "LogonType", "logon_type"),
        "app": ("app", "sourcetype"),
    },
    "dns_resolutions": {
        "time": ("time", "_time", "timestamp"),
        "src": ("src", "src_ip", "host"),
        # `query{}` / `name{}` / `answer{}` are Splunk Stream's multivalue field
        # spellings -- the literal braces are part of the JSON key, so a
        # candidate list naming only `query` misses every Stream DNS row (66 of
        # them across the saved runs).
        "query": ("query", "query{}", "domain", "name", "name{}"),
        "answer": ("answer", "answer{}", "answers", "ip", "dest_ip"),
        "rtype": ("record_type", "query_type", "type"),
        "rcode": ("reply_code", "response_code", "rcode"),
    },
    "connections": {
        "time": ("time", "_time", "timestamp"),
        "src": ("src", "src_ip"),
        "src_port": ("src_port",),
        "dest": ("dest", "dest_ip"),
        "dest_port": ("dest_port",),
        "proto": ("transport", "protocol", "proto"),
        "bytes_in": ("bytes_in",),
        "bytes_out": ("bytes_out",),
        "bytes": ("bytes",),
        "uri": ("uri_path", "uri", "url", "site"),
        "action": ("action", "status", "http_method"),
    },
    "processes": {
        "time": ("time", "_time", "timestamp"),
        "host": ("dest", "host", "Computer", "ComputerName"),
        "user": ("user", "User", "Account_Name", "AccountName", "SubjectUserName"),
        # Windows Security 4688 writes `New_Process_Name` /
        # `Creator_Process_Name` / `Account_Name`, and the same event arrives
        # under three casings depending on sourcetype. None were candidates,
        # which is why 1,648 of 1,887 real process rows lost data -- while
        # `projection.py:_infer_cim_category` already matched on
        # `new_process_name` to decide the row WAS a process event. The
        # categoriser and the projector disagreed about the shape of one record.
        "process": (
            "process_name", "New_Process_Name", "NewProcessName",
            "new_process_name", "process_exec", "Image",
        ),
        # Path spellings first. A masquerading parent shares its name with the
        # real binary (`splunkd.exe`) and differs only by its path, so name-first
        # rendering made them look the same: where such rows were retrieved, 0
        # mentions of the path reached the analyst payload (issue B1).
        "parent": (
            "parent_process_path", "ParentImage", "parent_process",
            "Creator_Process_Name", "creator_process_name", "ParentProcessName",
            "parent_process_name",
        ),
        "code": ("EventCode", "signature_id", "event_id"),
        "cmdline": (
            "process", "Process_Command_Line", "process_command_line",
            "command_line", "cmd_line", "CommandLine",
        ),
    },
}

# The `count=` column, which is not a dimension: it weights every other one.
# Named here so `_count_suffix` and the aggregate agree about where a group's
# size is read from.
_COUNT_FIELD: tuple[str, ...] = ("count",)


def _utc(value: str) -> str:
    """An offset-bearing ISO timestamp restated in UTC (`...Z`); anything else as is.

    The task window reaches the prompt in UTC, while Splunk returns `_time` in
    the searching user's zone. On run `cecd266a` the endpoint analyst compared a
    `14:53:35Z-14:54:15Z` window against rows stamped `17:53:53+03:00` -- the
    same instant -- and reported "no process activity" in the window before
    describing those very rows. One zone on both sides removes that arithmetic.
    Naive or unparseable values are left alone: guessing their zone is worse.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        return value
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _field(row: dict[str, Any], category: str, name: str, default: str = "-") -> str:
    """Resolve one named field for `category` through `_FIELDS`."""
    value = _first(row, *_FIELDS[category][name], default=default)
    return _utc(value) if name == "time" else value


def _format_auth_event(row: dict[str, Any]) -> str:
    return (
        f"{_field(row, 'auth_events', 'time')} "
        f"user={_field(row, 'auth_events', 'user')} "
        f"src={_field(row, 'auth_events', 'src')} "
        f"dest={_field(row, 'auth_events', 'dest')} "
        f"action={_field(row, 'auth_events', 'action')} "
        f"code={_field(row, 'auth_events', 'code')} "
        f"logon_type={_field(row, 'auth_events', 'logon_type')} "
        f"app={_field(row, 'auth_events', 'app')}"
        f"{_count_suffix(row)}"
    )


def _format_dns_resolution(row: dict[str, Any]) -> str:
    return (
        f"{_field(row, 'dns_resolutions', 'time')} "
        f"src={_field(row, 'dns_resolutions', 'src')} "
        f"query={_field(row, 'dns_resolutions', 'query')}"
        f"→{_field(row, 'dns_resolutions', 'answer')} "
        f"rtype={_field(row, 'dns_resolutions', 'rtype')} "
        f"rcode={_field(row, 'dns_resolutions', 'rcode')}"
        f"{_count_suffix(row)}"
    )


def _format_connection(row: dict[str, Any]) -> str:
    src = _field(row, "connections", "src")
    src_port = _field(row, "connections", "src_port", default="")
    dest = _field(row, "connections", "dest")
    dest_port = _field(row, "connections", "dest_port", default="")
    src_full = f"{src}:{src_port}" if src_port not in ("", "-") else src
    dest_full = f"{dest}:{dest_port}" if dest_port not in ("", "-") else dest
    # Both directions, never one. `bytes_in` and `bytes_out` co-occur on real
    # rows, and collapsing them to whichever candidate matched first rendered
    # `bytes=12` for a row carrying 900,000 inbound -- inverting the very
    # exfiltration signal the network prompt asks the analyst to look for.
    volume = " ".join(
        f"{label}={value}"
        for label, value in (
            ("bytes_in", _field(row, "connections", "bytes_in", default="")),
            ("bytes_out", _field(row, "connections", "bytes_out", default="")),
        )
        if value not in ("", "-")
    ) or f"bytes={_field(row, 'connections', 'bytes')}"
    return (
        f"{_field(row, 'connections', 'time')} "
        f"{src_full}→{dest_full} "
        f"proto={_field(row, 'connections', 'proto')} "
        f"{volume} "
        f"uri={_truncate(_field(row, 'connections', 'uri'), 120)} "
        f"action={_field(row, 'connections', 'action')}"
        f"{_count_suffix(row)}"
    )


def _format_process(row: dict[str, Any]) -> str:
    return (
        f"{_field(row, 'processes', 'time')} "
        f"host={_field(row, 'processes', 'host')} "
        f"user={_field(row, 'processes', 'user')} "
        f"process={_field(row, 'processes', 'process')} "
        # CIM `parent_process` is the parent's command line, so cap it like cmdline.
        f"parent={_truncate(_field(row, 'processes', 'parent'), _CMDLINE_LIMIT)} "
        f"code={_field(row, 'processes', 'code')} "
        f"cmdline={_truncate(_field(row, 'processes', 'cmdline'), _CMDLINE_LIMIT)}"
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
        f"{_sanitise(str(k))}="
        + _truncate(_utc(_sanitise(str(v))) if str(k).lower() in _TIME_KEYS else _sanitise(str(v)), 80)
        for k, v in items
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
      by falling back. Both bare tokens and key=value values count as content
      unless built purely from `_PLACEHOLDER_CHARS`.
    """
    tokens = line.split()[1:]
    if not tokens:
        return True
    for token in tokens:
        _, sep, value = token.partition("=")
        target = value if sep else token
        if set(target) - _PLACEHOLDER_CHARS:
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


# Which fields the aggregate groups by, per category. A subset of `_FIELDS`
# rather than all of it: `time` yields a range instead of a distribution, and
# the continuous columns (`bytes_in`, `bytes_out`, `bytes`) have no meaningful
# top-N. `cmdline` and `uri` are left out for a different reason -- they are
# near-unique per row, so a distribution over them is a list of the rows with
# extra steps, and it is the wide field that would spend the budget.
_SUMMARY_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "auth_events": ("user", "src", "dest", "action", "logon_type"),
    "dns_resolutions": ("src", "query", "answer", "rtype", "rcode"),
    "connections": ("src", "dest", "dest_port", "proto", "action"),
    "processes": ("host", "user", "process", "parent"),
}

_TOP_N = 5
"""How many values per dimension the aggregate names.

Bounded on purpose, and the bound is what keeps the summary a fixed cost: it must
not grow with the rows, or a large set would buy its own summary by pushing
`pack_evidence` down a rung of `_ROW_CAP_LADDER` and truncating further -- which
is the very hole this aggregate exists to close. See `packing.pack_evidence`."""

_SUMMARY_VALUE_LIMIT = 60
"""Per-value truncation inside the summary. A process path or a DNS name can be
long, and five of them on one line is where a dimension stops being compact."""

NO_TIME_MARKER = "no timestamp on these rows — they have no time range"
"""What the summary's time line says when the rows carry no timestamp.

Read by `analyze._drop_unsupported_figures`, which uses it to decide whether a
cited set can support a time range at all. A second hand-written copy of this
string there would silently stop matching the day the wording is improved, and
the gate would quietly pass every invented range -- so it is named here, beside
the code that emits it, and imported rather than restated."""

_MAX_GENERIC_DIMENSIONS = 6
"""How many keys an `uncategorised` set is summarised over.

Untagged sets have no known schema (`_format_generic` says why), so the keys are
whatever the rows carry -- which on an estate-summary set is a handful and on a
raw event set can be dozens. Bounded for the same reason as `_TOP_N`."""


def _row_weight(row: dict[str, Any]) -> int:
    """How many events one row stands for: its `count=`, else 1.

    The same reading of the same column `_count_suffix` renders and
    `_event_total` sums, so a `| stats count by ...` set aggregates by events
    rather than by groups. A row whose `count` is not an integer weighs 1 --
    the alternative is discarding the row from every distribution because one
    column was malformed.
    """
    raw = _first(row, *_COUNT_FIELD, default="")
    try:
        return max(int(str(raw).strip()), 0)
    except (TypeError, ValueError):
        return 1


def _generic_dimensions(rows: Sequence[dict[str, Any]]) -> list[str]:
    """Dimension keys for a set with no CIM schema: the row keys themselves.

    Ordered by how many rows carry them, so a key present on every row is
    summarised before one that appears on a handful. `count` is excluded -- it
    is the weight, not a dimension -- as is anything that looks like the time
    column, which `_time_range` reports instead.
    """
    tally: dict[str, int] = {}
    for row in rows:
        for key in row:
            name = str(key)
            if name.lower() in _COUNT_FIELD or name.lower() in _TIME_KEYS:
                continue
            tally[name] = tally.get(name, 0) + 1
    ranked = sorted(tally, key=lambda k: (-tally[k], k))
    return ranked[:_MAX_GENERIC_DIMENSIONS]


_TIME_KEYS = frozenset({"time", "_time", "timestamp"})


def _time_range(rows: Sequence[dict[str, Any]], candidates: tuple[str, ...]) -> str | None:
    """Earliest and latest timestamp across ALL rows, or `None` if they carry none.

    `None` is a real answer and the caller renders it as such. A `| stats count
    by <fields>` set that did not group by `_time` has no time of its own, and
    the analyst asked to describe it used to supply one anyway: on the
    2026-09-02 authorization run a `processes` set whose rows carry no time at
    all was reported as spanning 11:04 to 17:17.

    Sorted by parsed value where every value parses, and lexically otherwise --
    ISO-8601 strings sort correctly as text only while their offsets agree, and
    falling back rather than raising keeps an odd sourcetype from costing the
    whole summary.
    """
    values = [_utc(v) for v in (_first(row, *candidates, default="") for row in rows) if v]
    if not values:
        return None
    try:
        ordered = sorted(values, key=lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")))
    except ValueError:
        ordered = sorted(values)
    if ordered[0] == ordered[-1]:
        return ordered[0]
    return f"{ordered[0]} … {ordered[-1]}"


def summarise_rows(
    category: str, rows: Sequence[dict[str, Any]], *, header_id: str = ""
) -> str | None:
    """A computed account of EVERY row in a set, for the rows the cap withheld.

    This is `_event_total`'s rule applied to the rest of the numbers: *code
    supplies every number, the model authors none*, computed over all rows and
    not the capped subset, because the rows the cap withheld are exactly the
    ones the analyst cannot count. `_event_total` did that for one figure -- the
    event total in the header -- after a model summing a `count=` column by hand
    reported 1,063 in a narrative and 1,083 in an observation drawn from the
    same set (`cli-20260823T112627`).

    The hole this closes is larger than that one. `pack_evidence` settles on a
    rung of `_ROW_CAP_LADDER` and the analyst reads that many rows, while the
    prompt asks it to group and count the whole set -- 20 of `processes#2`'s 100
    rows on the 2026-09-02 authorization run. It cannot, so it interpolates:
    that finding's lead observation reported "124 processes … 18 distinct images
    … 46 repeated command lines", which are the three figures in the endpoint
    prompt's own worked example and appear nowhere in the rows.

    Returns `None` for an empty set -- `format_result_set` already renders
    `(no rows returned)` and a summary of nothing would say it twice.

    Cost is bounded and independent of row count (`_TOP_N`,
    `_SUMMARY_VALUE_LIMIT`, `_MAX_GENERIC_DIMENSIONS`); see `_TOP_N` for why
    that is load-bearing rather than tidiness.
    """
    if not rows:
        return None

    weights = [_row_weight(row) for row in rows]
    total = sum(weights)
    # The header id is repeated here, and it is not decoration. Sets are rendered
    # back to back, so an unlabelled summary sits between two headers and reads as
    # belonging to either -- on the 2026-09-05 replay the model wrote an
    # observation about `processes#6` out of `processes#2`'s parent distribution
    # (110, 206, 74, 52), and cited `processes#6` for all four. Naming the set on
    # its own summary is what makes the block self-identifying.
    lines = [
        f"~ {header_id + ' — ' if header_id else ''}computed over all {len(rows)} rows"
        + (f" ({total} events)" if total != len(rows) else "")
        + ":"
    ]

    time_candidates = _FIELDS.get(category, {}).get("time", ("time", "_time", "timestamp"))
    span = _time_range(rows, time_candidates)
    lines.append(f"  time: {span}" if span else f"  time: {NO_TIME_MARKER}")

    dimensions = _SUMMARY_DIMENSIONS.get(category)
    generic = dimensions is None
    names = list(dimensions) if dimensions else _generic_dimensions(rows)

    for name in names:
        tally: dict[str, int] = {}
        for row, weight in zip(rows, weights):
            value = (
                _first(row, name, default="-") if generic else _field(row, category, name)
            )
            tally[value] = tally.get(value, 0) + weight
        if len(tally) == 1 and "-" in tally:
            continue  # the field is absent from every row; saying so per row is noise
        ranked = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
        more = ""
        if len(ranked) > _TOP_N:
            # The rarest values too, at the same fixed cost. A top-N alone hides
            # the outlier: on check-K1 a parent with 8 of 17,882 events sat in
            # "… 11 more" under the real binary's 17,280, and the row cap hid
            # its rows (B1). Counts only -- which value matters is not ours to say.
            # Strictly rarer than the top five, or "rarest" names an arbitrary tie.
            floor = ranked[_TOP_N - 1][1]
            rare = [kv for kv in reversed(ranked[_TOP_N:]) if kv[0] != "-" and kv[1] < floor][:_TOP_N]
            more = f", … {len(ranked) - _TOP_N} more"
            if rare:
                more += "; rarest: " + ", ".join(
                    f"{_truncate(_sanitise(value), _SUMMARY_VALUE_LIMIT)}={count}"
                    for value, count in rare
                )
        rendered = ", ".join(
            f"{_truncate(_sanitise(value), _SUMMARY_VALUE_LIMIT)}={count}"
            for value, count in ranked[:_TOP_N]
        )
        lines.append(f"  {name}: {len(tally)} distinct — {rendered}{more}")

    return "\n".join(lines)


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
    formatter = _FORMATTERS.get(category)
    lines: list[str] = []
    empty_count = 0

    for row in shown:
        if formatter is not None and _projection_is_empty(formatter(row)):
            empty_count += 1
            lines.append(_format_generic(row))
        else:
            lines.append(format_row(category, row))

    if empty_count > 0:
        lines.append(f"… ({empty_count} of {len(shown)} shown rows projected nothing into {category} schema)")

    if len(result_set.rows) > row_cap:
        lines.append(f"… ({len(result_set.rows) - row_cap} more rows not shown)")

    # Rendered for EVERY set, not only a truncated one. A capped set needs it
    # because the analyst cannot count rows it was never shown; a fully printed
    # set needs it too, because being visible has not been enough -- on the
    # 2026-09-02 consent run `uncategorised#16` was printed whole and still had
    # seven index totals attributed to it that appear nowhere in its rows.
    summary = summarise_rows(category, result_set.rows, header_id=f"{category}#{index}")
    if summary:
        lines.append(summary)
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
