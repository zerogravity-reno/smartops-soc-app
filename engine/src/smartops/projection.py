"""Turning captured tool output into typed `Findings`. Code only, never a model.

This is the second layer of the two-layer payload. The model authors a small
assessment; **code** supplies every row, from what the tools actually returned,
**and code decides which CIM category each result set belongs to** by reading the
SPL the tool was actually called with.

Neither half can forge the other: a model that never sees the rows cannot invent
them, and code that never reads the prompt cannot be talked into re-categorising.

The category used to come from the model's own `QueryRun.category`, matched to the
executed call by query text. See `SiemFindings` for the measurement that ended
that: the model's report of its own queries is a recollection, and the match
missed on 66 result sets of which only 4 were recoverable by any string
similarity. Its tag is still read, and a disagreement with the SPL is still
logged -- it is now the cross-check rather than the decision.
"""

from __future__ import annotations

import logging
import re
from typing import Any, get_args

from contracts.findings import VtFindings, VtVerdict
from contracts.subtask import evidence_id as _evidence_id

from smartops.guards import _LOOKS_LIKE_SEARCH

from contracts import CimCategory, Findings, QueryRun, ResultSet, SiemFindings

logger = logging.getLogger(__name__)

_CIM_BUCKETS: tuple[CimCategory, ...] = get_args(CimCategory)

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


_ROW_KEYS = ("results", "rows", "records", "events")


def _rows_of(payload: Any) -> list[dict[str, Any]]:
    """Rows inside a tool result, without knowing the server's envelope.

    Tries the common shapes and gives up honestly rather than guessing: an
    unrecognised payload yields no rows and is reported as a zero-row result set,
    which is visible, instead of being silently reshaped into something wrong.

    **`structuredContent` is unwrapped first, and that is not a nicety.** A tool
    reached through a live `Agent` returns
    `{"status":…, "content":[…], "structuredContent": {"results": [...]}, …}`,
    so looking only at the top level found no `results` key and every projected
    finding came back with `row_count=0` and `rows=[]`. Measured on a 10-case
    live run: 54 siem evidence items carried real rows -- 100, 2, 100 and so on
    -- and the projection saw zero for all of them.

    The evidence itself was always captured correctly, which is why citations
    resolved and nothing looked broken. What was empty was the typed findings
    payload, which is the entire point of assembling findings in code.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in _ROW_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        # Envelope, not payload: recurse once into the field that carries the
        # real body rather than teaching every caller about the wrapper.
        inner = payload.get("structuredContent")
        if isinstance(inner, dict | list):
            return _rows_of(inner)
    return []


def _has_eventcode(q: str, code: int) -> bool:
    """Whether `q` references Windows/Sysmon `EventCode=<code>` exactly.

    A word boundary on the trailing digit is load-bearing: a bare substring test
    (`"eventcode=1" in q`) also matches `eventcode=10`, `13`, `100`, ... so a
    Sysmon file-create (11) or registry (13) event would be mis-read as a process
    (1) event. The negative lookahead pins the number to exactly `code`.
    """
    return re.search(rf"eventcode={code}(?![0-9])", q) is not None


# Windows Security and Sysmon event codes to the category one such event is. One
# table for both readers: `_infer_cim_category` (what a query asks for) and
# `_split_by_event_code` (what each returned row is). On 8807fafa a query asking
# for `EventCode=1 OR 3 OR 4688` was filed whole under connections, so the step
# that wanted its process rows counted 0 (B28).
_EVENTCODE_CATEGORIES: dict[int, CimCategory] = {
    1: "processes", 4688: "processes",
    3: "connections", 5156: "connections", 5157: "connections",
    22: "dns_resolutions",
    11: "file_events", 15: "file_events", 23: "file_events", 26: "file_events", 29: "file_events",
    12: "registry_events", 13: "registry_events", 14: "registry_events",
    4104: "script_blocks",
    4624: "auth_events", 4625: "auth_events", 4648: "auth_events", 4672: "auth_events",
}


def _names_code_of(q: str, category: CimCategory) -> bool:
    """Whether `q` names any event code that `category`'s events carry."""
    return any(_has_eventcode(q, c) for c, cat in _EVENTCODE_CATEGORIES.items() if cat == category)


_DATAMODEL = re.compile(r"\bdatamodel\s*=\s*[\"']?(\w+(?:\.\w+)?)")

# Data model (or `Model.Dataset`) to category. Only the datasets a category
# means: `endpoint.filesystem` and `endpoint.registry` are not process rows.
_DATAMODEL_CATEGORIES: dict[str, CimCategory] = {
    "endpoint.processes": "processes",
    "network_traffic": "connections",
    "network_traffic.all_traffic": "connections",
    "network_resolution": "dns_resolutions",
    "network_resolution.dns": "dns_resolutions",
    "authentication": "auth_events",
    "authentication.authentication": "auth_events",
    "endpoint.filesystem": "file_events",
    "endpoint.registry": "registry_events",
}


def _infer_cim_category(query: str | None) -> CimCategory | None:
    """Infer CIM category from SPL predicates when the subagent did not explicitly tag it."""
    if not query:
        return None
    q = query.lower()

    # 0. A `tstats` over a CIM data model names its category outright. The siem
    # prompt steers the subagent to these, and without this rule every one of
    # them was filed `uncategorised`: on check-K1, every `Endpoint.Processes`
    # set, including the rows carrying the masquerading parent's path (B1).
    datamodel = _DATAMODEL.search(q)
    if datamodel and datamodel.group(1) in _DATAMODEL_CATEGORIES:
        return _DATAMODEL_CATEGORIES[datamodel.group(1)]

    # 0b. Before processes: a Sysmon file or registry query often also names
    # `parentimage`/`image`, and 4104 rows are not process starts. On 148b0e69
    # these rows went `uncategorised` and synthesis said "no file writes".
    if _names_code_of(q, "file_events") or "targetfilename" in q:
        return "file_events"
    if _names_code_of(q, "registry_events") or "targetobject" in q:
        return "registry_events"
    if _names_code_of(q, "script_blocks") or "scriptblocktext" in q:
        return "script_blocks"

    # 1. DNS Resolution (Network Resolution)
    if (
        "stream:dns" in q
        or "tag=dns" in q
        or "tag::eventtype=dns" in q
        or _names_code_of(q, "dns_resolutions")  # Sysmon 22: DNS query
        or "dns_resolvers" in q
        or "dns_resolution" in q
    ):
        return "dns_resolutions"

    # 2. Network Traffic (Connections)
    if (
        "stream:tcp" in q
        or "stream:http" in q
        or "stream:ip" in q
        or "cisco:asa" in q
        or "cisco:ios" in q
        or "pan:traffic" in q
        or "symantec:ep:traffic" in q
        or "fortigate_traffic" in q  # the lab's firewall (B28)
        or "index=fortigate" in q
        or _names_code_of(q, "connections")  # Sysmon 3, WFP 5156/5157
        or "listeningports" in q
    ):
        return "connections"

    # 3. Endpoint Processes
    if (
        _names_code_of(q, "processes")  # Security 4688, Sysmon 1
        or "perfmonmk:process" in q
        or "symantec:ep:behavior" in q
        or "new_process_name" in q
        or "process_command_line" in q
        or "parentimage" in q
        or "pack_incident-response_processes" in q
        or "winhostmon" in q
    ):
        return "processes"

    # 4. Authentication
    if (
        _names_code_of(q, "auth_events")  # 4624/4625 logon, 4648 explicit creds, 4672 privileges
        or "tag=authentication" in q
        or "unix:useraccounts" in q
        or "unix:sshdconfig" in q
    ):
        return "auth_events"

    return None


def _is_search(query: str | None) -> bool:
    """Whether this call queried the estate, as opposed to describing it.

    A shape test on the recovered query, deliberately not a list of tool names:
    the tool schema comes from whichever MCP server is configured, which is the
    same reason `_query_of` and `IndexScopeGuard` scan the whole input rather
    than naming a parameter. Reuses the guard's own regex so "is this a search"
    has one definition -- a string that scopes nothing has nothing to categorise
    and nothing to say about a hypothesis.

    Confirmed against the 2026-09-02 run: `splunk_get_metadata` and
    `splunk_get_indexes` calls recover `sourcetypes`, a bare epoch
    (`1534723200`), or nothing at all, and every `splunk_run_query` recovers real
    SPL.
    """
    return bool(query) and _LOOKS_LIKE_SEARCH.search(query) is not None


_TSTATS = re.compile(r"\|\s*tstats\b")


def _describes_estate(query: str | None) -> bool:
    """A call that says what Splunk holds rather than what happened.

    No search at all, or a `tstats` over raw indexes (no data model): the siem
    prompt's first query, `| tstats count … by index, sourcetype`, returns event
    counts per index. Filed as evidence, every narrative reported "2105 Windows
    event log entries with no timestamp", and on 89674d75 synthesis read that as
    "high-volume uncategorized events showing suspicious activity" (B29).
    """
    if not _is_search(query):
        return True
    q = query.lower()
    return _TSTATS.search(q) is not None and _DATAMODEL.search(q) is None


def _split_by_event_code(rows: list[dict[str, Any]], category: CimCategory | None) -> dict[CimCategory | None, list]:
    """Rows grouped by the category their own `EventCode` names, else `category`.

    Only event rows (with `_time`) are moved: a `stats count by EventCode` row is a
    count, not an event, and must not complete a step as if it were one.
    """
    groups: dict[CimCategory | None, list] = {}
    for row in rows:
        code = str(row.get("EventCode", "")).strip()
        own = _EVENTCODE_CATEGORIES.get(int(code)) if "_time" in row and code.isdigit() else None
        groups.setdefault(own or category, []).append(row)
    return groups


def project_siem(calls: list[Any], queries_run: list[QueryRun], task_id: str) -> SiemFindings:
    """Bucket each executed call's rows into the CIM category **its SPL** implies.

    `queries_run` is read only to cross-check the model's own tag against what
    the SPL says, and to log the disagreement. It no longer decides -- see the
    module docstring.
    """
    by_query: dict[str, CimCategory | None] = {
        _normalise(q.query): q.category for q in queries_run
    }

    buckets: dict[str, list[ResultSet]] = {name: [] for name in _CIM_BUCKETS}
    buckets["uncategorised"] = []
    buckets["discovery"] = []

    for index, call in enumerate(calls):
        rows = _rows_of(call.payload)
        result_set = ResultSet(
            query=call.query or f"<{call.tool}: query not recoverable from tool input>",
            row_count=len(rows),
            rows=rows,
            # Index-aligned with `_EvidenceCollector.evidence()`, which mints ids
            # from `enumerate(self.calls)` over this same list. That alignment is
            # the entire basis of the back-reference, so both sides call the one
            # shared formula rather than keeping two copies of a format string.
            evidence_id=_evidence_id(task_id, index),
        )

        # Estate description, not evidence. Split off BEFORE categorising: these
        # calls carry no search, so every one of them would otherwise fall
        # through to `uncategorised` and be offered to an analyst as citable
        # rows -- which is how a delivered narrative came to describe Splunk's
        # `_internal` index and hosts outside the scope. See
        # `SiemFindings.discovery`.
        if _describes_estate(call.query):
            logger.info(
                "tool=%s | no evidence search in this call's input, filing as discovery "
                "(describes the estate, not evidence about the hypothesis)",
                call.tool,
            )
            buckets["discovery"].append(result_set)
            continue

        category = _infer_cim_category(call.query)

        # The model's own tag, kept as a cross-check. A disagreement means one of
        # the two read the query differently, and it is worth seeing: before code
        # took precedence, a Sysmon `EventCode=3` (network connection) tagged
        # `auth_events` was filed under the tag, and an identity analyst wrote a
        # narrative from network rows for a hypothesis that had no auth step at
        # all. Absence of a match is no longer notable -- the model reports fewer
        # queries than it runs, so most calls have no counterpart to compare.
        tagged = by_query.get(_normalise(call.query))
        if tagged in _CIM_BUCKETS and category in _CIM_BUCKETS and tagged != category:
            logger.warning(
                "task_id=%s tool=%s | model tagged this query '%s' but its SPL "
                "infers '%s'; filing under the SPL. query=%r",
                task_id,
                call.tool,
                tagged,
                category,
                (call.query or "")[:200],
            )
        elif tagged in _CIM_BUCKETS and category is None:
            # Not a contradiction -- there is nothing to contradict. The tag is
            # more specific than the SPL, so it is the model's claim that is
            # dropped here, and these rows go to `uncategorised`. Info rather
            # than warning: it is the aggregate that means something, and what it
            # means is that `_infer_cim_category` is meeting a shape it should
            # learn (`sourcetype=WinEventLog | stats count by EventCode` spans
            # all four models, so some of these are correctly unlearnable).
            logger.info(
                "tool=%s | model tagged this query '%s' but its SPL infers no "
                "category; filing as uncategorised. query=%r",
                call.tool,
                tagged,
                (call.query or "")[:200],
            )

        groups = _split_by_event_code(rows, category)
        if len(groups) > 1 or next(iter(groups), category) != category:
            # One call, several kinds of event: one set per kind, all pointing at
            # the same evidence id, since they came from the same call (B28).
            for kind, part in groups.items():
                piece = result_set.model_copy(update={"rows": part, "row_count": len(part)})
                buckets[kind if kind in _CIM_BUCKETS else "uncategorised"].append(piece)
        elif category in _CIM_BUCKETS:
            buckets[category].append(result_set)
        else:
            # A search whose shape `_infer_cim_category` does not recognise. The
            # rows are real and were paid for, so they are kept and offered --
            # what is missing is the attribution, and a full bucket here is the
            # signal to teach `_infer_cim_category` a shape it is meeting.
            logger.info(
                "tool=%s | no CIM category inferable from this SPL, filing as "
                "uncategorised -- query=%r",
                call.tool,
                (call.query or "")[:200],
            )
            buckets["uncategorised"].append(result_set)

    return SiemFindings(**buckets)


def project_vt(calls: list[Any], task_id: str) -> VtFindings:
    """Project captured VT tool calls into VtFindings."""
    verdicts: list[VtVerdict] = []
    for index, c in enumerate(calls):
        # Same index alignment as `project_siem`; see the comment there.
        eid = _evidence_id(task_id, index)
        payload = getattr(c, "payload", c)
        tool_name = getattr(c, "tool", "vt_lookup")
        query_val = getattr(c, "query", None)

        if isinstance(payload, dict) and "verdicts" in payload:
            for v in payload["verdicts"]:
                if isinstance(v, VtVerdict):
                    verdicts.append(v if v.evidence_id else v.model_copy(update={"evidence_id": eid}))
                elif isinstance(v, dict):
                    # Spread the payload AFTER the default so a payload that
                    # already carries `evidence_id` wins. Passing it as a keyword
                    # alongside `**v` would be a duplicate-keyword TypeError the
                    # moment such a payload appeared.
                    verdicts.append(VtVerdict(**{"evidence_id": eid, **v}))
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
                        evidence_id=eid,
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
                        evidence_id=eid,
                    )
                )
    return VtFindings(verdicts=verdicts)


def project(
    family: str, calls: list[Any], queries_run: list[QueryRun], task_id: str
) -> Findings | None:
    """The family's typed payload, or `None` where the family has no projector.

    Every family with a projector dispatches HERE. `project_vt` used to be
    appended at one call site instead (`or project_vt(...)` in `investigate`'s
    success path), which is why the sibling no-answer branch -- calling this
    function plainly, as documented -- reported `findings=None` for a vt subagent
    that still held real evidence. A dispatcher that only half-dispatches makes
    every caller responsible for knowing which half.
    """
    if family == "siem":
        return project_siem(calls, queries_run, task_id)
    if family == "vt":
        # `queries_run` is unused: a reputation lookup has no query to categorise,
        # so the verdicts come straight off the calls.
        return project_vt(calls, task_id)
    return None
