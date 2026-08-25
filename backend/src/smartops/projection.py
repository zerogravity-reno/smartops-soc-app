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
from contracts.subtask import evidence_id as _evidence_id

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


def _infer_cim_category(query: str | None) -> CimCategory | None:
    """Infer CIM category from SPL predicates when the subagent did not explicitly tag it."""
    if not query:
        return None
    q = query.lower()

    # 1. DNS Resolution (Network Resolution)
    if (
        "stream:dns" in q
        or "tag=dns" in q
        or "tag::eventtype=dns" in q
        or _has_eventcode(q, 22)  # Sysmon: DNS query
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
        or _has_eventcode(q, 3)  # Sysmon: network connection
        or _has_eventcode(q, 5156)  # WFP: allowed connection
        or _has_eventcode(q, 5157)  # WFP: blocked connection
        or "listeningports" in q
    ):
        return "connections"

    # 3. Endpoint Processes
    if (
        _has_eventcode(q, 4688)  # Windows Security: process create
        or _has_eventcode(q, 1)  # Sysmon: process create
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
        _has_eventcode(q, 4624)  # successful logon
        or _has_eventcode(q, 4625)  # failed logon
        or _has_eventcode(q, 4648)  # explicit-credential logon
        or _has_eventcode(q, 4672)  # special privileges assigned
        or "tag=authentication" in q
        or "unix:useraccounts" in q
        or "unix:sshdconfig" in q
    ):
        return "auth_events"

    return None


def project_siem(calls: list[Any], queries_run: list[QueryRun], task_id: str) -> SiemFindings:
    """Bucket each executed call's rows into the CIM category its query was tagged with."""
    by_query: dict[str, CimCategory | None] = {
        _normalise(q.query): q.category for q in queries_run
    }

    buckets: dict[str, list[ResultSet]] = {name: [] for name in _CIM_BUCKETS}
    buckets["uncategorised"] = []

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

        category = by_query.get(_normalise(call.query)) if call.query else None
        if category in _CIM_BUCKETS:
            buckets[category].append(result_set)
        else:
            inferred = _infer_cim_category(call.query)
            if inferred in _CIM_BUCKETS:
                logger.info(
                    "tool=%s | query was untagged by model, inferred CIM category '%s' from SPL",
                    call.tool,
                    inferred,
                )
                buckets[inferred].append(result_set)
            else:
                logger.info(
                    "tool=%s | result set not tagged with a CIM category, filing as uncategorised",
                    call.tool,
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
