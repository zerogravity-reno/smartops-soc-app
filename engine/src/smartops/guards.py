"""Boundaries enforced in code rather than in a prompt.

A prompt instruction is a request. Anything the system must be able to state as a
fact -- what a subagent is allowed to query, what it is allowed to touch -- has to
be enforced somewhere the model cannot argue with. Strands' `BeforeToolCallEvent`
is that place: a hook can cancel a tool call before it runs, and the cancellation
message comes back to the model as the tool result, so the model can correct
itself rather than simply failing.
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# `index=foo`, `index = "foo"`, `index=*`. The value stops at whitespace or the
# characters that end a term in SPL.
_INDEX_TERM = re.compile(r"\bindex\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s()|,]+)", re.IGNORECASE)

# Whether a string is a search at all. A tool that lists indexes or describes a
# sourcetype takes no SPL and must not be required to pin an index.
#
# `datamodel=`/`tag=`/`eventtype=` are here for the same reason `sourcetype=`
# is: rule 2 below accepts any of the four CIM predicates in place of a literal
# index, but a bare Splunk base search using only one of them (Splunk implies
# `search` on a bare filter, so it needs no pipe and no literal `search`
# keyword) used to match none of the other alternatives -- so `_reject_reason`
# treated it as "not a search at all" and exempted it from scoping entirely,
# rather than reaching rule 2 to actually validate it.
_LOOKS_LIKE_SEARCH = re.compile(
    r"\bindex\s*=|\bsourcetype\s*=|\bdatamodel\s*=|\btag\s*=|\beventtype\s*="
    r"|\bearliest\s*=|\blatest\s*=|\|\s*\w|^\s*search\b",
    re.IGNORECASE,
)

# A CIM-compliant predicate scopes a search without a literal `index=`, by
# selecting a data model Splunk maps to its own indexes. Module-level like every
# other pattern here: this one is evaluated once per string per tool call.
_CIM_PREDICATES = re.compile(r"\b(sourcetype|datamodel|tag|eventtype)\s*=", re.IGNORECASE)


def escape_untrusted(text: str) -> str:
    """Make attacker-influenced prose unable to carry markup into a prompt.

    Prompt framing is the only injection defence on this path, and a fence the
    quoted content can reproduce is not a fence. The previous approach defanged
    one literal closing tag per call site (`text.replace("</goal>", ...)`), which
    missed `</GOAL>`, `</ goal>`, and -- unfixably -- an attacker who *opens* a
    new tag instead of closing this one. Tags cannot be enumerated; `<` can.

    So escape the three characters that make markup, which closes all of those at
    once and needs to know nothing about the surrounding tag. A goal that
    legitimately mentions `<` reads fine as `&lt;` and the tampering stays
    visible, which is why this escapes rather than strips.

    `&` goes first: escaping `<` to `&lt;` and *then* escaping `&` would turn it
    into `&amp;lt;`.

    Strands ships no public equivalent. It has `_escape_xml_text` /
    `_escape_xml_attr` (`strands/injection/_xml.py:12,26`), whose module names
    this same threat, but `strands/injection/__init__.py` exports only the
    `Injection*` config types -- the escapers are private and reachable only
    through `ContextInjector` / `MemoryManager`, neither of which is on this path.
    Verified against installed 1.51.0.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fenced(tag: str, body: str) -> str:
    """Wrap `body` in a named region a prompt can point at as data.

    Deliberately separate from `escape_untrusted`, and deliberately does not
    escape: a fence's *body* is not always untrusted prose. The entity block is
    assembled by code from values `contracts.Entity` has already refused
    structure in, and escaping it would mutate indicators the model must retype
    verbatim. Composing the two at the call site keeps "was this escaped?" a
    visible decision instead of a hidden default.
    """
    return f"<{tag}>\n{body}\n</{tag}>"


class IndexScopeGuard:
    """Rejects a domain's queries that target an index outside its allowlist.

    Registered per subagent from `DomainSpec.index_allowlist`. The rule, on
    anything that looks like a search:

    1. If the search names any index, every one of them must be in the
       allowlist. `index=*` is never allowed.
    2. Otherwise, a CIM-compliant predicate (`sourcetype=`, `datamodel=`,
       `tag=`, `eventtype=`) is accepted in place of a literal index, because
       that is how the siem prompt tells the model to write its SPL and it
       scopes the search by data model rather than by index name.
    3. A search with neither is rejected as unconstrained.

    Rule 2 is a relaxation of the spec's original "require a literal allowlisted
    `index=`", and it is a real widening: such a search runs against whatever
    indexes the Splunk token can read. That is the deployment control below
    doing the work, not this hook.

    Queries cancelled under any of these are recorded on `blocked`, because a
    cancelled call produces an error tool result and `_EvidenceCollector` drops
    those -- leaving no record anywhere that the model attempted an escape.

    **This is a correctness guardrail, not a security control, and the difference
    matters.** Deciding "this SPL targets only allowed indexes" by inspecting the
    string is not decidable in general -- subsearches, macros, `tstats` and
    lookups all reach data by routes this never sees. It reliably catches the
    observed failure (every SPL in the 2026-08-11 run used `index=*`) and it
    raises the cost of an injected instruction, but a determined adversary who
    controls the query string can get past it.

    The strong version of this control costs no code and belongs in deployment:
    **scope the Splunk token to the allowed indexes**, and `index=*` returns only
    those regardless of what any model writes, enforced server-side. This hook is
    what stops an unhelpful or confused model; the token scope is what stops an
    adversary.
    """

    def __init__(self, family: str, allowlist: tuple[str, ...]) -> None:
        self._family = family
        self._allowlist = allowlist
        self._allowed = frozenset(name.strip().lower() for name in allowlist)
        self.blocked: list[str] = []
        """Every query string this guard cancelled, in the order it cancelled them."""

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        from strands.hooks import BeforeToolCallEvent

        registry.add_callback(BeforeToolCallEvent, self._check)

    def _check(self, event: Any) -> None:
        tool_use = event.tool_use or {}
        name = tool_use.get("name", "unknown")

        for value in _strings_in(tool_use.get("input")):
            reason = self._reject_reason(value)
            if reason is None:
                continue
            # Logged at warning because the run this exists for was invisible
            # without a raw span dump -- a blocked query is worth seeing.
            logger.warning(
                "family=%s, tool=%s | tool call cancelled by index scope guard: %s",
                self._family,
                name,
                reason,
            )
            self.blocked.append(value)
            event.cancel_tool = reason
            return

    def _reject_reason(self, value: str) -> str | None:
        if not _LOOKS_LIKE_SEARCH.search(value):
            return None

        allowed = ", ".join(f"index={name}" for name in self._allowlist)
        targeted = [_unquote(m.group(1)) for m in _INDEX_TERM.finditer(value)]

        # If an explicit index predicate was provided, check it.
        if targeted:
            disallowed = [name for name in targeted if name.lower() not in self._allowed]
            if disallowed:
                shown = ", ".join(f"index={name}" for name in dict.fromkeys(disallowed))
                allowed = ", ".join(f"index={name}" for name in self._allowlist)
                return (
                    f"Rejected: {shown} is outside this deployment's allowed indexes. "
                    f"Use one of: {allowed}, or rely on CIM-compliant sourcetype/datamodel predicates. "
                    f"A wildcard index is never allowed -- reissue the query with an explicit index or sourcetype."
                )
            return None

        # No index predicate: a CIM predicate scopes it instead. See rule 2 in the
        # class docstring, including what that concedes.
        if _CIM_PREDICATES.search(value):
            return None

        # Completely unconstrained query with neither index nor CIM/sourcetype predicate.
        allowed = ", ".join(f"index={name}" for name in self._allowlist)
        return (
            f"Rejected: this search is unconstrained (no index or sourcetype/CIM predicate). "
            f"Please specify a sourcetype (e.g., sourcetype=stream:dns), a datamodel, or one of: {allowed}."
        )


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# The shortest identifier fragment allowed to satisfy the scope. A domain's first
# label is accepted alongside its full value (see `_match_terms`), and a
# one- or two-character label would match almost any SPL, which would make the
# guard pass everything for a scope containing `a.com`.
_MIN_TERM = 4


def _match_terms(entities: Any) -> set[str]:
    """The lowercased fragments a query may carry to prove it is in scope.

    An entity's own value, plus -- for a dotted value -- its first label. Both
    are needed, and the run that motivated this shows why in one pair of queries:
    the scope holds the domain `coinhive.com`, and the model wrote
    `index=botsv3 "coinhive" | stats count by sourcetype, host`, which contains
    no substring `coinhive.com` at all. Requiring the full value would have
    cancelled a search that was squarely in scope -- and a good one: it is what
    found a second host contacting the same domain.

    Values shorter than `_MIN_TERM` are dropped rather than accepted, so a short
    label cannot turn the guard into a no-op.
    """
    terms: set[str] = set()
    for entity in entities:
        value = str(getattr(entity, "value", entity)).strip().lower()
        if len(value) >= _MIN_TERM:
            terms.add(value)
        label = value.partition(".")[0]
        if len(label) >= _MIN_TERM:
            terms.add(label)
    return terms


class ScopeGuard:
    """Rejects a domain's queries that are anchored to nothing in the scope.

    `IndexScopeGuard`'s sibling, and deliberately not part of it: that guard asks
    "does this search target an allowed index", which is a question about the
    deployment. This one asks "does this search have anything to do with what we
    were asked about", which is a question about the mission. The 2026-09-02 run
    passed every one of these through the index guard, correctly, and still put a
    different host's DNS traffic into a delivered contract.

    The rule, on anything that looks like a search: it must carry at least one
    scope term (`_match_terms`). What that catches, from that run:

        index=botsv3 sourcetype="stream:dns" | head 5
        index=botsv3 sourcetype="stream:dns" | top 10 host
        index=botsv3 sourcetype=stream:dns | stats count by src_ip | head 20

    None names a host, user or domain. The first is where a hypothesis about
    `bostoll` on `BSTOLL-L` acquired a network narrative describing `JWORTOS-L`.

    **Identifiers learned during the run count as in scope**, harvested from the
    rows of calls that were themselves in scope. Without this the guard would
    break the legitimate pivot: resolving `BSTOLL-L` to `192.168.247.131` and
    then querying that address is how network evidence is actually reached, and
    the address is in no entity. Harvesting is restricted to IPv4 and to in-scope
    calls, and both restrictions are load-bearing -- harvesting hostnames would
    let one aggregate that slipped through name seven new hosts and adopt them
    all, and harvesting from out-of-scope calls would let the guard bootstrap
    itself open.

    **What this does not do.** It cannot bound which rows come back, only which
    searches go out, so a scoped search that returns a neighbouring host's rows
    still delivers them -- `index=botsv3 "coinhive" | stats count by host` is in
    scope and legitimately reports every host that hit the domain. Distinct
    hostnames in evidence is therefore not expected to reach one; what is
    expected is that every one of them traces to a query anchored on a real
    entity.

    Cancelled queries are recorded on `blocked` for the same reason
    `IndexScopeGuard` records them: a cancelled call yields an error tool result,
    `_EvidenceCollector` drops those, and nothing else would show the attempt.
    """

    def __init__(self, family: str, scope: Any) -> None:
        self._family = family
        self._terms = _match_terms(scope.entities)
        self._entities = ", ".join(f"{e.kind}={e.value}" for e in scope.entities)
        self.blocked: list[str] = []
        """Every query string this guard cancelled, in the order it cancelled them."""
        self.learned: set[str] = set()
        """Addresses harvested from in-scope results and since treated as in scope."""

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent, HookOrder

        registry.add_callback(BeforeToolCallEvent, self._check)
        # Same lowest-priority claim `_EvidenceCollector` makes, and for the same
        # reason: a plugin that rewrites an oversized result would otherwise
        # replace the rows this harvests the pivot addresses from.
        registry.add_callback(AfterToolCallEvent, self._learn, order=HookOrder.SDK_FIRST)

    def _in_scope(self, value: str) -> bool:
        haystack = value.lower()
        return any(term in haystack for term in self._terms | self.learned)

    def _check(self, event: Any) -> None:
        tool_use = event.tool_use or {}
        name = tool_use.get("name", "unknown")

        for value in _strings_in(tool_use.get("input")):
            if not _LOOKS_LIKE_SEARCH.search(value) or self._in_scope(value):
                continue
            reason = (
                f"Rejected: this search names nothing in the investigation's scope. "
                f"Every query must reference at least one of: {self._entities} "
                f"(or an address already resolved from one). Reissue it with a host, "
                f"user, address or domain predicate -- a survey of the whole index "
                f"returns other people's data and cannot answer this question."
            )
            logger.warning(
                "family=%s, tool=%s | tool call cancelled by scope guard: query "
                "carries no scope term -- query=%r",
                self._family,
                name,
                value[:200],
            )
            self.blocked.append(value)
            event.cancel_tool = reason
            return

    def _learn(self, event: Any) -> None:
        """Adopt addresses returned by a call that was itself in scope."""
        if getattr(event, "exception", None) is not None:
            return
        result = event.result
        if isinstance(result, dict) and result.get("status") == "error":
            return

        searches = [
            value
            for value in _strings_in((event.tool_use or {}).get("input"))
            if _LOOKS_LIKE_SEARCH.search(value)
        ]
        if not searches or not all(self._in_scope(value) for value in searches):
            return

        try:
            body = json.dumps(result, default=str)
        except (TypeError, ValueError):
            body = str(result)
        self.learned.update(_IPV4.findall(body))


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _strings_in(value: Any) -> list[str]:
    """Every string reachable in a tool's input, at any nesting depth.

    The guard cannot assume which parameter carries the query: the tool schema
    comes from whichever MCP server is configured, and differs between vendors.
    Checking every string is what makes this independent of that schema.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings_in(item)]
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _strings_in(item)]
    return []


_TSTATS_DATAMODEL = re.compile(
    r"\|\s*tstats\b.*?\bfrom\s+datamodel\s*=\s*([^\s()|,]+)", re.IGNORECASE
)

# `summariesonly=t`, or the ESCU macro that expands to it. Absent means `f`.
_SUMMARIES_ONLY = re.compile(
    r"\bsummariesonly\s*=\s*(?:t|true|1)\b|`security_content_summariesonly`", re.IGNORECASE
)

_DATAMODEL_ALTERNATIVES: dict[str, str] = {
    "network_resolution": "sourcetype=stream:dns",
    "network_traffic": "sourcetype=stream:tcp or sourcetype=stream:ip",
    "endpoint.processes": "sourcetype=WinEventLog EventCode=4688 or Sysmon EventCode=1",
    "endpoint": "sourcetype=WinEventLog EventCode=4688 or Sysmon EventCode=1",
    "authentication": "sourcetype=WinEventLog EventCode=4624",
}


class TstatsDeadEndGuard:
    """Cancels `tstats` queries against datamodels known to return zero rows.

    Learned per run, in two steps, because "0 rows" means two different things:

    1. `summariesonly=t` returned 0 rows. The datamodel may simply be
       unaccelerated -- the raw events are still there. `X` goes on
       `summaries_empty`, and a further `summariesonly=t` query against it is
       cancelled with an instruction to retry the same query as
       `summariesonly=f`, which searches the raw events through the model.
    2. `summariesonly=f` (or no flag, which is `f`) returned 0 rows. Now the
       datamodel really is empty here. `X` goes on `dead_datamodels`, and every
       further `tstats` against it is cancelled with the raw-sourcetype
       alternative.

    Step 1 used to be the whole rule, so one empty accelerated query sent the
    subagent to hand-written sourcetype searches and it never tried the
    unaccelerated path, which is also CIM-normalised across sourcetypes.
    """

    def __init__(self, family: str) -> None:
        self._family = family
        self.blocked: list[str] = []
        """Every query string this guard cancelled, in the order it cancelled them."""
        self.dead_datamodels: set[str] = set()
        """Datamodels whose unaccelerated tstats returned 0 rows in this run."""
        self.summaries_empty: set[str] = set()
        """Datamodels whose `summariesonly=t` tstats returned 0 rows in this run."""

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent, HookOrder

        registry.add_callback(BeforeToolCallEvent, self._check)
        registry.add_callback(AfterToolCallEvent, self._learn, order=HookOrder.SDK_FIRST)

    def _extract_datamodel(self, value: str) -> str | None:
        match = _TSTATS_DATAMODEL.search(value)
        if not match:
            return None
        return _unquote(match.group(1)).strip().lower()

    def _check(self, event: Any) -> None:
        tool_use = event.tool_use or {}
        name = tool_use.get("name", "unknown")

        for value in _strings_in(tool_use.get("input")):
            dm = self._extract_datamodel(value)
            if dm is None:
                continue
            if dm in self.dead_datamodels:
                alt = _DATAMODEL_ALTERNATIVES.get(dm, f"specific sourcetypes directly for {dm}")
                reason = (
                    f"Rejected: `tstats` against datamodel '{dm}' returned 0 rows both from "
                    f"acceleration summaries and from raw events (summariesonly=f), so it is "
                    f"unpopulated in this environment. "
                    f"Query specific sourcetypes directly instead (e.g., {alt})."
                )
            elif dm in self.summaries_empty and _SUMMARIES_ONLY.search(value):
                reason = (
                    f"Rejected: `summariesonly=t` against datamodel '{dm}' already returned 0 rows, "
                    f"which usually means the datamodel is not accelerated, not that the data is "
                    f"absent. Run the same query with `summariesonly=f` instead: it searches the "
                    f"raw events through the datamodel. The time window is applied for you."
                )
            else:
                continue
            logger.warning(
                "family=%s, tool=%s | tool call cancelled by tstats dead-end guard: datamodel=%s",
                self._family,
                name,
                dm,
            )
            self.blocked.append(value)
            event.cancel_tool = reason
            return

    def _learn(self, event: Any) -> None:
        """Record datamodels whose `tstats` query yielded 0 rows."""
        if getattr(event, "exception", None) is not None:
            return
        result = event.result
        if isinstance(result, dict) and result.get("status") == "error":
            return

        for value in _strings_in((event.tool_use or {}).get("input")):
            dm = self._extract_datamodel(value)
            if dm is None:
                continue

            if self._result_is_empty(result):
                if _SUMMARIES_ONLY.search(value):
                    self.summaries_empty.add(dm)
                else:
                    self.dead_datamodels.add(dm)

    def _result_is_empty(self, result: Any) -> bool:
        if result is None:
            return True
        if isinstance(result, dict):
            # The official Splunk MCP server answers `{"results": [...]}` inside the
            # ToolResult's `structuredContent`, which no key below looked at -- so
            # against the real server this never saw an empty result.
            inner = result.get("structuredContent")
            if isinstance(inner, dict):
                return self._result_is_empty(inner)
            rows = result.get("rows", result.get("results"))
            if isinstance(rows, (list, tuple)):
                return len(rows) == 0
            count = result.get("row_count", result.get("total", result.get("count")))
            if isinstance(count, int):
                return count == 0
        res_str = str(result)
        if "rows=0" in res_str or "(no rows returned)" in res_str or res_str.strip() in ("", "[]", "{}"):
            return True
        if isinstance(result, (list, tuple)):
            return len(result) == 0
        return False


class TimeWindowPin:
    """Pins every search a time-scoped domain makes to the mission's window.

    Not a guard in the cancelling sense: it rewrites. When the selected tool
    declares `earliest_time` and `latest_time` in its input schema, both are set
    to the scope's epoch bounds on every call, overwriting whatever the model
    passed. The prompt already asks for these values; asking was not enough --
    43 of 45 siem queries on 2026-09-14 ran over all time, so evidence from
    outside the alert window was reported as in scope.

    The window is part of `Scope`, which is the authorization boundary, so the
    model does not get a vote. A tool that takes no time parameters is left
    alone: there is nothing to pin, and inventing SPL `earliest=` terms here
    would be string surgery on a query this code does not parse.
    """

    def __init__(self, family: str, time_window: tuple[Any, Any]) -> None:
        self._family = family
        self._earliest = str(int(time_window[0].timestamp()))
        self._latest = str(int(time_window[1].timestamp()))
        self.blocked: list[str] = []
        """Always empty -- this never cancels. Present so callers can pool `blocked`
        across every guard a subagent runs under."""

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        from strands.hooks import BeforeToolCallEvent

        registry.add_callback(BeforeToolCallEvent, self._pin)

    def _pin(self, event: Any) -> None:
        tool = event.selected_tool
        tool_use = event.tool_use or {}
        if tool is None or not isinstance(tool_use.get("input"), dict):
            return
        properties = tool.tool_spec.get("inputSchema", {}).get("json", {}).get("properties", {})
        if not {"earliest_time", "latest_time"} <= set(properties):
            return
        args = tool_use["input"]
        asked = (args.get("earliest_time"), args.get("latest_time"))
        if asked != (self._earliest, self._latest) and any(asked):
            logger.info(
                "family=%s, tool=%s | model asked for window %s, pinned to %s..%s",
                self._family, tool_use.get("name", "unknown"), asked, self._earliest, self._latest,
            )
        args["earliest_time"] = self._earliest
        args["latest_time"] = self._latest
