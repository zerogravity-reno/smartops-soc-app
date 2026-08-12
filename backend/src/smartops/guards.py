"""Boundaries enforced in code rather than in a prompt.

A prompt instruction is a request. Anything the system must be able to state as a
fact -- what a subagent is allowed to query, what it is allowed to touch -- has to
be enforced somewhere the model cannot argue with. Strands' `BeforeToolCallEvent`
is that place: a hook can cancel a tool call before it runs, and the cancellation
message comes back to the model as the tool result, so the model can correct
itself rather than simply failing.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# `index=foo`, `index = "foo"`, `index=*`. The value stops at whitespace or the
# characters that end a term in SPL.
_INDEX_TERM = re.compile(r"\bindex\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s()|,]+)", re.IGNORECASE)

# Whether a string is a search at all. A tool that lists indexes or describes a
# sourcetype takes no SPL and must not be required to pin an index.
_LOOKS_LIKE_SEARCH = re.compile(
    r"\bindex\s*=|\bsourcetype\s*=|\bearliest\s*=|\blatest\s*=|\|\s*\w|^\s*search\b",
    re.IGNORECASE,
)


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

    Registered per subagent from `DomainSpec.index_allowlist`. The rule is the one
    the design spec settled on: reject `index=*`, and require a literal
    allowlisted `index=` on anything that is a search.

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
            event.cancel_tool = reason
            return

    def _reject_reason(self, value: str) -> str | None:
        if not _LOOKS_LIKE_SEARCH.search(value):
            return None

        allowed = ", ".join(f"index={name}" for name in self._allowlist)
        targeted = [_unquote(m.group(1)) for m in _INDEX_TERM.finditer(value)]

        if not targeted:
            return (
                f"Rejected: this search does not pin an index. Every {self._family} "
                f"search must state one of: {allowed}. Reissue the query with an "
                f"explicit index."
            )

        disallowed = [name for name in targeted if name.lower() not in self._allowed]
        if disallowed:
            shown = ", ".join(f"index={name}" for name in dict.fromkeys(disallowed))
            return (
                f"Rejected: {shown} is outside this deployment's allowed indexes. "
                f"Use one of: {allowed}. A wildcard index is never allowed -- name "
                f"the index explicitly and reissue the query."
            )

        return None


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
