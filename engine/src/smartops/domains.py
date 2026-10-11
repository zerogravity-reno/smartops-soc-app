"""The registry of security domains, and everything that makes one distinct.

One `DomainSpec` per `ToolFamily`, holding what used to be scattered across ten
sites in five files: the entity gate, whether the domain is time-scoped, which
MCP servers serve it, its native tools, its model-free enricher, and the
description the Broker's model reads when deciding whether to engage it.

Adding a domain is now three declarative edits: a `DomainSpec` here, a member on
`contracts.ToolFamily`, and an entry in `mcp_servers.json`.

**Deliberately pure data.** This module imports `contracts` and the VirusTotal
native tools and nothing else -- no Strands, no `broker`, no `registry`. The tool
wrappers are generated in `smartops.broker`, because their body calls
`broker._dispatch()` and generating them here would make `domains` and `broker`
import each other.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from contracts import (
    Assessment,
    EdrAssessment,
    EntityKind,
    Findings,
    NdrAssessment,
    SiemAssessment,
    SiemFindings,
    ToolFamily,
    VtAssessment,
    VtFindings,
)
from smartops.tools.native import virustotal


@dataclass(frozen=True)
class DomainSpec:
    """Everything that distinguishes one security domain from another.

    Frozen because a spec is configuration read at import time by four separate
    modules. A mutable one would let any consumer silently change the entity
    gate or the toolset for every other consumer.
    """

    family: ToolFamily

    description: str
    """What the Broker's model reads when deciding whether to engage this domain.

    Model-facing and load-bearing: calling a specialist's tool IS the decision
    that its domain is relevant, so this text is the entire basis for routing.
    Each states what the domain is for, what observable it needs, and -- crucially
    -- what it is NOT for.
    """

    required_kinds: frozenset[EntityKind] | None
    """Which observable kinds this domain can be queried with. `None` means any.

    A *precondition*, not a judgement: VirusTotal cannot be queried without a
    hash, IP, domain, or URL regardless of what any model decides. A SIEM indexes
    logs about everything, so no observable makes it unusable.
    """

    time_scoped: bool
    """Whether this domain's data is indexed over time.

    Reputation lookups are not: "is this indicator known-bad" has no time
    dimension, so handing a `vt` subagent a 2018 window is an instruction it
    cannot follow and would have to invent a way to obey.
    """

    mcp_servers: tuple[str, ...] = ()
    """Names of MCP servers in `mcp_servers.json` that serve this domain.

    One server must not serve two families -- clients are built per family, so a
    name listed twice opens two connections to the same server.
    """

    native_tools: tuple[Callable, ...] = ()
    """Model-callable `@tool` functions for domains reached directly rather than
    through an MCP server."""

    enricher: Callable[..., Any] | None = None
    """A model-free lookup, for domains whose work is a *lookup* rather than an
    investigation: the entity's kind selects the query and its value is the
    argument, so there is no judgement to delegate. `None` for any domain that
    needs a decision about what to ask."""

    index_allowlist: tuple[str, ...] | None = None
    """Indexes this domain's queries may target, enforced by `guards.IndexScopeGuard`.

    A *deployment* fact, which is why it lives here and not on `Scope`. Which
    index holds the data is a property of the estate; `Scope` is the
    authorization boundary, and mixing infrastructure into it muddies a
    security-relevant type. The Analyst should not have to know that BOTSv3
    lives in `index=botsv3`.

    `None` means the domain has no index concept and the guard does not apply --
    distinct from an empty tuple, which would forbid every query.
    """

    assessment_model: type[Assessment] = Assessment
    """The model-authored judgement `make_answer_model()` embeds in this family's
    concrete answer model, as the `assessment` field's type.

    Defaults to the bare `Assessment` base -- an empty model with no fields -- for
    a domain that has not earned a real one yet. `edr` and `ndr` are disabled (no
    MCP server reachable, no vendor picked), so there is no retrieval shape to
    describe judgement over; inventing fields for it now would be a shape neither
    domain's real subagent is likely to keep once one is chosen.
    """

    findings_model: type[Findings] | None = None
    """The code-assembled payload type `SubtaskResult.findings` holds for this
    family, or `None` where no projector exists yet.

    Unlike `assessment_model`, this has no safe non-`None` default: `Findings`
    itself carries no fields, and a caller checking `findings_model is not None`
    to decide whether to expect a payload would be lied to by an empty stand-in.
    `siem` and `vt` are the only families with a working `projection.py` path
    today; `edr` and `ndr` stay `None` for the same reason as `assessment_model`.
    """

    redirects: tuple[tuple[ToolFamily, str], ...] = ()
    """(family, what to send there) pairs, rendered by `describe()` only when that
    family is configured. Kept out of `description` because a static "use
    investigate_edr" tells the model EDR exists when nothing serves it."""

    covers_when_absent: tuple[tuple[ToolFamily, str], ...] = ()
    """Text `describe()` appends when the keyed family is NOT configured: what this
    domain holds that the absent one would otherwise have answered. Pairs, not a
    dict, so the frozen spec stays hashable."""

    turns: int = 14
    max_output_tokens: int = 12_000


SIEM = DomainSpec(
    family="siem",
    description=(
        "Search SIEM logs for historical evidence across the whole estate:\n"
        "authentication events, process and network log records, index metadata.\n"
        "\n"
        "Use for anything needing log history or correlation over time, and as the\n"
        "starting point when you do not yet know which host or address matters.\n"
        "Works with any observable."
    ),
    redirects=(("vt", "file or domain reputation"), ("edr", "live host process detail")),
    covers_when_absent=(
        ("edr", (
            "Endpoint telemetry is indexed here: process creation (Sysmon EID 1, "
            "Windows 4688), file and registry events. Use this for host and process "
            "questions."
        )),
        ("ndr", "Network telemetry is indexed here: firewall, DNS and proxy logs."),
    ),
    required_kinds=None,
    time_scoped=True,
    mcp_servers=("splunk",),
    index_allowlist=("botsv3",),
    assessment_model=SiemAssessment,
    findings_model=SiemFindings,
)

EDR = DomainSpec(
    family="edr",
    description=(
        "Query endpoint detection and response for host-level detail: running and\n"
        "historical processes, persistence mechanisms, file activity, local accounts.\n"
        "\n"
        "Use when the question is about what happened *on a machine*. Needs a host,\n"
        "process, or user observable in scope."
    ),
    redirects=(("ndr", "network flow analysis"), ("vt", "reputation lookups")),
    required_kinds=frozenset({"host", "process", "user"}),
    time_scoped=True,
    mcp_servers=("edr",),
    assessment_model=EdrAssessment,
)

VT = DomainSpec(
    family="vt",
    description=(
        "Look up third-party reputation and threat intelligence for an indicator:\n"
        "whether a file hash, IP, domain, or URL is known-malicious externally.\n"
        "\n"
        "Use to establish whether an indicator is known-bad. Needs a file_hash, ip,\n"
        "domain, or url observable in scope. Do NOT use to find out what happened in\n"
        "our own environment -- it knows nothing about our estate."
    ),
    required_kinds=frozenset({"file_hash", "ip", "domain", "url"}),
    time_scoped=False,
    mcp_servers=(),
    native_tools=tuple(virustotal.TOOLS),
    enricher=virustotal.enrich_scope,
    assessment_model=VtAssessment,
    findings_model=VtFindings,
)

NDR = DomainSpec(
    family="ndr",
    description=(
        "Analyse network detection and response telemetry: connections, flows,\n"
        "protocol anomalies, and traffic to or from an address.\n"
        "\n"
        "Use when the question is about traffic and communication patterns. Needs an\n"
        "ip, domain, or url observable in scope."
    ),
    redirects=(("edr", "host-local process detail"),),
    required_kinds=frozenset({"ip", "domain", "url"}),
    time_scoped=True,
    mcp_servers=("ndr",),
    assessment_model=NdrAssessment,
)

# Order matters: it is the order the Broker sees the tools in, and the default
# order of `--families`. Kept as siem, edr, vt, ndr to match what shipped.
DOMAINS: dict[ToolFamily, DomainSpec] = {s.family: s for s in (SIEM, EDR, VT, NDR)}

ALL_FAMILIES: tuple[ToolFamily, ...] = tuple(DOMAINS)


def spec_for(family: ToolFamily) -> DomainSpec:
    """The spec for `family`. Raises `KeyError` for an unregistered family --
    which is a programming error, not a runtime condition."""
    return DOMAINS[family]


def scope_gap(family: ToolFamily, scope) -> str | None:
    """Why `scope` gives `family` nothing to query, or None when it can run."""
    required = DOMAINS[family].required_kinds
    in_scope = scope.kinds()
    if family == "vt":
        # A private address has no reputation, so it is not a vt observable (P-8).
        in_scope = {e.kind for e in scope.entities if not (e.kind == "ip" and virustotal.is_private_ip(e.value))}
    if required is None or required & in_scope:
        return None
    return (
        f"no {family} observable in scope: needs one of "
        f"{sorted(required)}, scope has {sorted(in_scope)}"
        + (" (private IPs have no reputation)" if family == "vt" and "ip" in scope.kinds() else "")
    )


def describe(spec: DomainSpec, is_configured: Callable[[ToolFamily], bool]) -> str:
    """`spec.description` as the Broker's model should read it in this process.

    A redirect is named only when its target is configured, and
    `covers_when_absent` text only when its family is not -- so an unconnected
    family never appears in anything a model reads. The predicate is passed in
    (`registry.family_is_configured`) to keep this module free of `registry`.
    """
    parts = [spec.description]
    parts += [
        f"Do NOT use for {what} (use investigate_{target})."
        for target, what in spec.redirects
        if is_configured(target)
    ]
    parts += [text for family, text in spec.covers_when_absent if not is_configured(family)]
    return " ".join(parts)
