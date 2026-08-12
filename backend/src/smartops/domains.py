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

from dataclasses import dataclass
from typing import Any, Callable

from contracts import (
    Assessment,
    EntityKind,
    Findings,
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
        "Works with any observable. Do NOT use for file or domain reputation (use\n"
        "investigate_vt) or for live host process detail (use investigate_edr)."
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
        "process, or user observable in scope. Do NOT use for network flow analysis\n"
        "(use investigate_ndr) or reputation lookups (use investigate_vt)."
    ),
    required_kinds=frozenset({"host", "process", "user"}),
    time_scoped=True,
    mcp_servers=("edr",),
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
        "ip, domain, or url observable in scope. Do NOT use for host-local process\n"
        "detail (use investigate_edr)."
    ),
    required_kinds=frozenset({"ip", "domain", "url"}),
    time_scoped=True,
    mcp_servers=("ndr",),
)

# Order matters: it is the order the Broker sees the tools in, and the default
# order of `--families`. Kept as siem, edr, vt, ndr to match what shipped.
DOMAINS: dict[ToolFamily, DomainSpec] = {s.family: s for s in (SIEM, EDR, VT, NDR)}

ALL_FAMILIES: tuple[ToolFamily, ...] = tuple(DOMAINS)


def spec_for(family: ToolFamily) -> DomainSpec:
    """The spec for `family`. Raises `KeyError` for an unregistered family --
    which is a programming error, not a runtime condition."""
    return DOMAINS[family]
