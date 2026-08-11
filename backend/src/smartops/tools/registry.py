"""Resolves a mission's `ToolFamily` into the concrete Strands tool objects a
subagent's `Agent(tools=[...])` should be built with.

This is the whole answer to "can this subagent use this tool": a mission
carries exactly one `ToolFamily` (set upstream by the Planner/Analyst, see
`contracts.SubagentMission.tool_family`), and `tools_for()` resolves that to
the family's full toolset -- native + every attached MCP server. Deciding
*which* tool within that set to actually call for a given mission is left to
the subagent's own model loop, driven by `mission.goal`; we don't pre-select
individual tool calls here. If a family's full toolset ever turns out to be
too permissive for some mission, narrow it with an MCP-side policy (e.g.
Cedar) rather than adding a second selection layer in this module.

Native tools in this registry are strictly model-callable `@tool` functions
that belong in an Agent's `tools=[]` list. `Budget.reserve()`/`settle()` are
NOT native tools by this definition -- they wrap the whole LLM/tool-call
round from orchestration code, before and after, and a model never calls
them directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from contracts import ToolFamily
from strands.tools.mcp import MCPClient

from smartops.tools.mcp import splunk

logger = logging.getLogger(__name__)

# Clients started so far, one entry per family that's actually been resolved.
# `MCPClient` requires `.start()` before `list_tools_sync()` will work at all
# -- an unstarted client raises on first use. Caching the started client here
# also means a family's connection is opened once per process, not once per
# `tools_for()` call: reused across every subagent built for that family,
# rather than leaked on every mission. This is a process-lifetime cache, not
# a real pooling strategy -- nothing here closes a client, and cross-
# investigation reuse/eviction is still the open question flagged below.
_started_clients: dict[ToolFamily, list[MCPClient]] = {}


@dataclass(frozen=True)
class ToolFamilyConfig:
    """Everything one `ToolFamily` is allowed to touch.

    `mcp_client_factories` are callables, not live clients -- connecting is a
    real cost (a stdio process or an HTTP session), so nothing here opens a
    connection until something actually asks for this family's tools.
    `tools_for()` starts and caches one client per family for the life of the
    process (see `_started_clients`); nothing yet closes one, and eviction /
    per-investigation scoping is still open -- see the 2026-08-06 session doc.
    """

    family: ToolFamily
    mcp_client_factories: list[Callable[[], MCPClient]] = field(default_factory=list)
    native_tools: list[Callable] = field(default_factory=list)


FAMILY_REGISTRY: dict[ToolFamily, ToolFamilyConfig] = {
    "siem": ToolFamilyConfig(family="siem", mcp_client_factories=[splunk.client]),
    # edr/vt/ndr: no MCP server wired up yet -- fill in once each vendor is
    # picked, or point at a custom server under `mcp_servers/` if none
    # exists for it. Splunk (siem) is the only one built out for now.
    "edr": ToolFamilyConfig(family="edr"),
    "vt": ToolFamilyConfig(family="vt"),
    "ndr": ToolFamilyConfig(family="ndr"),
}


def _clients_for(family: ToolFamily, cfg: ToolFamilyConfig) -> list[MCPClient]:
    """The started `MCPClient`s for `family`, starting them on first use.

    A client that can't be built or started is logged and skipped, leaving the
    family with fewer (possibly zero) clients rather than propagating. Callers
    read "zero clients" as "this family isn't available right now" -- which is
    the honest current state for every family, since no MCP server is wired up
    yet. Isolation is per-client and per-family: one unconfigured vendor must
    never abort resolution for the others.

    The catch is deliberately broad. Today the only failure is Splunk's
    `NotImplementedError` stub, but real vendors fail with connection errors,
    timeouts, and auth errors, and a narrowly-typed catch would need revisiting
    the first time a URL is merely wrong rather than unimplemented.

    Not thread-safe against true parallel callers (no lock) -- fine under
    asyncio's single-threaded scheduling, since nothing here awaits mid-check,
    but revisit if `tools_for()` is ever called from more than one OS thread.
    """
    if family not in _started_clients:
        clients = []
        for factory in cfg.mcp_client_factories:
            try:
                client = factory()
                client.start()
            except Exception:
                logger.warning(
                    "family=%s | MCP client unavailable, skipping it for this family",
                    family,
                    exc_info=True,
                )
                continue
            clients.append(client)
        _started_clients[family] = clients
    return _started_clients[family]


def tools_for(family: ToolFamily) -> list:
    """The full toolset a subagent handling `family` should be given.

    Called once per subagent construction, e.g.:

        agent = Agent(tools=tools_for(mission.tool_family), system_prompt=...)
    """
    cfg = FAMILY_REGISTRY[family]
    tools: list = list(cfg.native_tools)
    for client in _clients_for(family, cfg):
        tools.extend(client.list_tools_sync())
    return tools
