"""Resolves a mission's `ToolFamily` into the concrete Strands tool objects a
subagent's `Agent(tools=[...])` should be built with.

This is the whole answer to "can this subagent use this tool": a mission
carries exactly one `ToolFamily` (set upstream by the Analyst, see
`contracts.SubagentMission.tool_family`), and `tools_for()` resolves that to
the family's full toolset -- native + every attached MCP server. Deciding
*which* tool within that set to actually call for a given mission is left to
the subagent's own model loop, driven by `mission.goal`; we don't pre-select
individual tool calls here.

MCP servers are declared in an `mcpServers` JSON config and built by
`MCPClient.load_servers()` rather than by hand. That deletes a surprising
amount of code -- credential handling (`${VAR}` interpolation), transport
selection, pagination, connection startup, and per-server failure isolation
are all things Strands already does. What stays ours is the one thing Strands
has no concept of: which servers belong to which `ToolFamily`.

Native tools in this registry are strictly model-callable `@tool` functions
that belong in an Agent's `tools=[]` list. `Budget.reserve()`/`settle()` are
NOT native tools by this definition -- they wrap the whole LLM/tool-call
round from orchestration code, before and after, and a model never calls
them directly.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable

from contracts import ToolFamily
from strands.tools.mcp import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILENAME = "mcp_servers.json"
CONFIG_PATH_ENV_VAR = "SMARTOPS_MCP_CONFIG"

# Which MCP servers (by their name in the config) serve which family. This is
# the domain mapping Strands has no notion of -- it sees a flat list of servers.
#
# A name listed here that is absent, disabled, or unresolvable in the config
# simply yields no client for that family, which callers read as "this domain
# isn't reachable right now". That is the honest state for every family whose
# vendor hasn't been picked.
MCP_SERVERS_BY_FAMILY: dict[ToolFamily, tuple[str, ...]] = {
    "siem": ("splunk",),
    "edr": ("edr",),
    "ndr": ("ndr",),
    "vt": (),  # VirusTotal is a REST API, reached by a native tool, not MCP.
}

# Model-callable `@tool` functions per family, for domains reached directly
# rather than through an MCP server.
NATIVE_TOOLS_BY_FAMILY: dict[ToolFamily, list[Callable]] = {
    "siem": [],
    "edr": [],
    "ndr": [],
    "vt": [],
}

# Built once per process by `load_mcp_servers()`. Empty until then, and empty
# stays a valid state -- no config and no credentials is how this runs today.
_clients_by_family: dict[ToolFamily, list[MCPClient]] = {}


def _default_config_path() -> Path | None:
    """Where to look for the `mcpServers` config, in precedence order.

    `SMARTOPS_MCP_CONFIG` wins so a deployment can point at a mounted secret
    or an environment-specific file; otherwise `mcp_servers.json` in the
    working directory. Returns None when neither exists, because running with
    no MCP servers configured is a supported state, not an error.
    """
    override = os.environ.get(CONFIG_PATH_ENV_VAR)
    if override:
        return Path(override)
    candidate = Path.cwd() / DEFAULT_CONFIG_FILENAME
    return candidate if candidate.is_file() else None


def load_mcp_servers(config: str | Path | dict[str, Any] | None = None) -> dict[ToolFamily, list[MCPClient]]:
    """Build this process's MCP clients from config, once, and map them to families.

    Call at startup, before any `tools_for()`. Idempotent in effect but not
    guarded: calling twice builds a second set of clients, which would open a
    second connection per server, so don't.

    Failure handling is deliberately layered, and every layer is Strands':

    - A server marked `"disabled": true` is skipped outright.
    - A server whose `${VAR}` credential is unset raises inside `load_servers()`
      and is skipped when it sets `"continue_on_error": true`. This is the
      no-credentials path: absent `SPLUNK_TOKEN` means no splunk client, not a
      crash.
    - A server that fails to *connect* yields `[]` from `load_tools()` rather
      than raising, again via `continue_on_error`. That failure is sticky for
      the connection's lifecycle and is deliberately not retried -- recovery is
      teardown and restart.

    A malformed config (bad JSON, a non-mapping server entry) still raises, and
    should: that is a deployment error, not a runtime condition.
    """
    global _clients_by_family

    source = config if config is not None else _default_config_path()
    if source is None:
        logger.info(
            "no MCP config found (set %s or place %s in the working directory); "
            "no MCP-backed family will resolve any tools",
            CONFIG_PATH_ENV_VAR,
            DEFAULT_CONFIG_FILENAME,
        )
        _clients_by_family = {}
        return _clients_by_family

    servers = _read_servers(source)
    _assert_no_shared_servers()

    # Build per family by slicing the config, rather than calling load_servers()
    # once and correlating its flat return by position. Slicing is exact: each
    # family gets clients for exactly the servers named for it, and a server
    # skipped for an unset credential simply doesn't appear.
    _clients_by_family = {}
    for family, names in MCP_SERVERS_BY_FAMILY.items():
        subset = {name: servers[name] for name in names if name in servers}
        _clients_by_family[family] = (
            MCPClient.load_servers({"mcpServers": subset}) if subset else []
        )
        logger.info(
            "family=%s | %d of %d configured MCP server(s) available",
            family,
            len(_clients_by_family[family]),
            len(subset),
        )
    return _clients_by_family


def _read_servers(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """The `mcpServers` mapping, accepting either shape Strands accepts."""
    import json

    if isinstance(source, dict):
        raw = source
    else:
        raw = json.loads(Path(str(source).removeprefix("file://")).read_text(encoding="utf-8"))
    servers = raw.get("mcpServers", raw)
    if not isinstance(servers, dict):
        raise ValueError("MCP config must map server names to configurations")
    return servers


def _assert_no_shared_servers() -> None:
    """One server must not serve two families.

    Because clients are built per family, a name listed twice would open two
    connections to the same server -- doubling sessions and load for no gain.
    Cheap to check at startup; confusing to diagnose at runtime.
    """
    seen: dict[str, ToolFamily] = {}
    for family, names in MCP_SERVERS_BY_FAMILY.items():
        for name in names:
            if name in seen:
                raise ValueError(
                    f"MCP server {name!r} is mapped to both {seen[name]!r} and {family!r}; "
                    "one server per family, or it opens a connection per family"
                )
            seen[name] = family


def server_count(family: ToolFamily) -> int:
    """How many MCP servers were successfully *built* for `family`.

    Distinct from how many tools resolve: a built client whose host is
    unreachable contributes a server here and zero tools from `tools_for()`.
    Callers use the difference to tell "nothing configured" from "configured but
    not answering" -- two states that need different fixes and would otherwise
    produce the same message.
    """
    return len(_clients_by_family.get(family, []))


def mcp_clients() -> list[MCPClient]:
    """Every MCP client this process built, deduplicated.

    For process-lifetime lifecycle work in an entry point. `MCPClient` is a
    Strands `ToolProvider` with ref-counted consumers, so once a real subagent
    passes one to `Agent(tools=[...])`, that agent's `cleanup()` releases its
    consumer -- and if the count hits zero the connection tears down. When that
    lands (Aug-27), hold a process-level consumer across the run so the session
    spans every mission instead of reconnecting per mission.
    """
    seen: dict[int, MCPClient] = {}
    for clients in _clients_by_family.values():
        for client in clients:
            seen.setdefault(id(client), client)
    return list(seen.values())


async def tools_for(family: ToolFamily) -> list:
    """The full toolset a subagent handling `family` should be given.

    Async because `MCPClient.load_tools()` is: it starts the connection itself,
    auto-paginates, and caches internally, so repeated calls for the same family
    reuse one connection rather than opening one per mission.

    Returns `[]` for a family with no native tools and no reachable server --
    the current state of every family until credentials exist. Callers treat
    that as "this domain isn't available", not as an error.
    """
    tools: list = list(NATIVE_TOOLS_BY_FAMILY.get(family, []))
    for client in _clients_by_family.get(family, []):
        # `continue_on_error` makes a connection failure yield [] here rather
        # than raise, so one dead vendor cannot abort resolution for the others.
        tools.extend(await client.load_tools())
    return tools
