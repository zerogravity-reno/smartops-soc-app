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

import asyncio
import logging
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable

from contracts import ToolFamily
from strands.tools.mcp import MCPClient

from smartops.tools.native import virustotal

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILENAME = "mcp_servers.json"
CONFIG_PATH_ENV_VAR = "SMARTOPS_MCP_CONFIG"

# Comma-separated MCP server names whose TLS certificate must NOT be verified.
# Empty (the default) means every server is verified, so the committed repo is
# secure by default and the insecure setting lives only in an operator's
# environment -- a `.env`, which is gitignored, or a deployment's own config.
#
# This exists because `MCPServerConfig` has no TLS fields at all: there is no
# `verify`, `ca_cert`, or `httpx_client_factory` key, so trust cannot be
# expressed in `mcp_servers.json`. Naming servers here rather than flipping a
# global switch keeps the exemption scoped to the one host that needs it.
TLS_NO_VERIFY_ENV_VAR = "SMARTOPS_MCP_TLS_NO_VERIFY"

# Config keys `_build_unverified_client()` understands. Anything else on a
# no-verify server is rejected rather than ignored -- see that function.
_SUPPORTED_NO_VERIFY_KEYS = frozenset(
    {
        "url",
        "headers",
        "transport",
        "prefix",
        "continue_on_error",
        "startup_timeout",
        "application_name",
        "application_version",
        "disabled",
    }
)

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
    "vt": list(virustotal.TOOLS),
}

# Families whose work is a *lookup* rather than an investigation, and can
# therefore run with no model at all: the entity's kind selects the query and
# its value is the argument, so there is no judgement to delegate.
#
# This is what lets a family return real evidence before the Aug-27 subagents
# exist. Anything requiring a decision about *what* to ask -- which SPL to run,
# which host to pivot to -- has no entry here and waits for a real subagent.
ENRICHERS_BY_FAMILY: dict[ToolFamily, Callable[..., Any] | None] = {
    "siem": None,
    "edr": None,
    "ndr": None,
    "vt": virustotal.enrich_scope,
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
    no_verify = _tls_no_verify_servers()
    unknown_no_verify = sorted(no_verify - servers.keys())
    if unknown_no_verify:
        # A typo here fails *safe* (the server keeps verifying and stays broken),
        # which is exactly why it needs saying out loud -- the symptom is
        # indistinguishable from the variable not being set at all.
        logger.warning(
            "%s names server(s) not present in the config: %s",
            TLS_NO_VERIFY_ENV_VAR,
            ", ".join(unknown_no_verify),
        )

    _clients_by_family = {}
    for family, names in MCP_SERVERS_BY_FAMILY.items():
        subset = {name: servers[name] for name in names if name in servers}
        verified = {name: cfg for name, cfg in subset.items() if name not in no_verify}
        clients = MCPClient.load_servers({"mcpServers": verified}) if verified else []
        for name, cfg in subset.items():
            if name not in no_verify:
                continue
            try:
                client = _build_unverified_client(name, cfg)
            except Exception:
                # Mirror load_servers(): a per-server build failure is fatal
                # unless that server opted into being skipped.
                if not cfg.get("continue_on_error", False):
                    raise
                logger.warning(
                    "server_name=<%s> | failed to build unverified client, skipping",
                    name,
                    exc_info=True,
                )
                continue
            if client is not None:
                clients.append(client)
        _clients_by_family[family] = clients
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


def _tls_no_verify_servers() -> frozenset[str]:
    """Server names exempted from TLS verification, from the environment."""
    raw = os.environ.get(TLS_NO_VERIFY_ENV_VAR, "")
    return frozenset(name.strip() for name in raw.split(",") if name.strip())


def _build_unverified_client(name: str, server: dict[str, Any]) -> MCPClient | None:
    """Build one streamable-http `MCPClient` that does not verify its server's
    TLS certificate. Returns None when the server is disabled.

    ⚠️ **This removes the only protection against an impostor server.** The
    Authorization header -- a bearer token -- is sent to whatever answers on that
    address, and every tool result it returns is trusted as SOC evidence. It is
    opt-in per server via `SMARTOPS_MCP_TLS_NO_VERIFY` for exactly that reason,
    and it logs a warning on every build so an unverified connection is never
    silent in the logs.

    Why this cannot be a config key: `MCPServerConfig` has no TLS fields, and
    `_config_transport_callable()` calls `streamablehttp_client(url=..., headers=
    ...)` without forwarding an `httpx_client_factory`. The factory *is* an
    accepted parameter of `streamablehttp_client`, and `MCPClient` takes a
    transport callable directly, so supplying our own is the supported seam --
    no patching of Strands required.

    Unsupported keys raise rather than being dropped. `tool_filters` is the case
    that matters: silently ignoring it would widen a subagent's toolset beyond
    what the config says, which is a security regression disguised as a
    no-op. Strands' own parser for it is private, so rather than reimplement it
    we refuse the combination.
    """
    unsupported = sorted(server.keys() - _SUPPORTED_NO_VERIFY_KEYS)
    if unsupported:
        raise ValueError(
            f"MCP server {name!r} is listed in {TLS_NO_VERIFY_ENV_VAR} but declares "
            f"{', '.join(unsupported)}, which the unverified-TLS builder does not "
            "support. Remove the key, or remove the server from that variable so it "
            "is built by MCPClient.load_servers() with full config support."
        )

    if server.get("disabled", False):
        logger.debug("server_name=<%s> | skipping disabled MCP server", name)
        return None

    # Strands' own interpolation, so `${VAR}` behaves identically on this path:
    # same syntax, same "unset variable raises" rule that `continue_on_error`
    # then turns into a skip. Reimplementing it would be a second dialect of the
    # same feature, and would drift.
    from strands.tools.mcp.mcp_client import _interpolate_env_vars

    server = _interpolate_env_vars(server)

    transport = server.get("transport", "streamable-http")
    if transport != "streamable-http":
        raise ValueError(
            f"MCP server {name!r}: {TLS_NO_VERIFY_ENV_VAR} only applies to "
            f"streamable-http servers, got {transport!r}"
        )
    url = server.get("url")
    if not url:
        raise ValueError(f"MCP server {name!r}: streamable-http transport requires 'url'")

    logger.warning(
        "server_name=<%s>, url=<%s> | TLS VERIFICATION DISABLED for this MCP server "
        "(listed in %s); its identity is unverified and its bearer token is exposed "
        "to any host answering on that address",
        name,
        url,
        TLS_NO_VERIFY_ENV_VAR,
    )

    return MCPClient(
        lambda: _unverified_streamable_http(url, server.get("headers")),
        startup_timeout=server.get("startup_timeout", 30),
        prefix=server.get("prefix"),
        application_name=server.get("application_name", name),
        application_version=server.get("application_version"),
        continue_on_error=server.get("continue_on_error", False),
    )


def _insecure_httpx_client(
    headers: dict[str, str] | None = None,
    timeout: Any = None,
    auth: Any = None,
) -> Any:
    """An httpx client that does not verify TLS certificates.

    Mirrors `mcp.shared._httpx_utils.create_mcp_http_client` -- the MCP SDK's own
    default factory -- because `streamablehttp_client` depends on its
    `follow_redirects=True` and timeout defaults; the only difference is
    `verify=False`. A thin copy rather than a call into that helper, which
    exposes no way to pass `verify` through.
    """
    import httpx

    kwargs: dict[str, Any] = {
        "follow_redirects": True,
        "verify": False,
        "timeout": timeout if timeout is not None else httpx.Timeout(30.0, read=300.0),
    }
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


def _unverified_streamable_http(url: str, headers: dict[str, str] | None):
    """`streamablehttp_client` wired to the non-verifying httpx factory."""
    from mcp.client.streamable_http import streamablehttp_client

    return streamablehttp_client(
        url=url, headers=headers, httpx_client_factory=_insecure_httpx_client
    )


def enricher_for(family: ToolFamily) -> Callable[..., Any] | None:
    """The model-free lookup for `family`, if it has one.

    Returns None for every family whose work needs a decision about what to ask
    -- those wait for a real subagent.
    """
    return ENRICHERS_BY_FAMILY.get(family)


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
        tools.extend(await _load_tools_off_loop(client))
    return tools


async def _load_tools_off_loop(client: MCPClient) -> Sequence[Any]:
    """`client.load_tools()`, run off the event loop.

    `load_tools()` is declared `async` but its body is synchronous and blocking:
    it calls `start()` -- which waits on a background thread's init future for up
    to `startup_timeout` (30s by default) -- and then `list_tools_sync()` per
    page, with no `await` between them. Awaiting it directly therefore stalls the
    whole loop.

    That matters because `tools_for()` was made async precisely so concurrent
    dispatch would not serialise. With an unreachable MCP host, an inline await
    would block one family's resolution *and* every other family's, plus the
    VirusTotal HTTP calls and any `asyncio.wait_for` meant to bound the mission --
    the async signature making the code look non-blocking while doing the
    opposite. This is the same failure the planner's `asyncio.to_thread` wrapper
    guarded against, which was removed with `plan_missions()` and never
    re-established for this path.

    The coroutine is created here and driven by `asyncio.run` in a worker thread.
    Safe because nothing in `load_tools()` actually suspends, so it has no
    affinity to the loop it was created on.
    """
    return await asyncio.to_thread(asyncio.run, client.load_tools())
