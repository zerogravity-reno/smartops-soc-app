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
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from strands.tools.mcp import MCPClient

from contracts import ToolFamily
from smartops.domains import DOMAINS

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


# Built once per process by `load_mcp_servers()`. Empty until then, and empty
# stays a valid state -- no config and no credentials is how this runs today.
_clients_by_family: dict[ToolFamily, list[MCPClient]] = {}

# One lock per client, keyed by identity, serialising the first resolution of
# each. See `_load_tools_off_loop` for why.
_resolve_locks: dict[int, asyncio.Lock] = {}

PROCESS_CONSUMER = "smartops-process"
"""Consumer id held for the life of the process by every client we build.

`MCPClient` is a Strands `ToolProvider` whose connection is torn down when its
consumer count reaches zero (`strands/tools/mcp/mcp_client.py:476-484`). Today
nothing registers one: `add_consumer` has exactly one call site in the SDK
(`strands/tools/registry.py:133`, inside `ToolRegistry.process_tools`'s
`isinstance(tool, ToolProvider)` branch), and `tools_for()` hands `Agent` the
already-resolved `MCPAgentTool`s instead of the provider, so those match the
earlier `AgentTool` branch and the client never becomes a tracked provider.

Claiming one here is therefore *not* what fixes the observed failure -- nothing
was releasing a consumer, because none was ever taken. It closes the path
before someone passes a client straight into `Agent(tools=[...])`, at which
point that agent's `cleanup()` would otherwise tear the shared connection down
under every other family.
"""


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
    for family, spec in DOMAINS.items():
        subset = {name: servers[name] for name in spec.mcp_servers if name in servers}
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

    _resolve_locks.clear()
    for client in mcp_clients():
        # Not every stand-in implements the ToolProvider half of the interface,
        # and a client we cannot claim is still a client we can resolve tools
        # from -- so this is best-effort by design.
        claim = getattr(client, "add_consumer", None)
        if callable(claim):
            claim(PROCESS_CONSUMER)

    return _clients_by_family


async def warm_mcp_clients() -> None:
    """Resolve every built client's tools once, before any dispatch can.

    This is the fix for a live failure: in the run recorded at
    `.smartops/runs/botsv3_coinhive/20260815T124556942`, one of two concurrent
    `siem` dispatches came back with zero tools -- rejected with "1 MCP
    server(s) configured but returning no tools" and zero queries run -- while
    the other ran 11 queries against the same client.

    The cause is that `MCPClient.load_tools()` checks `_tool_provider_started`
    and only then calls `start()` (`mcp_client.py:405-409`), with a network
    handshake in between and no lock across the two. `_is_session_active()` goes
    true as soon as the background thread starts, well before the handshake
    finishes, so a second caller arriving in that window calls `start()` on a
    starting client and gets `MCPClientInitializationError("the client session
    is currently running")` (`mcp_client.py:334-336`). Our servers set
    `continue_on_error`, which converts that into `_connection_failed = True`
    and an empty list (`mcp_client.py:411-417`) -- and that flag is sticky, only
    cleared by `stop()` (`mcp_client.py:557`), which nothing here calls.

    Two same-family dispatches in one Broker turn is not a corner case: Strands
    runs a turn's tool calls under `ConcurrentToolExecutor` by default, so any
    plan with two `siem` steps arrives here at once.

    Call once at startup, after `load_mcp_servers()`. A server that cannot be
    reached is *not* an error: it yields no tools here exactly as it would at
    dispatch, and its family goes on to report honestly that nothing resolved.
    """
    clients = mcp_clients()
    if not clients:
        return

    async def warm(client: MCPClient) -> None:
        try:
            tools = await _load_tools_off_loop(client)
        except Exception:
            # Same trade `tools_for()` makes: one dead vendor must not stop the
            # others from being resolved.
            logger.warning("failed to warm an MCP client, it will resolve no tools", exc_info=True)
            return
        logger.info("warmed an MCP client: %d tool(s)", len(tools))

    await asyncio.gather(*(warm(client) for client in clients))


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
    for family, spec in DOMAINS.items():
        for name in spec.mcp_servers:
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
    return DOMAINS[family].enricher


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

    For process-lifetime lifecycle work in an entry point: `load_mcp_servers()`
    claims `PROCESS_CONSUMER` on each of these, and `warm_mcp_clients()`
    resolves each one's tools before any dispatch can.

    This docstring used to say that a subagent's `Agent.cleanup()` releases a
    consumer and tears the connection down under the next mission, and that
    holding a process-level consumer was the fix. **That was wrong**, and it is
    recorded here because it is a plausible story that costs an afternoon: the
    SDK calls `add_consumer` from exactly one place
    (`strands/tools/registry.py:133`, the `isinstance(tool, ToolProvider)`
    branch of `ToolRegistry.process_tools`), and `tools_for()` passes `Agent`
    the resolved `MCPAgentTool`s rather than the provider, so no consumer is
    ever taken and none is ever released. The real failure was a start-up race
    between concurrent dispatches -- see `warm_mcp_clients`.
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
    tools: list = list(DOMAINS[family].native_tools)
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

    **Serialised per client**, because sending it to a thread is exactly what
    lets two callers into `load_tools()` at once, and its start-up check is not
    atomic (see `warm_mcp_clients` for the mechanism and the run it broke).
    `warm_mcp_clients()` is what keeps this off the hot path -- once a client
    has resolved, every later call returns its cached list and the lock is
    uncontended. The lock is what makes the property hold anyway for a caller
    that never warmed, which is how this failed the first time.
    """
    lock = _resolve_locks.setdefault(id(client), asyncio.Lock())
    async with lock:
        return await asyncio.to_thread(asyncio.run, client.load_tools())
