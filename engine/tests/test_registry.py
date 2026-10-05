import asyncio
import dataclasses
import json
import threading
from typing import Any

import pytest
import smartops.tools.registry as registry_module
from smartops.domains import DOMAINS
from smartops.tools.registry import (
    load_mcp_servers,
    mcp_clients,
    tools_for,
    warm_mcp_clients,
)


class FakeMCPClient:
    """Stands in for `strands.tools.mcp.MCPClient`.

    Models the two behaviours `tools_for()` depends on: `load_tools()` is
    async and self-starting (no separate `.start()`), and it caches, so a
    second call for the same family must not open a second connection.
    """

    def __init__(self, tools, *, fails=False):
        self._tools = tools
        self._fails = fails
        self.load_calls = 0
        self.connections = 0

    async def load_tools(self):
        self.load_calls += 1
        if self._fails:
            # What `continue_on_error` produces: no tools, no exception.
            return []
        if self.connections == 0:
            self.connections = 1  # self-started on first use, then cached
        return self._tools

    def stop(self, exc_type=None, exc_val=None, exc_tb=None):
        self.consumers = set()

    def add_consumer(self, consumer_id, **kwargs):
        getattr(self, "consumers", set()).add(consumer_id)


class StickyFailureClient:
    """Models `MCPClient`'s swallowed-init-failure semantics exactly.

    Three behaviours, all of them load-bearing for the retry in
    `warm_mcp_clients()` and all taken from the installed SDK:

    1. `continue_on_error` turns a failed handshake into `[]` with **no
       exception** (`mcp_client.py:411-417`).
    2. That failure is **sticky and checked before any retry**
       (`mcp_client.py:401-403`: "a previously swallowed init failure is not
       retried on subsequent calls"), so every later call also returns `[]`.
    3. Only `stop()` clears it (`mcp_client.py:557`) -- and `stop()` also resets
       the consumer set, which is why the reset must re-claim `PROCESS_CONSUMER`.

    A retry implemented without the `stop()` cannot pass a test using this fake,
    which is the whole point of modelling it rather than using `fails=True`.

    Caching is modelled too (`_loaded_tools` in the real client), which is why
    `handshakes` rather than `load_calls` is the meaningful counter: a later
    `tools_for()` calls `load_tools()` again but must not reconnect.
    """

    def __init__(self, tools, *, failures: int):
        self._tools = tools
        self._remaining_failures = failures
        self._failed = False
        self._loaded = None
        self.load_calls = 0
        self.handshakes = 0
        self.stops = 0
        self.consumers: set = set()

    async def load_tools(self):
        self.load_calls += 1
        if self._failed:
            return []
        if self._loaded is not None:
            return self._loaded
        self.handshakes += 1
        if self._remaining_failures > 0:
            self._remaining_failures -= 1
            self._failed = True
            return []
        self._loaded = self._tools
        return self._loaded

    def stop(self, exc_type=None, exc_val=None, exc_tb=None):
        self.stops += 1
        self._failed = False
        self.consumers = set()

    def add_consumer(self, consumer_id, **kwargs):
        self.consumers.add(consumer_id)


@pytest.fixture(autouse=True)
def _clean_registry_state(monkeypatch):
    """Each test starts with no clients loaded and restores the real maps."""
    monkeypatch.setattr(registry_module, "_clients_by_family", {})
    registry_module._resolve_locks.clear()
    # An operator with this exported in their shell must not change how the
    # suite behaves: it would silently route every server in these tests down
    # the unverified-TLS builder instead of MCPClient.load_servers().
    monkeypatch.delenv(registry_module.TLS_NO_VERIFY_ENV_VAR, raising=False)
    # The warm retry's backoff is real seconds in production and pure waiting
    # here. Zeroed for the whole module so no test pays for it, and so that
    # raising WARM_ATTEMPTS never silently slows the suite.
    monkeypatch.setattr(registry_module, "WARM_RETRY_BACKOFF_SECONDS", 0)
    yield
    registry_module._resolve_locks.clear()


def _install_clients(monkeypatch, **by_family):
    monkeypatch.setattr(registry_module, "_clients_by_family", dict(by_family))


class TestToolsFor:
    async def test_family_with_no_clients_and_no_native_tools_resolves_empty(self):
        # The honest current state of every family: not an error, just nothing
        # reachable. Callers report REJECTED from this.
        assert await tools_for("siem") == []

    async def test_native_tools_resolve_without_any_mcp_server(self, monkeypatch):
        monkeypatch.setitem(DOMAINS, "vt", dataclasses.replace(DOMAINS["vt"], native_tools=["vt_lookup_ip"]))

        assert await tools_for("vt") == ["vt_lookup_ip"]

    async def test_mcp_tools_are_appended_to_native_tools(self, monkeypatch):
        monkeypatch.setitem(DOMAINS, "siem", dataclasses.replace(DOMAINS["siem"], native_tools=["native"]))
        _install_clients(monkeypatch, siem=[FakeMCPClient(tools=["splunk_search"])])

        assert await tools_for("siem") == ["native", "splunk_search"]

    async def test_repeated_resolution_reuses_one_connection(self, monkeypatch):
        # load_tools() caches internally, so two missions against the same
        # family must not open two sessions.
        client = FakeMCPClient(tools=["splunk_search"])
        _install_clients(monkeypatch, siem=[client])

        await tools_for("siem")
        await tools_for("siem")

        assert client.connections == 1

    async def test_a_failing_server_yields_no_tools_rather_than_raising(self, monkeypatch):
        # continue_on_error semantics: the family degrades to empty, it does
        # not take the run down.
        _install_clients(monkeypatch, siem=[FakeMCPClient(tools=["x"], fails=True)])

        assert await tools_for("siem") == []

    async def test_one_failing_server_does_not_starve_a_sibling_family(self, monkeypatch):
        _install_clients(
            monkeypatch,
            siem=[FakeMCPClient(tools=["splunk_search"])],
            edr=[FakeMCPClient(tools=["x"], fails=True)],
        )

        assert await tools_for("siem") == ["splunk_search"]
        assert await tools_for("edr") == []


class RacyMCPClient:
    """`FakeMCPClient`, but modelling `load_tools()`'s non-atomic start.

    The real client checks `_tool_provider_started` and only *then* calls
    `start()` (`mcp_client.py:405-409`), with a network handshake in between. A
    second caller arriving in that window calls `start()` on an already-starting
    client and gets `MCPClientInitializationError("the client session is
    currently running")` (`mcp_client.py:334-336`); `continue_on_error` swallows
    it into a sticky `_connection_failed` and an empty tool list
    (`mcp_client.py:411-417`).

    That is the shape of the failure observed in
    `.smartops/runs/botsv3_coinhive/20260815T124556942`, where one of two
    concurrent siem dispatches came back with zero tools while the other ran 11
    queries. `FakeMCPClient` cannot express it: its `load_tools()` has no window
    to arrive in.

    Deterministic rather than timing-dependent: the first caller in holds the
    handshake open until either a second caller has had its chance (and set
    `_release`) or `window` elapses, so a lone caller costs `window` once and a
    racing pair always interleaves.
    """

    def __init__(self, tools, *, window: float = 0.1):
        self._tools = tools
        self._window = window
        self._lock = threading.Lock()
        self._release = threading.Event()
        self._in_flight = False
        self._started = False
        self._failed = False
        self.connections = 0

    async def load_tools(self):
        with self._lock:
            if self._failed:
                return []
            if self._started:
                return self._tools
            if self._in_flight:
                # Lost the race to `start()`. continue_on_error turns the raise
                # into an empty list, and the failure is sticky.
                self._failed = True
                self._release.set()
                return []
            self._in_flight = True
            self.connections += 1

        self._release.wait(timeout=self._window)

        with self._lock:
            self._started = True
            self._in_flight = False
            return self._tools


class TestConcurrentResolutionDoesNotRaceTheConnection:
    """One Broker turn can emit two same-family dispatches, and Strands runs them
    concurrently under its default `ConcurrentToolExecutor`. Both must get tools.
    """

    async def test_two_concurrent_resolutions_both_receive_the_tools(self, monkeypatch):
        client = RacyMCPClient(tools=["splunk_search"])
        _install_clients(monkeypatch, siem=[client])
        await warm_mcp_clients()

        first, second = await asyncio.gather(tools_for("siem"), tools_for("siem"))

        assert first == ["splunk_search"]
        assert second == ["splunk_search"]

    async def test_warming_connects_once_and_dispatch_connects_never(self, monkeypatch):
        client = RacyMCPClient(tools=["splunk_search"])
        _install_clients(monkeypatch, siem=[client])

        await warm_mcp_clients()
        assert client.connections == 1

        await asyncio.gather(tools_for("siem"), tools_for("siem"))
        assert client.connections == 1

    async def test_a_server_that_fails_to_warm_still_resolves_empty(self, monkeypatch):
        # The honest-refusal path has to survive warming: a dead vendor yields
        # no tools, and the caller reports REJECTED rather than crashing.
        _install_clients(monkeypatch, siem=[FakeMCPClient(tools=["x"], fails=True)])

        await warm_mcp_clients()

        assert await tools_for("siem") == []

    async def test_warming_a_raising_server_does_not_abort_its_siblings(self, monkeypatch):
        class Exploding:
            connections = 0

            async def load_tools(self):
                raise RuntimeError("connection refused")

        healthy = FakeMCPClient(tools=["splunk_search"])
        _install_clients(monkeypatch, siem=[Exploding()], edr=[healthy])

        await warm_mcp_clients()

        assert healthy.load_calls == 1

    async def test_warming_with_no_clients_is_a_supported_state(self):
        await warm_mcp_clients()

    async def test_a_transient_handshake_failure_is_retried_and_recovered(self, monkeypatch):
        """The measured live failure, 2026-09-02.

        Splunk's MCP endpoint answered the initialize POST with `500 bad
        character (49) in reply size` -- a malformed chunked response, transient,
        with a fresh process resolving all 10 tools seconds later. Without the
        retry that cost the entire run its SIEM tier: all three siem steps
        rejected, no evidence from the one domain the case was about.
        """
        client = StickyFailureClient(tools=["splunk_run_query"], failures=1)
        _install_clients(monkeypatch, siem=[client])

        await warm_mcp_clients()

        assert await tools_for("siem") == ["splunk_run_query"]
        assert client.handshakes == 2, "the first attempt failed, the second must have run"

    async def test_the_retry_resets_the_client_because_the_failure_is_sticky(
        self, monkeypatch
    ):
        """Calling `load_tools()` again is a NO-OP -- the flag is checked first.

        This is the detail that separates a retry that works from one that only
        looks like it does, so it is asserted directly rather than inferred from
        the recovery above.
        """
        client = StickyFailureClient(tools=["splunk_run_query"], failures=1)
        _install_clients(monkeypatch, siem=[client])

        await warm_mcp_clients()

        assert client.stops == 1, "the client must be stopped before being retried"

    async def test_the_process_consumer_claim_survives_the_reset(self, monkeypatch):
        """`stop()` resets `_consumers`, so the reset has to re-claim.

        Dropping it would silently undo what `load_mcp_servers()` took the claim
        for -- see `registry.PROCESS_CONSUMER` -- and the loss would be invisible
        until some agent's `cleanup()` tore the shared connection down under
        every other family.
        """
        client = StickyFailureClient(tools=["splunk_run_query"], failures=1)
        _install_clients(monkeypatch, siem=[client])

        await warm_mcp_clients()

        assert registry_module.PROCESS_CONSUMER in client.consumers

    async def test_a_permanently_dead_server_is_still_tolerated(self, monkeypatch):
        """Bounded retries, and the honest-refusal path survives them: a server
        that is genuinely down yields no tools and the caller reports REJECTED
        rather than the run crashing."""
        client = StickyFailureClient(tools=["splunk_run_query"], failures=99)
        _install_clients(monkeypatch, siem=[client])

        await warm_mcp_clients()

        assert await tools_for("siem") == []
        assert client.handshakes == registry_module.WARM_ATTEMPTS, "retries must be bounded"

    async def test_resolving_nothing_after_every_attempt_is_logged_at_warning(
        self, monkeypatch, caplog
    ):
        """It used to log "warmed an MCP client: 0 tool(s)" at INFO -- a total
        outage recorded in the same words as a success, and invisible without
        --verbose. The operator has to be told that a domain will produce no
        evidence for the whole run."""
        import logging

        client = StickyFailureClient(tools=["x"], failures=99)
        _install_clients(monkeypatch, siem=[client])

        with caplog.at_level(logging.WARNING, logger=registry_module.logger.name):
            await warm_mcp_clients()

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, "a client resolving no tools must warn"
        assert any("NO tools" in r.getMessage() for r in warnings)

    async def test_a_healthy_client_is_not_stopped_or_retried(self, monkeypatch):
        """The common path must be untouched: one connection, no reset."""
        client = StickyFailureClient(tools=["splunk_run_query"], failures=0)
        _install_clients(monkeypatch, siem=[client])

        await warm_mcp_clients()

        assert client.handshakes == 1
        assert client.stops == 0

    async def test_resolution_is_safe_even_when_nobody_warmed(self, monkeypatch):
        # Warming keeps the lock uncontended; the lock is what makes the
        # property hold for a caller that skipped it. Forgetting to warm is how
        # this failed the first time, so it must not be the only defence.
        client = RacyMCPClient(tools=["splunk_search"])
        _install_clients(monkeypatch, siem=[client])

        first, second = await asyncio.gather(tools_for("siem"), tools_for("siem"))

        assert first == ["splunk_search"]
        assert second == ["splunk_search"]
        assert client.connections == 1


class TestEveryClientHoldsAProcessConsumer:
    """`MCPClient` is a `ToolProvider` whose connection is torn down when its
    consumer count reaches zero (`mcp_client.py:476-484`). Nothing registers one
    today, because `tools_for()` hands `Agent` resolved `MCPAgentTool`s rather
    than the provider. Holding one at process level is not what fixes the race,
    but it closes that path before someone passes a client in directly.
    """

    def test_a_built_client_is_claimed_for_the_process(self, monkeypatch):
        claimed: list[Any] = []

        class Claimable:
            def add_consumer(self, consumer_id, **kwargs):
                claimed.append(consumer_id)

        monkeypatch.setattr(registry_module, "MCPClient", _StubMCPClientFactory([Claimable()]))

        load_mcp_servers({"mcpServers": {"splunk": {"url": "https://example.invalid"}}})

        assert len(claimed) == 1

    def test_a_client_without_the_provider_api_is_not_fatal(self, monkeypatch):
        # Keeps the suite's own FakeMCPClient (and any older client) usable.
        monkeypatch.setattr(
            registry_module, "MCPClient", _StubMCPClientFactory([FakeMCPClient(tools=["x"])])
        )

        load_mcp_servers({"mcpServers": {"splunk": {"url": "https://example.invalid"}}})


class _StubMCPClientFactory:
    """Stands in for the `MCPClient` class, returning prepared clients."""

    def __init__(self, clients):
        self._clients = clients

    def load_servers(self, config):
        servers = (config or {}).get("mcpServers") or {}
        return list(self._clients)[: len(servers)]


class TestLoadMcpServers:
    def test_no_config_is_a_supported_state(self, monkeypatch):
        monkeypatch.delenv(registry_module.CONFIG_PATH_ENV_VAR, raising=False)
        monkeypatch.setattr(registry_module, "_default_config_path", lambda: None)

        assert load_mcp_servers() == {}
        assert mcp_clients() == []

    def test_disabled_servers_produce_no_clients(self):
        loaded = load_mcp_servers(
            {"mcpServers": {"splunk": {"disabled": True}, "edr": {"disabled": True}}}
        )

        assert loaded["siem"] == []
        assert loaded["edr"] == []

    def test_missing_credential_skips_only_that_server(self, monkeypatch):
        # The no-credentials path, end to end: an unset ${VAR} raises inside
        # load_servers(), continue_on_error swallows it, and the family is left
        # with no client instead of the process failing.
        monkeypatch.delenv("SPLUNK_MCP_URL", raising=False)
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)

        loaded = load_mcp_servers(
            {
                "mcpServers": {
                    "splunk": {
                        "url": "${SPLUNK_MCP_URL}",
                        "headers": {"Authorization": "Bearer ${SPLUNK_TOKEN}"},
                        "continue_on_error": True,
                    }
                }
            }
        )

        assert loaded["siem"] == []

    def test_missing_credential_without_continue_on_error_raises(self, monkeypatch):
        # Guards the config: dropping continue_on_error turns a missing secret
        # into a hard startup failure, which is why every entry sets it.
        monkeypatch.delenv("SPLUNK_MCP_URL", raising=False)

        with pytest.raises(Exception):
            load_mcp_servers({"mcpServers": {"splunk": {"url": "${SPLUNK_MCP_URL}"}}})

    def test_a_server_mapped_to_two_families_is_rejected(self, monkeypatch):
        # Would silently open one connection per family.
        monkeypatch.setitem(DOMAINS, "siem", dataclasses.replace(DOMAINS["siem"], mcp_servers=("shared",)))
        monkeypatch.setitem(DOMAINS, "edr", dataclasses.replace(DOMAINS["edr"], mcp_servers=("shared",)))
        monkeypatch.setitem(DOMAINS, "ndr", dataclasses.replace(DOMAINS["ndr"], mcp_servers=()))
        monkeypatch.setitem(DOMAINS, "vt", dataclasses.replace(DOMAINS["vt"], mcp_servers=()))

        with pytest.raises(ValueError, match="mapped to both"):
            load_mcp_servers({"mcpServers": {"shared": {"disabled": True}}})

    def test_malformed_config_raises_rather_than_degrading(self):
        # A deployment error, not a runtime condition -- unlike a missing
        # credential, there is no sensible way to continue.
        with pytest.raises(ValueError):
            load_mcp_servers({"mcpServers": ["not", "a", "mapping"]})


class TestTlsNoVerify:
    """`SMARTOPS_MCP_TLS_NO_VERIFY` routes named servers to a hand-built client
    whose httpx factory skips certificate verification.

    It exists because `MCPServerConfig` has no TLS fields, so trust cannot be
    expressed in `mcp_servers.json` at all. Every test here is really guarding
    one property: the exemption applies to *exactly* the servers named, and
    nothing else.
    """

    SPLUNK = {
        "url": "${SPLUNK_MCP_URL}",
        "headers": {"Authorization": "Bearer ${SPLUNK_TOKEN}"},
        "continue_on_error": True,
    }

    @pytest.fixture(autouse=True)
    def _credentials(self, monkeypatch):
        monkeypatch.setenv("SPLUNK_MCP_URL", "https://splunk.invalid:8089/services/mcp")
        monkeypatch.setenv("SPLUNK_TOKEN", "token-value")

    def _spy(self, monkeypatch):
        calls = []

        def fake(name, server):
            calls.append(name)
            return object()

        monkeypatch.setattr(registry_module, "_build_unverified_client", fake)
        return calls

    def test_unset_variable_leaves_every_server_verified(self, monkeypatch):
        # The committed default. Nothing reaches the unverified builder.
        calls = self._spy(monkeypatch)

        load_mcp_servers({"mcpServers": {"splunk": self.SPLUNK}})

        assert calls == []

    def test_named_server_is_built_unverified(self, monkeypatch):
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")
        calls = self._spy(monkeypatch)

        loaded = load_mcp_servers({"mcpServers": {"splunk": self.SPLUNK}})

        assert calls == ["splunk"]
        assert len(loaded["siem"]) == 1

    def test_exemption_does_not_leak_to_an_unnamed_sibling(self, monkeypatch):
        # The whole point of naming servers rather than a global flag.
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")
        monkeypatch.setenv("EDR_URL", "https://edr.invalid/mcp")
        calls = self._spy(monkeypatch)

        load_mcp_servers(
            {
                "mcpServers": {
                    "splunk": self.SPLUNK,
                    "edr": {"url": "${EDR_URL}", "continue_on_error": True},
                }
            }
        )

        assert calls == ["splunk"]

    def test_whitespace_and_empty_entries_are_tolerated(self, monkeypatch):
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, " splunk , ,")

        assert registry_module._tls_no_verify_servers() == frozenset({"splunk"})

    def test_a_name_absent_from_the_config_is_warned_about(self, monkeypatch, caplog):
        # Fails safe -- the server keeps verifying and stays broken -- so the
        # symptom is identical to the variable never being set. Hence the warning.
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "spulnk")

        with caplog.at_level("WARNING"):
            load_mcp_servers({"mcpServers": {"splunk": self.SPLUNK}})

        assert "spulnk" in caplog.text

    def test_tool_filters_are_refused_rather_than_dropped(self, monkeypatch):
        # Silently ignoring a filter would widen a subagent's toolset beyond
        # what the config declares: a security regression that looks like a no-op.
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")
        config = {"mcpServers": {"splunk": {**self.SPLUNK, "tool_filters": {"allowed": ["^x$"]}}}}

        with pytest.raises(ValueError, match="tool_filters"):
            registry_module._build_unverified_client("splunk", config["mcpServers"]["splunk"])

    def test_disabled_named_server_produces_no_client(self, monkeypatch):
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")

        loaded = load_mcp_servers({"mcpServers": {"splunk": {**self.SPLUNK, "disabled": True}}})

        assert loaded["siem"] == []

    def test_missing_credential_skips_when_continue_on_error(self, monkeypatch):
        # Same contract as the verified path: an unset ${VAR} is an expected
        # state, not a crash.
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)

        loaded = load_mcp_servers({"mcpServers": {"splunk": self.SPLUNK}})

        assert loaded["siem"] == []

    def test_missing_credential_raises_without_continue_on_error(self, monkeypatch):
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        config = {k: v for k, v in self.SPLUNK.items() if k != "continue_on_error"}

        with pytest.raises(ValueError, match="SPLUNK_TOKEN"):
            load_mcp_servers({"mcpServers": {"splunk": config}})

    def test_non_streamable_transport_is_rejected(self, monkeypatch):
        # The factory seam only exists for streamable-http; claiming to cover
        # sse or stdio would disable nothing while implying it had.
        monkeypatch.setenv(registry_module.TLS_NO_VERIFY_ENV_VAR, "splunk")

        with pytest.raises(ValueError, match="streamable-http"):
            registry_module._build_unverified_client(
                "splunk", {**self.SPLUNK, "transport": "sse"}
            )

    def test_factory_disables_verification_and_keeps_mcp_defaults(self, monkeypatch):
        # `follow_redirects` and the read timeout are load-bearing for
        # streamablehttp_client, so they must survive alongside verify=False.
        import httpx

        captured = {}

        def fake_client(**kwargs):
            captured.update(kwargs)
            return "client"

        monkeypatch.setattr(httpx, "AsyncClient", fake_client)

        result = registry_module._insecure_httpx_client(headers={"Authorization": "Bearer t"})

        assert result == "client"
        assert captured["verify"] is False
        assert captured["follow_redirects"] is True
        assert captured["headers"] == {"Authorization": "Bearer t"}
        assert captured["timeout"].read == 300.0


class TestShippedConfig:
    """The repo's own mcp_servers.json has to stay loadable and safe."""

    CONFIG = "mcp_servers.json"

    def test_every_server_sets_continue_on_error_or_is_disabled(self):
        from pathlib import Path

        servers = json.loads(Path(self.CONFIG).read_text(encoding="utf-8"))["mcpServers"]

        for name, cfg in servers.items():
            assert cfg.get("disabled") or cfg.get("continue_on_error"), (
                f"server {name!r} would abort startup on a missing credential"
            )

    def test_no_literal_secrets(self):
        from pathlib import Path

        raw = Path(self.CONFIG).read_text(encoding="utf-8")
        servers = json.loads(raw)["mcpServers"]

        for name, cfg in servers.items():
            for key in ("url", "headers"):
                value = json.dumps(cfg.get(key, ""))
                if "${" in value:
                    continue
                assert "token" not in value.lower() and "bearer" not in value.lower(), (
                    f"server {name!r} may contain a literal credential in {key!r}"
                )

    def test_every_mapped_server_name_exists_in_the_config(self):
        from pathlib import Path

        servers = json.loads(Path(self.CONFIG).read_text(encoding="utf-8"))["mcpServers"]

        for family, spec in DOMAINS.items():
            for name in spec.mcp_servers:
                assert name in servers, (
                    f"family {family!r} maps to MCP server {name!r}, which the config does not define"
                )
