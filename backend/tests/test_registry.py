import dataclasses
import json

import pytest
import smartops.tools.registry as registry_module
from smartops.domains import DOMAINS
from smartops.tools.registry import (
    load_mcp_servers,
    mcp_clients,
    tools_for,
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


@pytest.fixture(autouse=True)
def _clean_registry_state(monkeypatch):
    """Each test starts with no clients loaded and restores the real maps."""
    monkeypatch.setattr(registry_module, "_clients_by_family", {})
    # An operator with this exported in their shell must not change how the
    # suite behaves: it would silently route every server in these tests down
    # the unverified-TLS builder instead of MCPClient.load_servers().
    monkeypatch.delenv(registry_module.TLS_NO_VERIFY_ENV_VAR, raising=False)
    yield


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
