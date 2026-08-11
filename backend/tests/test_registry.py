import json

import pytest

import smartops.tools.registry as registry_module
from smartops.tools.registry import (
    MCP_SERVERS_BY_FAMILY,
    NATIVE_TOOLS_BY_FAMILY,
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
    monkeypatch.setattr(registry_module, "MCP_SERVERS_BY_FAMILY", dict(MCP_SERVERS_BY_FAMILY))
    monkeypatch.setattr(
        registry_module, "NATIVE_TOOLS_BY_FAMILY", {k: list(v) for k, v in NATIVE_TOOLS_BY_FAMILY.items()}
    )
    yield


def _install_clients(monkeypatch, **by_family):
    monkeypatch.setattr(registry_module, "_clients_by_family", dict(by_family))


class TestToolsFor:
    async def test_family_with_no_clients_and_no_native_tools_resolves_empty(self):
        # The honest current state of every family: not an error, just nothing
        # reachable. Callers report REJECTED from this.
        assert await tools_for("siem") == []

    async def test_native_tools_resolve_without_any_mcp_server(self, monkeypatch):
        monkeypatch.setitem(registry_module.NATIVE_TOOLS_BY_FAMILY, "vt", ["vt_lookup_ip"])

        assert await tools_for("vt") == ["vt_lookup_ip"]

    async def test_mcp_tools_are_appended_to_native_tools(self, monkeypatch):
        monkeypatch.setitem(registry_module.NATIVE_TOOLS_BY_FAMILY, "siem", ["native"])
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
        monkeypatch.setattr(
            registry_module,
            "MCP_SERVERS_BY_FAMILY",
            {"siem": ("shared",), "edr": ("shared",), "ndr": (), "vt": ()},
        )

        with pytest.raises(ValueError, match="mapped to both"):
            load_mcp_servers({"mcpServers": {"shared": {"disabled": True}}})

    def test_malformed_config_raises_rather_than_degrading(self):
        # A deployment error, not a runtime condition -- unlike a missing
        # credential, there is no sensible way to continue.
        with pytest.raises(ValueError):
            load_mcp_servers({"mcpServers": ["not", "a", "mapping"]})


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

        for family, names in MCP_SERVERS_BY_FAMILY.items():
            for name in names:
                assert name in servers, (
                    f"family {family!r} maps to MCP server {name!r}, which the config does not define"
                )
