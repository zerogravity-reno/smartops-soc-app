from dataclasses import dataclass, field

import smartops.tools.registry as registry_module
from smartops.tools.registry import FAMILY_REGISTRY, ToolFamilyConfig, tools_for


@dataclass
class _FakeMCPClient:
    """Stands in for `strands.tools.mcp.MCPClient` -- records whether
    `.start()` was called before `.list_tools_sync()`, without touching a
    real MCP transport."""

    tools: list
    started: bool = False
    start_calls: int = 0

    def start(self):
        self.started = True
        self.start_calls += 1

    def list_tools_sync(self):
        if not self.started:
            raise RuntimeError("the client session is not running")
        return self.tools


def _install_fake_family(monkeypatch, family, client):
    """Registers `family` with a factory returning the given fake client,
    and clears any cached client for it -- via monkeypatch, so another
    test's cached connection is restored afterward, not leaked forward."""
    monkeypatch.setitem(FAMILY_REGISTRY, family, ToolFamilyConfig(family=family, mcp_client_factories=[lambda: client]))
    monkeypatch.delitem(registry_module._started_clients, family, raising=False)


class TestToolsFor:
    def test_starts_the_client_before_listing_tools(self, monkeypatch):
        client = _FakeMCPClient(tools=["search"])
        _install_fake_family(monkeypatch, "siem", client)

        result = tools_for("siem")

        assert client.started is True
        assert result == ["search"]

    def test_caches_the_started_client_across_calls(self, monkeypatch):
        client = _FakeMCPClient(tools=["search"])
        calls = {"n": 0}

        def factory():
            calls["n"] += 1
            return client

        monkeypatch.setitem(FAMILY_REGISTRY, "siem", ToolFamilyConfig(family="siem", mcp_client_factories=[factory]))
        monkeypatch.delitem(registry_module._started_clients, "siem", raising=False)

        tools_for("siem")
        tools_for("siem")

        assert calls["n"] == 1
        assert client.start_calls == 1

    def test_family_with_no_factories_returns_native_tools_only(self, monkeypatch):
        monkeypatch.setitem(FAMILY_REGISTRY, "edr", ToolFamilyConfig(family="edr", native_tools=["native-tool"]))
        monkeypatch.delitem(registry_module._started_clients, "edr", raising=False)

        assert tools_for("edr") == ["native-tool"]
