"""Client-side config for the official Splunk MCP Server (siem family).

GA on Splunkbase (https://splunkbase.splunk.com/app/7931) -- we connect to
it as an MCP client, we do not host it. Exposes SPL search, saved searches,
and index metadata over the Splunk management port with RBAC enforcement.

Auth/transport are not wired yet -- fill in once the target Splunk
instance's connection details are known (management port + Streamable HTTP,
most likely, per the server's own docs; OAuth 2.1 is available in 1.1.0+).
"""

from __future__ import annotations

from strands.tools.mcp import MCPClient


def client() -> MCPClient:
    raise NotImplementedError("wire up Splunk MCP Server connection details")
