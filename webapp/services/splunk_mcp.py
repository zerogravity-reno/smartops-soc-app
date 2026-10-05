"""The webapp's own Splunk reads, through the official Splunk MCP server.

The same server and credentials the Tool Broker uses (`mcp_servers.json`):
`SPLUNK_MCP_URL` plus a bearer `SPLUNK_TOKEN`, with TLS verification skipped only
when `SMARTOPS_MCP_TLS_NO_VERIFY` names `splunk` (a self-signed :8089 cert).
"""

import asyncio
import os

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


def run_query(query: str, earliest_time: str = "", latest_time: str = "", row_limit: int = 100) -> list[dict]:
    """`splunk_run_query`'s rows. Raises on a tool error rather than returning it as data."""
    args = {"query": query, "row_limit": row_limit}
    if earliest_time:
        args["earliest_time"] = earliest_time
    if latest_time:
        args["latest_time"] = latest_time
    return asyncio.run(_call("splunk_run_query", args)).get("results", [])


async def _call(tool: str, args: dict) -> dict:
    no_verify = {n.strip() for n in os.environ.get("SMARTOPS_MCP_TLS_NO_VERIFY", "").split(",")}

    def client(headers=None, timeout=None, auth=None):
        return httpx.AsyncClient(headers=headers, timeout=timeout, auth=auth, verify="splunk" not in no_verify)

    headers = {"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN']}"}
    async with streamablehttp_client(
        os.environ["SPLUNK_MCP_URL"], headers=headers, httpx_client_factory=client, timeout=60
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
    if result.isError:
        raise RuntimeError(result.content[0].text if result.content else f"{tool} failed")
    return result.structuredContent or {}
