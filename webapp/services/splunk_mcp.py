"""The webapp's own Splunk reads, through the backend's MCP client (`smartops.tools`).

One client, one config (`mcp_servers.json`), one TLS rule: this module used to open
its own MCP session beside the Broker's.
"""

from smartops.tools.registry import call_tool


def run_query(query: str, earliest_time: str = "", latest_time: str = "", row_limit: int = 100) -> list[dict]:
    """`splunk_run_query`'s rows. Raises on a tool error rather than returning it as data."""
    args = {"query": query, "row_limit": row_limit}
    if earliest_time:
        args["earliest_time"] = earliest_time
    if latest_time:
        args["latest_time"] = latest_time
    return call_tool("siem", "splunk_run_query", args).get("results", [])
