import httpx
import warnings
import json
import time
import os
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

warnings.filterwarnings('ignore')
load_dotenv()

mcp = FastMCP("LocalSplunk")

BASE_URL = os.environ.get("SPLUNK_WEB_URL", "https://wobbly-erased-starter.ngrok-free.dev")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "ysalah")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "12345679")
SKIP = {"ngrok-skip-browser-warning": "true"}


def make_authenticated_client():
    """Login via Splunk Web UI and return an authenticated httpx.Client with cookies."""
    client = httpx.Client(verify=False, follow_redirects=True)

    # Step 1: GET login page to get cval CSRF cookie
    client.get(f"{BASE_URL}/en-US/account/login", headers=SKIP, timeout=15)
    cval = client.cookies.get("cval", "")

    # Step 2: POST login form with CSRF value
    client.post(
        f"{BASE_URL}/en-US/account/login",
        headers=SKIP,
        data={"username": SPLUNK_USER, "password": SPLUNK_PASS,
              "cval": cval, "return_to": "/en-US/"},
        timeout=15,
    )

    csrf_token = client.cookies.get("splunkweb_csrf_token_8000", "")
    client.headers.update({
        **SKIP,
        "X-Splunk-Form-Key": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
    })
    return client


@mcp.tool()
def search_splunk(query: str, count: int = 50) -> str:
    """Run an SPL query on Splunk to search for logs.

    Args:
        query: The SPL query to run. Must be valid Splunk SPL.
        count: The maximum number of results to return.
    """
    try:
        if not query.startswith("search "):
            query = "search " + query

        client = make_authenticated_client()
        csrf_token = client.cookies.get("splunkweb_csrf_token_8000", "")
        try:
            # Create async job — include CSRF token in body too
            r = client.post(
                f"{BASE_URL}/en-US/splunkd/__raw/services/search/jobs?output_mode=json",
                data={"search": query, "exec_mode": "normal", "splunk_form_key": csrf_token},
                timeout=30,
                follow_redirects=True,
            )

            if r.status_code in (301, 302, 303, 307, 308):
                return json.dumps({
                    "status": "error",
                    "message": f"Auth redirect: {r.headers.get('location', '?')}"
                })

            r.raise_for_status()
            sid = r.json()["sid"]

            # Poll until done (max 60s)
            state = "QUEUED"
            for _ in range(60):
                sr = client.get(
                    f"{BASE_URL}/en-US/splunkd/__raw/services/search/jobs/{sid}?output_mode=json",
                    timeout=10, follow_redirects=False,
                )
                if sr.status_code != 200:
                    break
                state = sr.json()["entry"][0]["content"]["dispatchState"]
                if state in ("DONE", "FAILED"):
                    break
                time.sleep(1)

            if state == "FAILED":
                return json.dumps({"status": "error", "message": "Splunk job failed."})

            # Get results
            rr = client.get(
                f"{BASE_URL}/en-US/splunkd/__raw/services/search/jobs/{sid}/results"
                f"?output_mode=json&count={count}",
                timeout=30, follow_redirects=False,
            )
            rr.raise_for_status()
            results_list = rr.json().get("results", [])

            if not results_list:
                return json.dumps({"status": "empty", "message": "No results found.", "results": []})

            return json.dumps(results_list, indent=2)
        finally:
            client.close()

    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})



@mcp.tool()
def list_detection_rules(search_name: str = "", app: str = "SplunkEnterpriseSecuritySuite", count: int = 25, enabled_only: bool = False) -> str:
    """List ESCU detection rules from Splunk ES Content Management.

    Args:
        search_name: Optional keyword to filter rule names (e.g. 'crypto', 'powershell').
        app: Splunk app context (default: SplunkEnterpriseSecuritySuite).
        count: Max number of rules to return (default: 25).
        enabled_only: If True, return only enabled (non-disabled) rules.
    """
    try:
        client = make_authenticated_client()
        try:
            filter_param = ""
            if search_name:
                import urllib.parse
                filter_param = f"&search=name%3D*{urllib.parse.quote(search_name)}*"

            r = client.get(
                f"{BASE_URL}/en-US/splunkd/__raw/servicesNS/-/{app}/saved/searches"
                f"?output_mode=json&count={count}&f=name&f=search&f=disabled&f=is_scheduled&f=description"
                f"&search=name%3DESCU*{filter_param}",
                timeout=30,
            )
            r.raise_for_status()
            rules = []
            for e in r.json().get("entry", []):
                c = e.get("content", {})
                disabled = c.get("disabled", True)
                if enabled_only and disabled:
                    continue
                rules.append({
                    "name": e["name"],
                    "status": "enabled" if not disabled else "disabled",
                    "scheduled": c.get("is_scheduled", False),
                    "spl": c.get("search", ""),
                    "description": c.get("description", ""),
                })
            return json.dumps({"total": len(rules), "rules": rules}, indent=2)
        finally:
            client.close()
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
def get_notable_events(hours: int = 24, urgency: str = "", status: str = "", count: int = 20) -> str:
    """Get active notable events (alerts) from Splunk ES Mission Control.

    Args:
        hours: How many hours back to look (default: 24).
        urgency: Filter by urgency level (e.g. 'critical', 'high', 'medium', 'low').
        status: Filter by status (e.g. 'new', 'in progress', 'resolved').
        count: Max number of events to return (default: 20).
    """
    try:
        client = make_authenticated_client()
        csrf_token = client.cookies.get("splunkweb_csrf_token_8000", "")
        try:
            filters = f"earliest=-{hours}h"
            if urgency:
                filters += f" urgency={urgency}"
            if status:
                filters += f" status=\"{status}\""

            spl = (
                f"search index=notable {filters}"
                f" | table _time rule_name urgency status src dest user src_ip rule_id"
                f" | sort -_time"
                f" | head {count}"
            )

            r = client.post(
                f"{BASE_URL}/en-US/splunkd/__raw/services/search/jobs?output_mode=json",
                data={"search": spl, "exec_mode": "normal", "splunk_form_key": csrf_token},
                timeout=30,
            )
            r.raise_for_status()
            sid = r.json()["sid"]

            state = "QUEUED"
            for _ in range(60):
                sr = client.get(
                    f"{BASE_URL}/en-US/splunkd/__raw/services/search/jobs/{sid}?output_mode=json",
                    timeout=10,
                )
                if sr.status_code != 200:
                    break
                state = sr.json()["entry"][0]["content"]["dispatchState"]
                if state in ("DONE", "FAILED"):
                    break
                time.sleep(1)

            rr = client.get(
                f"{BASE_URL}/en-US/splunkd/__raw/services/search/jobs/{sid}/results"
                f"?output_mode=json&count={count}",
                timeout=30,
            )
            rr.raise_for_status()
            results = rr.json().get("results", [])
            return json.dumps({"total": len(results), "notable_events": results}, indent=2)
        finally:
            client.close()
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


if __name__ == "__main__":
    import sys
    sys.stderr.write("Starting Splunk MCP Server on stdio...\n")
    sys.stderr.flush()
    mcp.run()
