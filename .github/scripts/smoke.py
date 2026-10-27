"""Check that a running SmartOps API serves the built UI and the local ESCU corpus.

Usage: python .github/scripts/smoke.py [base_url]
Waits up to 60 s for the server, so CI can start uvicorn in the background first.
"""

import json
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8013"

deadline = time.monotonic() + 60
while True:
    try:
        with urlopen(base + "/", timeout=5) as page:
            body = page.read()
        break
    except (URLError, ConnectionError):
        if time.monotonic() > deadline:
            sys.exit(f"server at {base} did not answer within 60 s")
        time.sleep(1)

assert b'id="root"' in body, "UI not served: build the frontend first"
request = Request(
    base + "/api/escu",
    data=json.dumps({"rule_name": "Windows PowerShell DownloadString"}).encode(),
    headers={"Content-Type": "application/json"},
)
with urlopen(request, timeout=10) as response:
    result = json.load(response)
assert result["status"] == "success" and result["matches"], result
print("UI and ESCU lookup passed")
