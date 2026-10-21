"""Read RFC discussion and publish bounded replies; never modify repository files."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote
from urllib.request import Request, urlopen

REPOSITORY = "zerogravity-reno/smartops-soc-app"
PR_NUMBER = 9
BRANCH = "docs/analyst-broker-quality-gates-rfc"
DOCUMENT = "docs/analyst-broker-quality-gates-rfc.md"
AUTHORS = {"ysalahai", "mrahmy-reno", "ayousry84"}
IGNORED_INVITATIONS = {6324854229}
MARKER = "<!-- smartops-rfc-feedback:v1 "


def event_allowed(name: str, event: dict) -> bool:
    if name == "schedule":
        return True
    actor = event.get("sender", {}).get("login", "").lower()
    if actor not in AUTHORS or event.get("sender", {}).get("type") != "User":
        return False
    if name == "workflow_dispatch":
        return True
    if name == "issue_comment":
        issue = event.get("issue", {})
        return issue.get("number") == PR_NUMBER and bool(issue.get("pull_request"))
    if name in {"pull_request_review_comment", "pull_request_review"}:
        return event.get("pull_request", {}).get("number") == PR_NUMBER
    return False


def target_allowed(pr: dict) -> bool:
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    repository = head.get("repo") or {}
    return (
        pr.get("number") == PR_NUMBER
        and pr.get("state") == "open"
        and pr.get("draft") is True
        and pr.get("auto_merge") is None
        and base.get("ref") == "main"
        and head.get("ref") == BRANCH
        and repository.get("full_name") == REPOSITORY
    )


def feedback_items(issues: list, inline: list, reviews: list) -> list:
    items = []
    for kind, entries in (("comment", issues), ("inline", inline), ("review", reviews)):
        for entry in entries:
            user = entry.get("user") or {}
            if user.get("login", "").lower() not in AUTHORS or user.get("type") != "User":
                continue
            if kind == "comment" and entry["id"] in IGNORED_INVITATIONS:
                continue
            if not (entry.get("body") or "").strip():
                continue
            items.append({
                "kind": kind, "id": entry["id"], "author": user["login"],
                "body": entry["body"], "url": entry["html_url"],
                "updated_at": entry.get("updated_at", entry.get("submitted_at", "")),
                "path": entry.get("path"), "line": entry.get("line"),
                "state": entry.get("state"),
            })
    return sorted(items, key=lambda item: (item["kind"], item["id"]))


def fingerprint(head: str, items: list) -> str:
    data = json.dumps({"head": head, "items": items}, sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


def already_replied(comments: list, digest: str) -> bool:
    marker = f"{MARKER}{digest} -->"
    return any(
        item.get("user", {}).get("login") == "github-actions[bot]"
        and marker in item.get("body", "") for item in comments
    )


def validate_reply(raw: str) -> str:
    result = json.loads(raw)
    if not isinstance(result, dict) or set(result) != {"reply"}:
        raise ValueError("Expected exactly one reply field")
    reply = result["reply"]
    if not isinstance(reply, str) or not 1 <= len(reply.strip()) <= 24000:
        raise ValueError("Reply is empty or exceeds the comment budget")
    if "<!--" in reply or re.search(r"@(?!ysalahai\b|mrahmy-reno\b|ayousry84\b)[\w-]+", reply):
        raise ValueError("Reply contains a control marker or unrelated mention")
    return reply.strip()


class GitHub:
    def request(self, suffix: str, body: dict | None = None):
        token = os.environ["GH_TOKEN"]
        request = Request(
            f"https://api.github.com/repos/{REPOSITORY}/{suffix}",
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    def pages(self, suffix: str) -> list:
        items = []
        for page in range(1, 11):
            batch = self.request(f"{suffix}?per_page=100&page={page}")
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise ValueError("Discussion exceeds pagination budget; no feedback was silently omitted")

    def snapshot(self):
        pr = self.request(f"pulls/{PR_NUMBER}")
        if not target_allowed(pr):
            return None
        comments = self.pages(f"issues/{PR_NUMBER}/comments")
        items = feedback_items(comments, self.pages(f"pulls/{PR_NUMBER}/comments"),
                               self.pages(f"pulls/{PR_NUMBER}/reviews"))
        return pr, comments, items, fingerprint(pr["head"]["sha"], items)


def output(name: str, value: str):
    with open(os.environ["GITHUB_OUTPUT"], "a") as file:
        file.write(f"{name}={value}\n")


def prepare(api: GitHub):
    output("pending", "false")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if not event_allowed(os.environ["GITHUB_EVENT_NAME"], event):
        return
    snapshot = api.snapshot()
    if snapshot is None:
        return
    pr, comments, items, digest = snapshot
    if not items or already_replied(comments, digest):
        return
    source = api.request(f"contents/{DOCUMENT}?ref={quote(pr['head']['sha'], safe='')}")
    document = base64.b64decode(source["content"]).decode()
    previous = [item["body"] for item in comments
                if item.get("user", {}).get("login") == "github-actions[bot]"
                and item.get("body", "").startswith(MARKER)]
    data = json.dumps({"head_sha": pr["head"]["sha"], "proposal": document,
                       "feedback": items, "previous_reply": previous[-1:]}, ensure_ascii=False)
    if len(data) > 140000:
        raise ValueError("Discussion exceeds context budget; no model call made")
    instructions = Path(".github/prompts/rfc-feedback.md").read_text()
    Path(".rfc-feedback-prompt.md").write_text(instructions + "\n\nUNTRUSTED DISCUSSION DATA (JSON):\n" + data)
    output("fingerprint", digest)
    output("pending", "true")


def publish(api: GitHub):
    raw = os.environ["RECONCILIATION_RESULT"]
    if len(raw) > 100000:
        raise ValueError("Model output exceeds budget")
    reply = validate_reply(raw)
    digest = os.environ["FEEDBACK_FINGERPRINT"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid feedback fingerprint")
    snapshot = api.snapshot()
    if snapshot is None:
        print("PR is no longer the open draft target; nothing published")
        return
    _, comments, _, current = snapshot
    if current != digest or already_replied(comments, digest):
        print("Discussion changed or was already handled; next event/sweep will reconcile it")
        return
    body = (f"{MARKER}{digest} -->\n"
            "**Automated RFC discussion — proposal remains draft**\n\n" + reply +
            "\n\n---\nThis bot proposes amendments and tracks discussion; it cannot change files, "
            "approve the proposal, mark the PR ready, or merge it. Reply here to continue the discussion.")
    result = api.request(f"issues/{PR_NUMBER}/comments", {"body": body})
    print("Published discussion reply: " + result["html_url"])


if __name__ == "__main__":
    {"prepare": prepare, "publish": publish}[sys.argv[1]](GitHub())
