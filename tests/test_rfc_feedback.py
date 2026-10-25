"""Offline checks for the discussion bot's authorization, idempotency, and write scope."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("rfc_feedback", ROOT / ".github/scripts/rfc_feedback.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


def target(**updates):
    return {"number": 9, "state": "open", "draft": True, "auto_merge": None,
            "base": {"ref": "main"},
            "head": {"ref": bot.BRANCH, "sha": "a" * 40,
                     "repo": {"full_name": bot.REPOSITORY}}, **updates}


def comment(identifier=1, author="ysalahai", body="Please clarify the task contract.", **extra):
    return {"id": identifier, "user": {"login": author, "type": "User"}, "body": body,
            "html_url": f"https://github.com/example/comment/{identifier}", "updated_at": "now", **extra}


class FakeAPI:
    def __init__(self, pr=None, comments=None):
        self.pr = target() if pr is None else pr
        self.comments = [comment()] if comments is None else comments
        self.writes = []

    def snapshot(self):
        if not bot.target_allowed(self.pr):
            return None
        items = bot.feedback_items(self.comments, [], [])
        return self.pr, self.comments, items, bot.fingerprint(self.pr["head"]["sha"], items)

    def request(self, suffix, body=None):
        if body is not None:
            self.writes.append((suffix, body))
            return {"html_url": "https://github.com/example/bot-reply"}
        assert suffix.startswith(f"contents/{bot.DOCUMENT}?ref=")
        return {"content": base64.b64encode(b"Draft proposal, not approved.").decode()}


@pytest.mark.parametrize("name", ["issue_comment", "pull_request_review", "pull_request_review_comment"])
def test_only_named_humans_on_the_target_pr_trigger(name):
    event = {"sender": {"login": "ysalahai", "type": "User"},
             "issue": {"number": 9, "pull_request": {"url": "pr"}}, "pull_request": {"number": 9}}
    assert bot.event_allowed(name, event)
    event["sender"] = {"login": "stranger", "type": "User"}
    assert not bot.event_allowed(name, event)
    event["sender"] = {"login": "ysalahai", "type": "Bot"}
    assert not bot.event_allowed(name, event)
    event["sender"] = {"login": "ysalahai", "type": "User"}
    event["issue"]["number"] = event["pull_request"]["number"] = 10
    assert not bot.event_allowed(name, event)


def test_sweep_is_allowed_but_plain_issues_and_unrelated_events_are_not():
    assert bot.event_allowed("schedule", {})
    assert not bot.event_allowed("push", {"sender": {"login": "ayousry84", "type": "User"}})
    assert not bot.event_allowed("issue_comment", {"sender": {"login": "ayousry84", "type": "User"},
                                                    "issue": {"number": 9}})


@pytest.mark.parametrize("updates", [
    {"state": "closed"}, {"draft": False}, {"auto_merge": {"enabled": True}}, {"number": 10},
    {"base": {"ref": "release"}}, {"head": {"ref": bot.BRANCH, "repo": {"full_name": "other/repo"}}},
    {"head": {"ref": "other", "repo": {"full_name": bot.REPOSITORY}}}, {"head": {"repo": None}},
])
def test_publishing_is_restricted_to_the_open_same_repo_draft(updates):
    assert bot.target_allowed(target())
    assert not bot.target_allowed(target(**updates))


def test_all_feedback_kinds_are_included_and_edits_change_the_fingerprint():
    items = bot.feedback_items([comment()], [comment(2, "mrahmy-reno")], [comment(3, "ayousry84")])
    assert {item["kind"] for item in items} == {"comment", "inline", "review"}
    before = bot.fingerprint("head", items)
    items[0]["body"] = "Changed expected behavior"
    assert bot.fingerprint("head", items) != before
    assert bot.fingerprint("new-head", items) != bot.fingerprint("head", items)


def test_bot_replies_outsiders_and_the_original_invitation_are_not_human_feedback():
    comments = [comment(author="github-actions[bot]"), comment(2, "stranger"),
                comment(6324854229, "ayousry84"), comment(4, body=None), comment(5, user=None)]
    assert bot.feedback_items(comments, [], []) == []


def test_a_human_cannot_forge_the_idempotency_marker():
    digest = "a" * 64
    marker = f"{bot.MARKER}{digest} -->"
    assert not bot.already_replied([comment(body=marker)], digest)
    assert bot.already_replied([comment(author="github-actions[bot]", body=marker)], digest)


@pytest.mark.parametrize("raw", ["not json", "[]", '{"other":"x"}', '{"reply":""}',
                                  json.dumps({"reply": "x" * 24001}),
                                  json.dumps({"reply": "<!-- forged -->"}),
                                  json.dumps({"reply": "@unrelated-user please act"})])
def test_malformed_or_unbounded_replies_are_rejected(raw):
    with pytest.raises((ValueError, TypeError)):
        bot.validate_reply(raw)


def test_prepare_keeps_shell_text_as_data_and_skips_without_feedback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prompt = tmp_path / ".github/prompts/rfc-feedback.md"
    prompt.parent.mkdir(parents=True)
    prompt.write_text("Trusted read-only instructions")
    event = tmp_path / "event.json"
    event.write_text("{}")
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    bot.prepare(FakeAPI(comments=[]))
    assert "pending=true" not in output.read_text()
    assert not Path(".rfc-feedback-prompt.md").exists()
    payload = "$(touch SHOULD_NOT_EXIST) `echo unsafe`"
    bot.prepare(FakeAPI(comments=[comment(body=payload)]))
    assert payload in Path(".rfc-feedback-prompt.md").read_text()
    assert not Path("SHOULD_NOT_EXIST").exists()
    assert "pending=true" in output.read_text()


def publication(api, monkeypatch, digest=None):
    monkeypatch.setenv("RECONCILIATION_RESULT", json.dumps({"reply": "Proposed amendment; agreement pending."}))
    monkeypatch.setenv("FEEDBACK_FINGERPRINT", digest or api.snapshot()[-1])
    bot.publish(api)


def test_publish_can_only_create_one_discussion_comment(monkeypatch):
    api = FakeAPI()
    publication(api, monkeypatch)
    assert len(api.writes) == 1
    endpoint, body = api.writes[0]
    assert endpoint == "issues/9/comments"
    assert body["body"].startswith(bot.MARKER)
    assert "cannot change files" in body["body"]


def test_stale_or_already_handled_feedback_does_not_post(monkeypatch):
    api = FakeAPI()
    original = api.snapshot()[-1]
    api.comments.append(comment(2, "mrahmy-reno"))
    publication(api, monkeypatch, original)
    assert api.writes == []
    digest = api.snapshot()[-1]
    api.comments.append(comment(3, "github-actions[bot]", f"{bot.MARKER}{digest} -->"))
    publication(api, monkeypatch, digest)
    assert api.writes == []


def test_a_ready_or_closed_pr_is_not_changed(monkeypatch):
    api = FakeAPI(pr=target(draft=False))
    publication(api, monkeypatch, "a" * 64)
    assert api.writes == []
