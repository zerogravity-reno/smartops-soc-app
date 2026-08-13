"""Unit tests for Requirement R3 Offline Replay Harness (backend/src/smartops/replay.py)."""

import json
from datetime import datetime, timezone
import pytest
from contracts import Evidence, SubagentMission, Scope, Entity
from smartops.replay import (
    ReplayToolset,
    create_replay_subagent_runner,
    get_replay_tools_for_family,
    load_evidence_from_file,
    load_evidence_from_run,
    make_replay_tool,
)


@pytest.fixture
def sample_evidence_items():
    now = datetime.now(timezone.utc)
    return [
        Evidence(
            id="task_100:0",
            tool_family="siem",
            raw={
                "tool": "splunk__splunk_search",
                "query": "search index=botsv3 query=coinhive.com",
                "result": {"status": "success", "results": [{"src_ip": "10.0.1.42", "query": "coinhive.com"}]},
            },
            collected_at=now,
        ),
        Evidence(
            id="task_100:1",
            tool_family="vt",
            raw={
                "tool": "vt_lookup_domain",
                "query": "coinhive.com",
                "result": {"status": "success", "verdict": "malicious", "score": 85},
            },
            collected_at=now,
        ),
    ]


class TestEvidenceLoaders:
    def test_load_evidence_from_file(self, tmp_path):
        ev_file = tmp_path / "evidence.json"
        data = [
            {
                "id": "t1:0",
                "tool_family": "siem",
                "raw": {"tool": "splunk_search", "query": "index=botsv3", "result": {"rows": 5}},
                "collected_at": "2026-08-12T15:00:00Z",
            }
        ]
        ev_file.write_text(json.dumps(data), encoding="utf-8")

        loaded = load_evidence_from_file(ev_file)
        assert len(loaded) == 1
        assert loaded[0].id == "t1:0"
        assert loaded[0].tool_family == "siem"
        assert loaded[0].raw["result"]["rows"] == 5

    def test_load_evidence_from_run(self, tmp_path):
        run_dir = tmp_path / "run_abc"
        run_dir.mkdir(parents=True)
        ev_file = run_dir / "evidence.json"
        data = [
            {
                "id": "t2:0",
                "tool_family": "vt",
                "raw": {"tool": "vt_lookup_domain", "query": "example.com", "result": {"clean": True}},
                "collected_at": "2026-08-12T15:00:00Z",
            }
        ]
        ev_file.write_text(json.dumps(data), encoding="utf-8")

        loaded = load_evidence_from_run("run_abc", base_dir=tmp_path)
        assert len(loaded) == 1
        assert loaded[0].id == "t2:0"


class TestReplayToolsetMatching:
    def test_exact_query_match(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        res = replayer.match("splunk__splunk_search", query="search index=botsv3 query=coinhive.com")

        assert res["status"] == "success"
        assert res["results"][0]["src_ip"] == "10.0.1.42"

    def test_fuzzy_query_match(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        res = replayer.match("splunk__splunk_search", query="coinhive.com")

        assert res["status"] == "success"
        assert res["results"][0]["src_ip"] == "10.0.1.42"

    def test_tool_name_fallback_match(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        res = replayer.match("vt_lookup_domain", query="unknown_domain.com")

        assert res["status"] == "success"
        assert res["verdict"] == "malicious"

    def test_cache_miss_returns_fallback_payload(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        res = replayer.match("unknown_tool_xyz", query="something_else")

        assert res["status"] == "no_data"
        assert "replay cache miss" in res["message"].lower()


class TestReplayToolFactory:
    async def test_make_replay_tool(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        replayed_tool = make_replay_tool("splunk__splunk_search", "Replayed Splunk tool", replayer)

        res = await replayed_tool(query="search index=botsv3 query=coinhive.com")
        assert res["status"] == "success"

    def test_get_replay_tools_for_family(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        siem_tools = get_replay_tools_for_family("siem", replayer)

        tool_names = [getattr(t, "tool_name", getattr(t, "__name__", None)) for t in siem_tools]
        assert "splunk__splunk_search" in tool_names
        assert "read_reference" in tool_names


class TestReplaySubagentRunner:
    def test_create_replay_subagent_runner(self, sample_evidence_items):
        from smartops.budget import Budget, ModelChoice
        replayer = ReplayToolset(sample_evidence_items)
        model = ModelChoice(model_id="mock-model", pricing_key="claude-sonnet-4-6")
        budget = Budget(10.0)

        runner = create_replay_subagent_runner(replayer, model=model, budget=budget)
        assert callable(runner)
