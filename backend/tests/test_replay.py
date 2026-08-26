"""Unit tests for Requirement R3 Offline Replay Harness (backend/src/smartops/replay.py)."""

import json
from datetime import UTC, datetime

import pytest
from smartops import subagents
from smartops.budget import Budget, ModelChoice
from smartops.replay import (
    ReplayToolset,
    create_replay_subagent_runner,
    get_replay_tools_for_family,
    load_evidence_from_file,
    load_evidence_from_run,
    make_replay_tool,
)
from smartops.skills import SKILLS_ENABLED_ENV_VAR
from smartops.subagents import _system_prompt_for

from contracts import Entity, Evidence, Scope, SubagentMission, SubtaskResult, SubtaskStatus


def _tool_names(tools) -> list:
    return [getattr(t, "tool_name", getattr(t, "__name__", None)) for t in tools]


@pytest.fixture
def sample_evidence_items():
    now = datetime.now(UTC)
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


class TestLoadingARunTheBrokerActuallyWrote:
    """`save_run_artifacts()` writes `<base>/<task_id>/<stamp>/`, not
    `<base>/<run_id>/`.

    The timestamped layout landed in `cfeae8a`/`2ed11e7` so two runs of one case
    would stop overwriting each other, and this loader was never moved with it --
    so every call for a real case raised `FileNotFoundError`, having appended
    `evidence.json` to a directory that holds only timestamp subdirectories and
    `latest.txt`.
    """

    @staticmethod
    def _write_run(base, task_id, stamp, evidence_id):
        run_dir = base / task_id / stamp
        run_dir.mkdir(parents=True)
        (run_dir / "evidence.json").write_text(
            json.dumps(
                [
                    {
                        "id": evidence_id,
                        "tool_family": "siem",
                        "raw": {"tool": "splunk_search", "query": "index=botsv3", "result": {}},
                        "collected_at": "2026-08-15T15:00:00Z",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return run_dir

    def test_a_case_id_loads_the_run_latest_txt_names(self, tmp_path):
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T112844145", "old:0")
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T161337647", "new:0")
        (tmp_path / "botsv3_coinhive" / "latest.txt").write_text(
            "20260815T161337647", encoding="utf-8"
        )

        loaded = load_evidence_from_run("botsv3_coinhive", base_dir=tmp_path)

        assert [e.id for e in loaded] == ["new:0"]

    def test_without_latest_txt_the_newest_stamp_wins(self, tmp_path):
        # The stamps sort lexicographically because they are zero-padded
        # `%Y%m%dT%H%M%S%f`, so this needs no parsing.
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T112844145", "old:0")
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T161337647", "new:0")

        loaded = load_evidence_from_run("botsv3_coinhive", base_dir=tmp_path)

        assert [e.id for e in loaded] == ["new:0"]

    def test_an_explicit_stamp_loads_exactly_that_run(self, tmp_path):
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T112844145", "old:0")
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T161337647", "new:0")

        loaded = load_evidence_from_run("botsv3_coinhive/20260815T112844145", base_dir=tmp_path)

        assert [e.id for e in loaded] == ["old:0"]

    def test_the_runs_dir_env_var_is_honoured(self, tmp_path, monkeypatch):
        # The writer defaults `base_dir` from SMARTOPS_RUNS_DIR; a reader that
        # hardcodes `.smartops/runs` looks in a different tree entirely.
        self._write_run(tmp_path, "botsv3_coinhive", "20260815T161337647", "new:0")
        monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))

        loaded = load_evidence_from_run("botsv3_coinhive")

        assert [e.id for e in loaded] == ["new:0"]

    def test_a_case_with_no_runs_says_so(self, tmp_path):
        (tmp_path / "botsv3_coinhive").mkdir(parents=True)

        with pytest.raises(FileNotFoundError, match="botsv3_coinhive"):
            load_evidence_from_run("botsv3_coinhive", base_dir=tmp_path)


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

    def test_get_replay_tools_for_family(self, sample_evidence_items, monkeypatch):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)
        replayer = ReplayToolset(sample_evidence_items)
        siem_tools = get_replay_tools_for_family("siem", replayer)

        tool_names = _tool_names(siem_tools)
        assert "splunk__splunk_search" in tool_names
        # `read_reference` is half of the skill pack, which is off by default --
        # see `TestReplayKeepsTheSkillPackHalvesTogether` below.
        assert "read_reference" not in tool_names


class TestReplayKeepsTheSkillPackHalvesTogether:
    """A replay gets both halves of the skill pack, or neither -- never one.

    The two halves are built by different modules: `replay.py` assembles the
    toolset, while the routing table that tells the model `read_reference` exists
    is injected by `subagents._system_prompt_for`, which `investigate` calls on
    the replay's behalf. Nothing but a test holds those two together, and the
    failure mode is silent -- a replay ships a tool the prompt never mentions, or
    advertises a tool that is not attached, and diverges from the run it claims
    to be replaying without saying so.

    So this asserts the two halves against each other in both directions, rather
    than asserting either one's contents.
    """

    @staticmethod
    async def _replayed_siem_prompt_and_tools(monkeypatch, evidence):
        """What the replay runner hands `investigate` for a `siem` mission."""
        captured: dict = {}

        async def fake_investigate(mission, **kwargs):
            captured["tools"] = _tool_names(kwargs["tools"])
            # The prompt `investigate` would build for this mission -- see
            # `subagents._run_agent`, which is the only construction site.
            captured["prompt"] = _system_prompt_for(
                mission.tool_family, turns=kwargs["turns"]
            )
            return SubtaskResult(task_id=mission.task_id, status=SubtaskStatus.OK)

        monkeypatch.setattr(subagents, "investigate", fake_investigate)

        runner = create_replay_subagent_runner(
            ReplayToolset(evidence),
            model=ModelChoice(model_id="mock-model", pricing_key="claude-sonnet-4-6"),
            budget=Budget(10.0),
        )
        await runner(_siem_replay_mission())
        return captured

    async def test_neither_half_by_default(self, monkeypatch, sample_evidence_items):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)

        captured = await self._replayed_siem_prompt_and_tools(
            monkeypatch, sample_evidence_items
        )

        assert "read_reference" not in captured["tools"]
        assert "read_reference" not in captured["prompt"]
        assert "SKILL PACK ROUTING TABLE" not in captured["prompt"]
        # Gated, not gutted: the replayed domain tools are still there.
        assert "splunk__splunk_search" in captured["tools"]

    async def test_both_halves_when_enabled(self, monkeypatch, sample_evidence_items):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        captured = await self._replayed_siem_prompt_and_tools(
            monkeypatch, sample_evidence_items
        )

        assert "read_reference" in captured["tools"]
        assert "read_reference" in captured["prompt"]
        assert "SKILL PACK ROUTING TABLE" in captured["prompt"]

    @pytest.mark.parametrize("env_value", [None, "0", "1", "true"])
    async def test_the_tool_and_the_table_never_disagree(
        self, monkeypatch, sample_evidence_items, env_value
    ):
        """The invariant itself, stated once: whatever the switch says, the
        toolset and the prompt say the same thing as each other."""
        if env_value is None:
            monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)
        else:
            monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, env_value)

        captured = await self._replayed_siem_prompt_and_tools(
            monkeypatch, sample_evidence_items
        )

        tool_attached = "read_reference" in captured["tools"]
        table_injected = "SKILL PACK ROUTING TABLE" in captured["prompt"]
        assert tool_attached == table_injected


class TestReplaySubagentRunner:
    def test_create_replay_subagent_runner(self, sample_evidence_items):
        replayer = ReplayToolset(sample_evidence_items)
        model = ModelChoice(model_id="mock-model", pricing_key="claude-sonnet-4-6")
        budget = Budget(10.0)

        runner = create_replay_subagent_runner(replayer, model=model, budget=budget)
        assert callable(runner)


def _siem_replay_mission() -> SubagentMission:
    return SubagentMission(
        task_id="replay-1:siem:u1",
        hypothesis_id="h1",
        tool_family="siem",
        goal="what did BSTOLL-L do with coinhive.com",
        scope=Scope(
            entities=[Entity(kind="host", value="BSTOLL-L")],
            time_window=(
                datetime(2018, 8, 20, tzinfo=UTC),
                datetime(2018, 8, 21, tzinfo=UTC),
            ),
        ),
    )


class TestEvidenceById:
    """A `ResultSet.evidence_id` / `Exhibit.evidence_ids` entry must be resolvable.

    Those ids are the whole point of the link contract, and the store could only
    hand back a list for the caller to scan itself.
    """

    @staticmethod
    def _run(tmp_path, *ids: str):
        run_dir = tmp_path / "run_x"
        run_dir.mkdir(parents=True)
        (run_dir / "evidence.json").write_text(
            json.dumps(
                [
                    {
                        "id": eid,
                        "tool_family": "siem",
                        "raw": {"tool": "splunk_search", "query": eid, "result": {"rows": 1}},
                        "collected_at": "2026-08-25T10:07:00Z",
                    }
                    for eid in ids
                ]
            ),
            encoding="utf-8",
        )
        return run_dir

    def test_keys_are_evidence_ids(self, tmp_path):
        from smartops.replay import evidence_by_id

        run_dir = self._run(tmp_path, "t:siem:a:0", "t:siem:a:1")

        by_id = evidence_by_id(run_dir)

        assert by_id.keys() == {"t:siem:a:0", "t:siem:a:1"}
        assert by_id["t:siem:a:1"].raw["query"] == "t:siem:a:1"

    def test_a_duplicate_id_warns_and_keeps_the_later_record(self, tmp_path, caplog):
        import logging

        from smartops.replay import evidence_by_id

        run_dir = self._run(tmp_path, "t:siem:a:0", "t:siem:a:0")

        with caplog.at_level(logging.WARNING, logger="smartops.replay"):
            by_id = evidence_by_id(run_dir)

        assert len(by_id) == 1
        assert "appears more than once" in caplog.text


class TestModelAuthoredAnswersAreFilteredOnRead:
    """`Evidence` is raw tool output, never model-authored.

    `_EvidenceCollector` enforces that at capture, but 22 of the 26 runs on disk
    predate that skip and hold 60 `SiemAnswer`/`VtAnswer` records. They are not
    inert: `build_replay_tools` mints one replay tool per recorded tool name, so
    an unfiltered `VtAnswer` record becomes a tool that hands a subagent the
    model's own prior answer as though a tool had returned it.
    """

    @staticmethod
    def _file(tmp_path):
        ev = tmp_path / "evidence.json"
        ev.write_text(
            json.dumps(
                [
                    {
                        "id": "t:vt:x:0",
                        "tool_family": "vt",
                        "raw": {
                            "tool": "vt_lookup_domain",
                            "query": "coinhive.com",
                            "result": {"malicious": 11},
                        },
                        "collected_at": "2026-08-20T13:36:00Z",
                    },
                    {
                        "id": "t:vt:x:1",
                        "tool_family": "vt",
                        "raw": {
                            "tool": "VtAnswer",
                            "query": None,
                            "result": {"text": "Successfully validated VtAnswer structured output"},
                        },
                        "collected_at": "2026-08-20T13:36:01Z",
                    },
                ]
            ),
            encoding="utf-8",
        )
        return ev

    def test_the_answer_record_is_dropped(self, tmp_path):
        loaded = load_evidence_from_file(self._file(tmp_path))

        assert [e.id for e in loaded] == ["t:vt:x:0"]

    def test_surviving_ids_are_not_renumbered(self, tmp_path):
        """The reason this is a read-time filter and not a purge.

        `evidence_id()` is `f"{task_id}:{index}"`. Deleting a record from the
        artifact renumbers every record after it and silently re-targets every
        stored citation. Ids travel inside the record, so dropping one on read
        re-targets nothing -- and that is what this asserts.
        """
        ev = tmp_path / "evidence.json"
        records = [
            {
                "id": f"t:siem:x:{i}",
                "tool_family": "siem",
                "raw": {"tool": "SiemAnswer" if i == 1 else "splunk_run_query", "result": {}},
                "collected_at": "2026-08-20T13:36:00Z",
            }
            for i in range(4)
        ]
        ev.write_text(json.dumps(records), encoding="utf-8")

        loaded = load_evidence_from_file(ev)

        # index 1 is gone; 2 and 3 keep their original ids rather than sliding down.
        assert [e.id for e in loaded] == ["t:siem:x:0", "t:siem:x:2", "t:siem:x:3"]

    def test_a_forensic_read_can_still_see_everything(self, tmp_path):
        loaded = load_evidence_from_file(self._file(tmp_path), include_model_answers=True)

        assert [e.id for e in loaded] == ["t:vt:x:0", "t:vt:x:1"]

    def test_it_says_what_it_dropped(self, tmp_path, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="smartops.replay"):
            load_evidence_from_file(self._file(tmp_path))

        assert "t:vt:x:1" in caplog.text
        assert "not evidence" in caplog.text

    def test_the_replay_index_never_offers_an_answer_tool(self, tmp_path):
        """The consequence that made this worth fixing rather than noting."""
        from smartops.replay import ReplayToolset

        # Straight from raw dicts: this path never touches the loader.
        toolset = ReplayToolset(
            [
                {"tool": "vt_lookup_domain", "query": "coinhive.com", "result": {"malicious": 11}},
                {"tool": "VtAnswer", "query": None, "result": {"text": "model's own answer"}},
            ]
        )

        assert {r["tool"] for r in toolset.records} == {"vt_lookup_domain"}
        # And asking for it by name is an honest cache miss, not the model's answer.
        missed = toolset.match("VtAnswer")
        assert missed.get("replay") is True
