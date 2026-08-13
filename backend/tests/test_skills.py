"""Unit tests for Requirement R3 Skill Pack Integration (backend/src/smartops/skills)."""

from datetime import UTC, datetime

import pytest
from smartops import subagents
from smartops.budget import Budget, ModelChoice
from smartops.skills import (
    SKILLS_ENABLED_ENV_VAR,
    SkillPack,
    get_skill_pack,
    inject_skill_routing_table,
    read_reference,
    skills_enabled,
)
from smartops.subagents import _system_prompt_for, domain_runner

from contracts import (
    Entity,
    Scope,
    SubagentMission,
    SubtaskResult,
    SubtaskStatus,
)

MODEL = ModelChoice(model_id="test-model", pricing_key="claude-sonnet-4-6")


class TestSupermanSplunkSkillPack:
    def test_vended_skill_pack_exists_and_loads(self):
        pack = get_skill_pack("superman-splunk")
        assert isinstance(pack, SkillPack)
        assert pack.name == "superman-splunk"
        assert "superman-splunk" in pack.routing_table.lower()
        assert len(pack.references) == 5

    def test_five_expected_references_present(self):
        pack = get_skill_pack("superman-splunk")
        expected_refs = {
            "spl_syntax",
            "cim_data_models",
            "botsv3_sourcetypes",
            "investigation_playbooks",
            "performance_optimization",
        }
        assert set(pack.references.keys()) == expected_refs

    def test_total_skill_pack_line_count_is_near_target(self):
        pack = get_skill_pack("superman-splunk")
        total_lines = len(pack.routing_table.splitlines())
        for content in pack.references.values():
            total_lines += len(content.splitlines())

        # Target is ~1,100-1,700 lines across 5 references + SKILL.md
        assert total_lines >= 1000, f"Expected >= 1,000 lines, got {total_lines}"

    def test_load_reference_case_insensitive_and_extension_flexible(self):
        pack = get_skill_pack("superman-splunk")

        content1 = pack.load_reference("spl_syntax")
        content2 = pack.load_reference("SPL_SYNTAX")
        content3 = pack.load_reference("spl_syntax.md")

        assert "SPL Query Syntax" in content1
        assert content1 == content2 == content3

    def test_load_reference_unknown_returns_available_options(self):
        pack = get_skill_pack("superman-splunk")
        result = pack.load_reference("unknown_reference_xyz")

        assert "not found" in result.lower()
        assert "available references" in result.lower()
        assert "spl_syntax" in result
        assert "cim_data_models" in result


class TestReadReferenceTool:
    def test_read_reference_tool_direct_call(self):
        res = read_reference("cim_data_models")
        assert "Common Information Model" in res
        assert "Network Resolution" in res

    def test_read_reference_tool_handles_invalid_name(self):
        res = read_reference("invalid_ref_name")
        assert "not found" in res.lower()
        assert "spl_syntax" in res


class TestSystemPromptRoutingTableInjection:
    def test_inject_skill_routing_table(self):
        base_prompt = "You are a SIEM specialist."
        injected = inject_skill_routing_table(base_prompt)

        assert "SKILL PACK ROUTING TABLE (superman-splunk)" in injected
        assert "read_reference" in injected
        assert "spl_syntax" in injected
        assert "cim_data_models" in injected

    def test_inject_skill_routing_table_is_idempotent(self):
        base_prompt = "You are a SIEM specialist."
        injected_once = inject_skill_routing_table(base_prompt)
        injected_twice = inject_skill_routing_table(injected_once)

        assert injected_once == injected_twice


class TestSkillPackGate:
    """The pack is one switch, `SMARTOPS_SKILLS_ENABLED`, governing both halves.

    The load-bearing assertions here are the negative ones. Arm S of the A/B is
    the only arm that can receive this pack, so while the A/B is running, an
    unset environment must produce a `siem` subagent with no routing table in its
    system prompt *and* no `read_reference` in its toolset -- otherwise the
    comparison of tool count, token cost and turns is measuring the pack rather
    than the topology.

    The positive cases are here so the gate is provably a gate and not a
    deletion: flip the flag and both halves come back.
    """

    @staticmethod
    async def _siem_tools(monkeypatch, base_tools):
        """The toolset `domain_runner` hands to `investigate` for `siem`."""
        captured: dict[str, list] = {}

        async def fake_investigate(mission, **kwargs):
            captured["tools"] = list(kwargs["tools"])
            return SubtaskResult(task_id=mission.task_id, status=SubtaskStatus.OK)

        monkeypatch.setattr(subagents, "tools_for", _async_returning(list(base_tools)))
        monkeypatch.setattr(subagents, "investigate", fake_investigate)

        run = domain_runner(model=MODEL, budget=Budget.from_usd(1.0))
        await run(_siem_mission())
        return captured["tools"]

    def test_disabled_unless_explicitly_enabled(self, monkeypatch):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)
        assert skills_enabled() is False

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
    def test_non_truthy_values_leave_it_disabled(self, monkeypatch, value):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, value)
        assert skills_enabled() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy_values_enable_it(self, monkeypatch, value):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, value)
        assert skills_enabled() is True

    def test_siem_prompt_has_no_routing_table_when_disabled(self, monkeypatch):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)

        prompt = _system_prompt_for("siem", turns=14)

        assert "SKILL PACK ROUTING TABLE" not in prompt
        assert "read_reference" not in prompt
        assert "spl_syntax" not in prompt
        # The prompt is otherwise untouched -- gated, not gutted.
        assert "siem domain specialist" in prompt

    async def test_siem_toolset_has_no_read_reference_when_disabled(self, monkeypatch):
        monkeypatch.delenv(SKILLS_ENABLED_ENV_VAR, raising=False)

        tools = await self._siem_tools(monkeypatch, ["splunk__splunk_search"])

        assert read_reference not in tools
        assert tools == ["splunk__splunk_search"]

    def test_siem_prompt_has_routing_table_when_enabled(self, monkeypatch):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        prompt = _system_prompt_for("siem", turns=14)

        assert "SKILL PACK ROUTING TABLE" in prompt
        assert "read_reference" in prompt
        assert "spl_syntax" in prompt

    async def test_siem_toolset_has_read_reference_when_enabled(self, monkeypatch):
        monkeypatch.setenv(SKILLS_ENABLED_ENV_VAR, "1")

        tools = await self._siem_tools(monkeypatch, ["splunk__splunk_search"])

        assert read_reference in tools


def _siem_mission() -> SubagentMission:
    return SubagentMission(
        task_id="case-1:siem:u1",
        hypothesis_id="h1",
        tool_family="siem",
        goal="what happened",
        scope=Scope(
            entities=[Entity(kind="host", value="BSTOLL-L")],
            time_window=(
                datetime(2018, 8, 20, tzinfo=UTC),
                datetime(2018, 8, 21, tzinfo=UTC),
            ),
        ),
    )


def _async_returning(value):
    async def fake(*args, **kwargs):
        return value

    return fake
