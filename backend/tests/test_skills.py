"""Unit tests for Requirement R3 Skill Pack Integration (backend/src/smartops/skills)."""

import pytest
from smartops.skills import (
    SkillPack,
    get_skill_pack,
    inject_skill_routing_table,
    read_reference,
)
from smartops.subagents import _system_prompt_for


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

    def test_siem_system_prompt_automatically_includes_routing_table(self):
        prompt = _system_prompt_for("siem", turns=14)
        assert "SKILL PACK ROUTING TABLE" in prompt
        assert "read_reference" in prompt
        assert "spl_syntax" in prompt
