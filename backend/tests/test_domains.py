"""The domain registry is the single place a security domain is declared.

These are parity tests: every assertion mirrors a constant that used to live
somewhere else in the package. They exist so the refactor that deletes those
constants cannot silently drop one.
"""

import dataclasses
from typing import get_args

import pytest
from contracts import ToolFamily
from smartops.domains import ALL_FAMILIES, DOMAINS, DomainSpec, spec_for
from smartops.tools.native import virustotal


class TestRegistryCoverage:
    def test_every_tool_family_has_exactly_one_spec(self):
        assert set(DOMAINS) == set(get_args(ToolFamily))

    def test_each_spec_is_keyed_by_its_own_family(self):
        for family, spec in DOMAINS.items():
            assert spec.family == family

    def test_spec_for_returns_the_registered_spec(self):
        assert spec_for("siem") is DOMAINS["siem"]

    def test_all_families_matches_the_registry(self):
        assert set(ALL_FAMILIES) == set(DOMAINS)


class TestEntityGateParity:
    """Mirrors the old broker.FAMILY_REQUIRED_KINDS."""

    def test_siem_requires_nothing_because_a_siem_indexes_everything(self):
        assert DOMAINS["siem"].required_kinds is None

    def test_edr_requires_a_host_process_or_user(self):
        assert DOMAINS["edr"].required_kinds == frozenset({"host", "process", "user"})

    def test_ndr_requires_an_ip_domain_or_url(self):
        assert DOMAINS["ndr"].required_kinds == frozenset({"ip", "domain", "url"})

    def test_vt_requires_a_hash_ip_domain_or_url(self):
        assert DOMAINS["vt"].required_kinds == frozenset({"file_hash", "ip", "domain", "url"})


class TestTimeScopingParity:
    """Mirrors the old subagents._TIME_SCOPED_FAMILIES."""

    def test_log_indexed_domains_are_time_scoped(self):
        assert DOMAINS["siem"].time_scoped
        assert DOMAINS["edr"].time_scoped
        assert DOMAINS["ndr"].time_scoped

    def test_reputation_lookup_has_no_time_dimension(self):
        assert not DOMAINS["vt"].time_scoped


class TestToolWiringParity:
    """Mirrors the old registry.MCP_SERVERS_BY_FAMILY / NATIVE_TOOLS_BY_FAMILY."""

    def test_siem_is_served_by_the_splunk_mcp_server(self):
        assert DOMAINS["siem"].mcp_servers == ("splunk",)

    def test_vt_is_a_rest_api_reached_by_native_tools_not_mcp(self):
        assert DOMAINS["vt"].mcp_servers == ()
        assert list(DOMAINS["vt"].native_tools) == list(virustotal.TOOLS)

    def test_only_vt_has_native_tools(self):
        for family in ("siem", "edr", "ndr"):
            assert DOMAINS[family].native_tools == ()

    def test_no_mcp_server_serves_two_families(self):
        seen: set[str] = set()
        for spec in DOMAINS.values():
            for name in spec.mcp_servers:
                assert name not in seen, f"{name} is mapped to two families"
                seen.add(name)


class TestEnricherParity:
    """Mirrors the old registry.ENRICHERS_BY_FAMILY."""

    def test_vt_has_a_model_free_enricher(self):
        assert DOMAINS["vt"].enricher is virustotal.enrich_scope

    def test_domains_needing_a_decision_have_no_enricher(self):
        for family in ("siem", "edr", "ndr"):
            assert DOMAINS[family].enricher is None


class TestDescriptions:
    def test_every_domain_describes_itself_for_the_model(self):
        for spec in DOMAINS.values():
            assert spec.description.strip()

    def test_a_description_says_what_the_domain_is_not_for(self):
        # Each carries a "Do NOT use" clause; that negative guidance is what
        # stops the Broker calling the wrong specialist.
        for spec in DOMAINS.values():
            assert "Do NOT use" in spec.description


class TestImmutability:
    def test_a_spec_cannot_be_mutated_after_construction(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            DOMAINS["siem"].time_scoped = False  # type: ignore[misc]


class TestGeneratedTools:
    """The four investigate_* wrappers are generated from DOMAINS.

    They used to be hand-written and identical apart from one string, which is
    exactly the kind of duplication that drifts -- and since the description
    drives routing, drift there is a silent behaviour change.
    """

    def test_one_tool_is_generated_per_domain(self):
        from smartops.broker import FAMILY_TOOLS

        assert len(FAMILY_TOOLS) == len(DOMAINS)

    def test_each_tool_is_named_for_its_family(self):
        from smartops.broker import TOOL_BY_FAMILY

        for family, tool in TOOL_BY_FAMILY.items():
            assert tool.tool_name == f"investigate_{family}"

    def test_the_model_facing_description_comes_from_the_spec(self):
        from smartops.broker import TOOL_BY_FAMILY

        for family, tool in TOOL_BY_FAMILY.items():
            described = tool.tool_spec["description"]
            assert "Do NOT use" in described
            assert described.splitlines()[0] in DOMAINS[family].description

    def test_question_is_the_models_only_parameter(self):
        from smartops.broker import TOOL_BY_FAMILY

        for tool in TOOL_BY_FAMILY.values():
            # tool_context is injected by the framework, never by the model.
            properties = tool.tool_spec["inputSchema"]["json"]["properties"]
            assert set(properties) == {"question"}

    def test_the_question_parameter_is_described_for_the_model(self):
        from smartops.broker import TOOL_BY_FAMILY

        for tool in TOOL_BY_FAMILY.values():
            question = tool.tool_spec["inputSchema"]["json"]["properties"]["question"]
            assert question["description"].strip()

    async def test_a_generated_tool_dispatches_its_own_family(self, monkeypatch):
        """Each closure carries its own family. Closing over a loop variable
        would make every generated tool dispatch the last one."""
        import smartops.broker as broker

        seen: list[str] = []

        async def fake_dispatch(family, question, ctx):
            seen.append(family)
            return "ok"

        monkeypatch.setattr(broker, "_dispatch", fake_dispatch)

        for tool in broker.TOOL_BY_FAMILY.values():
            await tool(question="q", tool_context=object())

        assert seen == list(broker.TOOL_BY_FAMILY)


class TestAddingADomainIsOneEntry:
    """The claim this refactor is for, made executable.

    A new domain should need a DomainSpec and nothing else in code. This builds
    one that is not in DOMAINS and drives it through the machinery that used to
    require nine other edits.
    """

    def _spec(self):
        return DomainSpec(
            family="edr",  # a real ToolFamily member; the values below are not EDR's
            description=(
                "Fictional domain used only by this test.\n"
                "\n"
                "Do NOT use it for anything real."
            ),
            required_kinds=frozenset({"user"}),
            time_scoped=False,
            mcp_servers=("fictional",),
        )

    def test_a_new_spec_produces_a_working_tool_with_no_other_code_change(self):
        from smartops.broker import make_investigate_tool

        tool = make_investigate_tool(self._spec())

        assert tool.tool_name == "investigate_edr"
        assert "Fictional domain" in tool.tool_spec["description"]
        assert set(tool.tool_spec["inputSchema"]["json"]["properties"]) == {"question"}

    def test_a_new_spec_carries_its_own_prompt_shape(self):
        from smartops.subagents import _system_prompt_for

        spec = self._spec()
        prompt = _system_prompt_for(spec.family, turns=4, time_scoped=spec.time_scoped)

        # time_scoped=False must select the lookup guidance, not the time rule.
        assert "rate limited" in prompt
        assert "do NOT use relative times" not in prompt
