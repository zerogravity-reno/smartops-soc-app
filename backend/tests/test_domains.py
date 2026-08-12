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
