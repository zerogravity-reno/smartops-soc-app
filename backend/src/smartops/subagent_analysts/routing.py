"""Split one `BrokerReport` into per-domain evidence slices.

Routing is by CIM category and entity kind, in code -- not a model decision:

- identity  <- auth_events
- network   <- dns_resolutions, connections, and VT verdicts for ip/domain/url
- endpoint  <- processes, and VT verdicts for file_hash

`uncategorised` SIEM result sets (rows whose query the fetch model never tagged
with a category -- an honesty bucket, see `SiemFindings.uncategorised`) have no
known category, so they are routed by the scope's entity kinds and flagged as
untagged. They are never dropped: they were retrieved and paid for.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from contracts import (
    AnalystDomain,
    BrokerReport,
    CimCategory,
    ResultSet,
    Scope,
    SiemFindings,
    VtFindings,
    VtVerdict,
)

logger = logging.getLogger(__name__)

# CIM category -> the analysis domain that owns it.
_CATEGORY_DOMAIN: dict[CimCategory, AnalystDomain] = {
    "auth_events": "identity",
    "dns_resolutions": "network",
    "connections": "network",
    "processes": "endpoint",
}

# VirusTotal indicator kind -> the analysis domain reputation for it belongs to.
_VT_KIND_DOMAIN: dict[str, AnalystDomain] = {
    "ip": "network",
    "domain": "network",
    "url": "network",
    "file_hash": "endpoint",
}

# Entity kind -> the domain(s) an untagged result set is offered to when its scope
# includes that kind. `user` owns identity; `host`, `process`, `file_hash` own endpoint;
# `ip`, `domain`, `url` own network.
_ENTITY_KIND_DOMAINS: dict[str, tuple[AnalystDomain, ...]] = {
    "user": ("identity",),
    "host": ("endpoint",),
    "ip": ("network",),
    "domain": ("network",),
    "url": ("network",),
    "file_hash": ("endpoint",),
    "process": ("endpoint",),
}


@dataclass
class DomainSlice:
    """The evidence one domain analyst reasons over."""

    domain: AnalystDomain
    siem_sets: list[tuple[CimCategory, ResultSet]] = field(default_factory=list)
    vt_verdicts: list[VtVerdict] = field(default_factory=list)
    untagged_sets: list[ResultSet] = field(default_factory=list)

    def has_evidence(self) -> bool:
        return bool(self.siem_sets or self.vt_verdicts or self.untagged_sets)


@dataclass
class RoutedEvidence:
    identity: DomainSlice
    network: DomainSlice
    endpoint: DomainSlice

    def slices(self) -> list[DomainSlice]:
        return [self.identity, self.network, self.endpoint]


def _untagged_target_domains(scope: Scope) -> set[AnalystDomain]:
    targets: set[AnalystDomain] = set()
    for kind in scope.kinds():
        targets.update(_ENTITY_KIND_DOMAINS.get(kind, ()))
    # If scope carried only kinds we do not map (none today), fall back to all
    # three rather than silently dropping the rows.
    return targets or {"identity", "network", "endpoint"}


def route(report: BrokerReport, scope: Scope) -> RoutedEvidence:
    """Distribute the report's typed findings across the three domain slices."""
    slices: dict[AnalystDomain, DomainSlice] = {
        "identity": DomainSlice(domain="identity"),
        "network": DomainSlice(domain="network"),
        "endpoint": DomainSlice(domain="endpoint"),
    }
    untagged_targets = _untagged_target_domains(scope)

    for result in report.results:
        findings = result.findings
        if isinstance(findings, SiemFindings):
            for category, domain in _CATEGORY_DOMAIN.items():
                for result_set in getattr(findings, category):
                    slices[domain].siem_sets.append((category, result_set))
            for result_set in findings.uncategorised:
                for domain in untagged_targets:
                    slices[domain].untagged_sets.append(result_set)
        elif isinstance(findings, VtFindings):
            for verdict in findings.verdicts:
                domain = _VT_KIND_DOMAIN.get(verdict.kind)
                if domain is not None:
                    slices[domain].vt_verdicts.append(verdict)
        elif result.evidence:
            # `findings is None` while the subagent DID capture evidence. Today
            # that means edr or ndr: `projection.project()` has projectors for
            # siem and vt only, so an edr subagent can retrieve rows, have them
            # stored as `Evidence`, and contribute nothing to any analyst.
            #
            # Latent while both families are always REJECTED for want of an MCP
            # server -- a rejection captures no evidence, so this branch does not
            # fire -- and live the day a connector lands. Logged rather than
            # raised, and logged rather than passed over silently, because silence
            # is the actual defect: the analysts would simply see less, with
            # nothing anywhere saying so. A projector per family is the fix, and
            # it belongs with the connector that defines the row shape rather
            # than ahead of it.
            logger.warning(
                "task_id=%s | %d evidence item(s) captured with no typed findings to "
                "route; no projector exists for this family, so no analyst will see "
                "them (smartops.projection.project)",
                result.task_id,
                len(result.evidence),
            )
        # findings is None with no evidence: a rejected or errored result. Nothing
        # to route and nothing lost.

    return RoutedEvidence(
        identity=slices["identity"],
        network=slices["network"],
        endpoint=slices["endpoint"],
    )
