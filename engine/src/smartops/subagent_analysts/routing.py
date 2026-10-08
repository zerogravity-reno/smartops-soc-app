"""Split one `BrokerReport` into per-domain evidence slices.

Routing is by CIM category and entity kind, in code -- not a model decision:

- identity  <- auth_events
- network   <- dns_resolutions, connections, and VT verdicts for ip/domain/url
- endpoint  <- processes, and VT verdicts for file_hash

`uncategorised` SIEM result sets (rows whose SPL `projection._infer_cim_category`
recognised no shape in -- an honesty bucket, see `SiemFindings.uncategorised`)
have no known category, so they are routed by the scope's entity kinds and
flagged as untagged. They are never dropped: they were retrieved and paid for.

**`discovery` reaches no slice, and that is deliberate.** It holds output from
calls that describe the estate -- index and sourcetype listings -- rather than
querying it, so there is no hypothesis for an analyst to weigh it against. It
falls out of `route` already, because the loops below name the four CIM buckets
and `uncategorised` explicitly; stated here so a later reader does not add it
back on the "never dropped" reasoning above, which is about *retrieved rows*.
Those listings are kept in `findings.json` for the audit either way.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from contracts import (
    AnalystDomain,
    BrokerReport,
    CimCategory,
    ResultSet,
    Scope,
    SiemFindings,
    ToolFamily,
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
    "file_events": "endpoint",
    "registry_events": "endpoint",
    "script_blocks": "endpoint",
}

# VirusTotal indicator kind -> the analysis domain reputation for it belongs to.
_VT_KIND_DOMAIN: dict[str, AnalystDomain] = {
    "ip": "network",
    "domain": "network",
    "url": "network",
    "file_hash": "endpoint",
}

# Entity kind -> the domain(s) an untagged result set is offered to when its scope
# includes that kind. `user` owns identity; `host`, `process`, `file_hash`, `file_name`,
# `command_line`, `process_id`, `process_guid` own endpoint; `ip`, `domain`, `url` own network.
_ENTITY_KIND_DOMAINS: dict[str, tuple[AnalystDomain, ...]] = {
    "user": ("identity",),
    "host": ("endpoint",),
    "ip": ("network",),
    "domain": ("network",),
    "url": ("network",),
    "file_hash": ("endpoint",),
    "process": ("endpoint",),
    "file_name": ("endpoint",),
    "command_line": ("endpoint",),
    "process_id": ("endpoint",),
    "process_guid": ("endpoint",),
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


_FAMILY_DOMAINS: dict[ToolFamily, tuple[AnalystDomain, ...]] = {
    "edr": ("endpoint",),
    "ndr": ("network",),
    # By indicator kind, matching `_VT_KIND_DOMAIN` above: reputation for an
    # address/domain/URL is network, for a hash it is endpoint.
    "vt": ("network", "endpoint"),
    # SIEM is the general instrument -- it carries auth, DNS, connection and
    # process events, which is precisely why it can stand in for a missing
    # specialist. It is the reason a `not_configured` edr does not leave the
    # endpoint domain empty.
    "siem": ("identity", "network", "endpoint"),
}
"""Which analysis domains a fetch-side family can supply evidence for.

**Read this together with `AnalystDomain`'s "not derived from `ToolFamily`".**
That still holds and this does not contradict it: a domain is not *defined* by a
family, and `route()` below still assigns every result set by CIM category and
entity kind, never by which family fetched it. This mapping answers a different
question, asked from the opposite direction -- *if this family is missing, whose
evidence might be thinner?* -- and it is needed because nothing else in the
codebase could answer it.

It exists for `subagent_analysts.analyze._domain_gaps`, so a
`contracts.DomainGap` can say which domains an unavailable instrument would have
served and which of those ended up with no evidence at all. Without it, a
consumer holding "edr was not configured" and "the endpoint narrative is empty"
has two facts and no stated link between them, and recovering the link requires
knowing what EDR is -- which is exactly the kind of inference
`RetrievalSummary`'s docstring exists to avoid asking of a reader.

Deliberately coarse. It is a statement about what an instrument *could* cover,
not about what any particular query retrieved -- that is what `route()` and the
per-domain findings already report, from the evidence itself.
"""


def domains_for_family(family: ToolFamily) -> tuple[AnalystDomain, ...]:
    """The analysis domains `family` can supply evidence for. See `_FAMILY_DOMAINS`.

    Falls back to all three rather than none for an unmapped family: a new
    `ToolFamily` added without touching this map is far more likely to be
    another broad source than one that serves no analysis domain at all, and
    over-reporting which domains a gap touched is the safer error -- it
    overstates the caveat rather than silently dropping it.
    """
    return _FAMILY_DOMAINS.get(family, ("identity", "network", "endpoint"))


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
    # Retries return the same rows under another query (`summariesonly=t`/`=f`,
    # one index vs a list of them): c7dbf51d's T3 carried its 59 file rows three
    # times. Each copy is a new set to cite and count, so only the first routes.
    # Empty sets all look alike and each says something different, so they stay.
    seen: set[tuple[str, str]] = set()

    def first(category: str, result_set: ResultSet) -> bool:
        if not result_set.rows:
            return True
        key = (category, json.dumps(result_set.rows, sort_keys=True, default=str))
        if key in seen:
            logger.info("task_id=%s | same rows as an earlier %s set, not routed again: %r",
                        report.task_id, category, result_set.query[:200])
            return False
        seen.add(key)
        return True

    for result in report.results:
        findings = result.findings
        if isinstance(findings, SiemFindings):
            for category, domain in _CATEGORY_DOMAIN.items():
                for result_set in getattr(findings, category):
                    if first(category, result_set):
                        slices[domain].siem_sets.append((category, result_set))
            for result_set in findings.uncategorised:
                if first("uncategorised", result_set):
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
