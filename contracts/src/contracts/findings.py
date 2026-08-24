"""Per-family payload shapes: what a subagent asserts, and what code assembles.

Two layers, and the split is the point of this module.

`Assessment` is **model-authored** and deliberately small — a judgement about
coverage, not a transcription of data. `Findings` is **code-assembled** from
`Evidence` and holds the rows themselves.

The separation exists because a model forced to emit retrieved rows as structured
output would turn them into *output* tokens against a cumulative
`Limits(output_tokens=)` ceiling, and would admit hallucinated field values into
evidence — which `contracts.subtask.Evidence` already forbids.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

CimCategory = Literal["dns_resolutions", "connections", "processes", "auth_events"]
"""Splunk CIM data-model names, adopted rather than invented.

| category           | CIM data model       |
|--------------------|----------------------|
| `dns_resolutions`  | Network Resolution   |
| `connections`      | Network Traffic      |
| `processes`        | Endpoint -> Processes|
| `auth_events`      | Authentication       |

This inherits a vocabulary analysts already use, a predictable extension path
(Web, Malware, Filesystem, Registry, Intrusion Detection), and a shape that still
holds when EDR arrives -- an EDR process event and a SIEM process event land in
the same model.

*Not* derived from `EntityKind`: the two are orthogonal, not hierarchical. A
`host` yields Authentication *and* Processes *and* Network Traffic.
"""


class ResultSet(BaseModel):
    """Rows returned by one query.

    **Assembled by code**, never authored by a model. `rows` is raw tool output
    passed through untouched -- there is deliberately no per-sourcetype parser,
    because a parser is a second place for field semantics to drift from Splunk's.
    """

    query: str = Field(min_length=1)
    row_count: int = Field(ge=0)
    rows: list[dict[str, Any]] = Field(default_factory=list)


class Assessment(BaseModel):
    """Base for the small, model-authored per-family judgement."""


class Findings(BaseModel):
    """Base for the code-assembled per-family payload."""


class SiemAssessment(Assessment):
    """What the SIEM subagent asserts about its own retrieval.

    No conclusions, no root cause -- those belong to the Analyst. This says what
    was covered and what was not, so the Broker can evaluate completeness without
    reading rows.
    """

    tool_family: Literal["siem"] = Field(
        default="siem",
        description=(
            "Discriminator so `SubtaskResult.assessment` round-trips through JSON as "
            "the right subclass -- a bare `Assessment` annotation has no way to tell "
            "a saved entry was `SiemAssessment` and would silently reconstruct the "
            "empty base class on reload. Named `tool_family` to match the vocabulary "
            "already used on `Evidence.tool_family`, not `kind` (already means "
            "something else on `VtVerdict`)."
        ),
    )
    covered: list[CimCategory] = Field(
        default_factory=list,
        description="Categories this subagent actually retrieved data for.",
    )
    not_covered: list[CimCategory] = Field(
        default_factory=list,
        description=(
            "Categories asked for but not retrieved, including ones that returned "
            "nothing. An empty result is a finding, not a failure."
        ),
    )
    note: str = Field(
        default="",
        max_length=400,
        description=(
            "Optional, capped, and NOT a summary of findings: strictly a remark "
            "about retrieval -- a truncated result set, a sourcetype that did not "
            "exist. Do not describe what the data means."
        ),
    )


class SiemFindings(Findings):
    """Result sets bucketed by CIM category, keyed by the query that produced them.

    The bucket comes from the category the model tagged its own query with
    (`subtask.QueryRun.category`) -- a classification of its own action, which it
    knows without inspecting rows. The rows come from `Evidence`. So no component
    ever retypes data it retrieved.
    """

    tool_family: Literal["siem"] = Field(
        default="siem", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    dns_resolutions: list[ResultSet] = Field(default_factory=list)
    connections: list[ResultSet] = Field(default_factory=list)
    processes: list[ResultSet] = Field(default_factory=list)
    auth_events: list[ResultSet] = Field(default_factory=list)

    uncategorised: list[ResultSet] = Field(
        default_factory=list,
        description=(
            "Result sets whose query the model never tagged with a category. Not "
            "a fifth CIM category -- an honesty bucket. Rows were retrieved and "
            "paid for, so dropping them because attribution failed would be the "
            "worse error, and a full bucket here is a signal that the model's "
            "reported queries stopped matching the ones it actually ran."
        ),
    )

    def total_rows(self) -> int:
        return sum(
            rs.row_count
            for bucket in (
                self.dns_resolutions,
                self.connections,
                self.processes,
                self.auth_events,
                self.uncategorised,
            )
            for rs in bucket
        )


class VtVerdict(BaseModel):
    """One indicator's reputation, projected from the VirusTotal response.

    Mirrors `smartops.tools.native.virustotal.Verdict` minus `raw`, which stays in
    `Evidence` rather than being duplicated into the payload.
    """

    kind: str
    value: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None


class VtAssessment(Assessment):
    """What the VT lookup asserts. Usually produced by the enricher, model-free."""

    tool_family: Literal["vt"] = Field(
        default="vt", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    looked_up: int = Field(default=0, ge=0)
    not_looked_up: list[str] = Field(
        default_factory=list,
        description="Indicators in scope that were not checked, e.g. rate limited.",
    )
    note: str = Field(default="", max_length=400)


class VtFindings(Findings):
    """Verdicts, projected by code from the parsed VirusTotal response."""

    tool_family: Literal["vt"] = Field(
        default="vt", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    verdicts: list[VtVerdict] = Field(default_factory=list)

    def flagged(self) -> list[VtVerdict]:
        return [v for v in self.verdicts if v.malicious > 0 or v.suspicious > 0]


class EdrAssessment(Assessment):
    """What the EDR subagent asserts about host-level process/entity retrieval."""

    tool_family: Literal["edr"] = Field(
        default="edr", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    covered: list[CimCategory] = Field(default_factory=list)
    not_covered: list[CimCategory] = Field(default_factory=list)
    note: str = Field(default="", max_length=400)


class NdrAssessment(Assessment):
    """What the NDR subagent asserts about network telemetry retrieval."""

    tool_family: Literal["ndr"] = Field(
        default="ndr", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    covered: list[CimCategory] = Field(default_factory=list)
    not_covered: list[CimCategory] = Field(default_factory=list)
    note: str = Field(default="", max_length=400)

