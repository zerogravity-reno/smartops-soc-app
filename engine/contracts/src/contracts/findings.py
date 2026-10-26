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

from typing import Any, Literal, get_args

from pydantic import BaseModel, Field

CimCategory = Literal[
    "dns_resolutions", "connections", "processes", "auth_events",
    "file_events", "registry_events", "script_blocks",
]
"""Splunk CIM data-model names, adopted rather than invented.

| category           | CIM data model       |
|--------------------|----------------------|
| `dns_resolutions`  | Network Resolution   |
| `connections`      | Network Traffic      |
| `processes`        | Endpoint -> Processes|
| `auth_events`      | Authentication       |
| `file_events`      | Endpoint -> Filesystem |
| `registry_events`  | Endpoint -> Registry |
| `script_blocks`    | (none: PowerShell 4104) |

`script_blocks` has no CIM model; it is here because the rows hold what a
PowerShell command actually ran, and on 148b0e69 they reached no analyst.

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
    kind: Literal["events", "count", "aggregate", "unknown"] = Field(
        default="events",
        description=(
            "What the rows are, read from the SPL by code: events, one scalar count "
            "(`stats count`), grouped aggregate rows (`stats count by x`), or unknown. "
            "A count is a count, not a row: only events and unknown fill event quotas "
            "or prove a search empty."
        ),
    )
    truncated: bool = False
    total: int | None = Field(
        default=None, description="Splunk's row total before the cap, when the payload says it."
    )
    evidence_id: str | None = Field(
        default=None,
        description=(
            "The `Evidence.id` this result set's rows were projected from. "
            "Without it a stored citation resolves only to a POSITION in a "
            "recomputed routing (`connections#23` means 'the 23rd connections "
            "set'), so if the routing order ever changes every stored citation "
            "silently re-targets different evidence. Optional because artifacts "
            "written before this field exist and must still load."
        ),
    )


class Assessment(BaseModel):
    """Base for the small, model-authored per-family judgement."""

    note: str = Field(
        default="",
        max_length=2000,
        description=(
            "Optional, capped, and NOT a summary of findings: strictly a remark "
            "about retrieval -- a truncated result set, a sourcetype that did not "
            "exist. Do not describe what the data means."
        ),
    )
    """Declared HERE, once, because it is the same field for every family.

    **2000 characters, not tokens, and nothing reads it.** No code consumes this
    field: it is absent from `broker._digest` (which returns status, rows, query
    count, reason and gaps to the Broker), from every prompt, and from the analyst
    path. It is written by the model, stored in `report.json`, and read by a human
    auditing a run -- so the cap is not protecting anyone's context window, it is
    bounding what a model spends OUTPUT tokens on against its cumulative
    `Limits(output_tokens=)` ceiling.

    Raised from 400 after a vt subagent overran it. That overrun was not evidence
    the cap was wrong -- the model had simply never been shown the description
    below, because three of the four family subclasses used to redeclare this
    field without it. 2000 gives a genuine retrieval remark room ("sourcetype
    stream:dns returned nothing; the index rotated mid-window") while still being
    far too small to invite the summary the description forbids. A limit generous
    enough to hold an analysis would contradict the instruction beside it.

    **Why it is declared here and not per family.** It used to be declared four
    times -- in `SiemAssessment`, `VtAssessment`, `EdrAssessment` and
    `NdrAssessment` -- and only the SIEM copy carried the description. The other
    three were `Field(default="", max_length=400)`: identical in every enforced
    respect, and missing the only part of the field that tells a model what to put
    in it.

    That is not a tidiness point. The vt subagent, shown a bare capped string,
    wrote a 500-character analysis of what the reputation data MEANT and was
    rejected twice by structured-output validation before truncating into the
    limit -- two turns spent on a rule it was never shown, and the rule it broke
    ("NOT a summary of findings") was written down the whole time, on a sibling
    class it did not inherit from.
    """


class Findings(BaseModel):
    """Base for the code-assembled per-family payload."""


class SearchClaim(BaseModel):
    """The siem subagent's claim about one search: does it answer the question?

    Model-authored. Code checks the **attribution** only (B52 C): the search and its
    cited rows exist, sit in a category the step wants, and name its target when it
    has one. Whether the rows mean what the claim says is the Broker's review.
    """

    search: int = Field(ge=1, description="The number on the search's 'search N' line.")
    answers_question: Literal["yes", "no", "absence"] = Field(
        description="yes: rows answer it; absence: a search of the asked category "
        "returned 0 rows and the step has no target values (target absence needs "
        "the Broker's independent code count); no: it does not bear on it.",
    )
    reason: str = Field(max_length=200, description="One line: why.")
    rows: list[int] = Field(
        default_factory=list,
        description="For yes: the row numbers that answer, as the 'search N' line lists them.",
    )


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
    results: list[SearchClaim] = Field(
        default_factory=list,
        description="Per search that bears on the question: whether it answers it. "
        "Claims code could not attribute are dropped.",
    )


class SiemFindings(Findings):
    """Result sets bucketed by CIM category, keyed by the query that produced them.

    **The bucket is derived by code from the SPL** (`projection._infer_cim_category`),
    not from the category the model tagged its own query with. The model's tag is
    kept as a cross-check that logs disagreement. The rows come from `Evidence`.
    So no component ever retypes data it retrieved.

    That precedence was the other way around until 2026-09-02, on the reasoning
    that classifying its own action is something a model knows without inspecting
    rows. Measured on the first 3-hypothesis task-file run, it does not survive
    contact: `subtask.QueryRun` is a *post-hoc recollection*, and of 66 result
    sets whose tag was lost, only 4 came within 85% similarity of any query the
    model reported -- it reports fewer queries than it ran and retypes the ones it
    does report. The join key was never reliable, so the tag it carried could not
    be either.
    """

    tool_family: Literal["siem"] = Field(
        default="siem", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    dns_resolutions: list[ResultSet] = Field(default_factory=list)
    connections: list[ResultSet] = Field(default_factory=list)
    processes: list[ResultSet] = Field(default_factory=list)
    auth_events: list[ResultSet] = Field(default_factory=list)
    file_events: list[ResultSet] = Field(default_factory=list)
    registry_events: list[ResultSet] = Field(default_factory=list)
    script_blocks: list[ResultSet] = Field(default_factory=list)

    uncategorised: list[ResultSet] = Field(
        default_factory=list,
        description=(
            "Result sets whose query code could infer no CIM category from. Not "
            "a fifth CIM category -- an honesty bucket. Rows were retrieved and "
            "paid for, so dropping them because attribution failed would be the "
            "worse error, and a full bucket here is a signal that queries are "
            "being written in shapes `_infer_cim_category` does not recognise."
        ),
    )

    discovery: list[ResultSet] = Field(
        default_factory=list,
        description=(
            "Output from a call that DESCRIBES the estate rather than querying "
            "it -- an index listing, a sourcetype listing, a metadata lookup. "
            "The model orienting itself, not evidence about any hypothesis, so "
            "it is never routed to an analyst and never satisfies a fetch step. "
            "Kept rather than dropped because it was retrieved and paid for and "
            "belongs in the audit trail.\n\n"
            "Separated on 2026-09-02 after measurement: 15 such calls produced "
            "1,186 of the run's 1,695 `uncategorised` rows -- 70% -- and were "
            "the direct source of the padding in the delivered payload, which "
            "narrated Splunk's own `_internal` index and hosts nobody had asked "
            "about. They can never be categorised either: they carry no search "
            "for `_infer_cim_category` to read."
        ),
    )

    def total_rows(self) -> int:
        """Rows retrieved *about the estate*. Deliberately excludes `discovery`.

        An index listing's rows describe what Splunk holds, not what happened on
        a host, so counting them here would report retrieval that did not occur.
        Nor a count or aggregate: a `{count: 0}` row is Splunk saying "none".
        """
        return sum(
            rs.row_count
            for bucket in (*get_args(CimCategory), "uncategorised")
            for rs in getattr(self, bucket)
            if rs.kind in ("events", "unknown")
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
    evidence_id: str | None = Field(
        default=None,
        description=(
            "The `Evidence.id` this verdict was projected from. See "
            "`ResultSet.evidence_id`."
        ),
    )


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


class NdrAssessment(Assessment):
    """What the NDR subagent asserts about network telemetry retrieval."""

    tool_family: Literal["ndr"] = Field(
        default="ndr", description="Discriminator, see `SiemAssessment.tool_family`."
    )
    covered: list[CimCategory] = Field(default_factory=list)
    not_covered: list[CimCategory] = Field(default_factory=list)

