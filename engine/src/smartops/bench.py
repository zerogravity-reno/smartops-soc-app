"""`smartops-bench`: runs the Task Broker over benchmark cases and records what it cost.

Originally an A/B runner comparing the hierarchical Broker (Arm S) against a flat
baseline (Arm F). The flat baseline was dropped in favour of the subagent design,
so this is now a single-topology measurement harness: N runs per case, median and
spread across them.

The cross-arm comparison machinery went with Arm F, and that retired two defects
rather than fixing them. `routing_correctness` was comparing two different
quantities -- Arm S recorded dispatch INTENT while Arm F recorded REALISED work --
and the significance rule was a hardcoded threshold that called a one-millisecond
delta "statistically significant". Neither has a second arm to be wrong about now.

Collects per run:
- Wall-clock duration
- Total cost & cost by role (`Budget.spend_by_role()`)
- Input / output tokens, and cache read/write tokens (`accumulated_usage`)
- Model calls (ledger entries -- see `RunMetrics.model_calls`, which is NOT turns)
- Queries run count
- Index scoping correctness (allowlist check, scored independently of the guard)
- Findings completeness (row counts per category)
- Routing correctness (`dispatched` vs expected families)
- Failure mode (`stop_reason`)

Supports offline dry-runs with --scripted / --mock, which cost nothing and call no
model. A report whose `scripted` is true measured the plumbing, not the system.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

from contracts.findings import CimCategory, SiemFindings, VtFindings
from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel

from contracts import AnalystDomain, AnalystTask, Entity, Scope, SubtaskResult, ToolFamily
from smartops.broker import broker_task
from smartops.budget import Budget, ModelChoice, model_choice_from_env
from smartops.domains import spec_for
from smartops.main import _PLACEHOLDER_MODEL, _scripted_invoker
from smartops.skills import SKILLS_ENABLED_ENV_VAR, pinned_skills_enabled, skills_enabled
from smartops.subagents import domain_runner
from smartops.tools.registry import load_mcp_servers, warm_mcp_clients

logger = logging.getLogger(__name__)


# The benchmark's own answer to "was the skill pack in play?", pinned rather than
# inherited. A stray `SMARTOPS_SKILLS_ENABLED=1` in a shell would otherwise hand
# the siem subagent a routing table and an extra tool, and every cost and token
# figure the run reports would silently be measuring that configuration instead
# of the default one -- with nothing in the artifact to say so.
BENCH_SKILLS_ENABLED = False


DEFAULT_BOTSV3_TASK = AnalystTask(
    task_id="botsv3_coinhive",
    hypothesis_id="coinhive-cryptomining",
    goal="Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?",
    scope=Scope(
        entities=[
            Entity(kind="domain", value="coinhive.com"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

# hdoor.exe (BOTSv3 Q307), a network scanner/backdoor -- not PowerShell. The
# original task pointed at a hash absent from BOTSv3 (VT NOT FOUND); renamed
# from BOTSV3_POWERSHELL_TASK along with the case, per R8.
BOTSV3_HDOOR_TASK = AnalystTask(
    task_id="botsv3_hdoor_tool",
    hypothesis_id="hdoor-backdoor-tool",
    goal="Investigate suspected attack tool (network scanner/backdoor) file hash 586EF56F4D8963DD546163AC31C865D7 reputation on VirusTotal and SIEM activity on host BSTOLL-L.",
    scope=Scope(
        entities=[
            Entity(kind="file_hash", value="586EF56F4D8963DD546163AC31C865D7"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

# C2 at 45.77.53.176 (BOTSv3 Q322). BOTSv3 Q323 documents ABUNGST-L and
# FYODOR-L -- not BSTOLL-L -- as the endpoints that contacted C2
# infrastructure, so the host changed along with the IP: keeping BSTOLL-L
# would correctly retrieve nothing and look like an analyst failure rather
# than a correctly-scoped negative.
BOTSV3_C2_IP_TASK = AnalystTask(
    task_id="botsv3_c2_beacon",
    hypothesis_id="c2-beacon-outbound",
    goal="Is external IP 45.77.53.176 known-malicious, and what network connections did host ABUNGST-L make to it?",
    scope=Scope(
        entities=[
            Entity(kind="ip", value="45.77.53.176"),
            Entity(kind="host", value="ABUNGST-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_WEB_SHELL_TASK = AnalystTask(
    task_id="botsv3_web_shell_url",
    hypothesis_id="web-shell-uri-access",
    goal="Is URL http://po18-s92-l01/swm/upload/shell.php known-malicious, and what web server logs exist for host po18-s92-l01?",
    scope=Scope(
        entities=[
            Entity(kind="url", value="http://po18-s92-l01/swm/upload/shell.php"),
            Entity(kind="host", value="po18-s92-l01"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_DNS_TUNNELING_TASK = AnalystTask(
    task_id="botsv3_dns_tunneling",
    hypothesis_id="dns-tunneling-query",
    goal="Is domain a1b2c3.tunnel.malicious.net known-malicious, and what DNS resolutions occurred for host BSTOLL-L?",
    scope=Scope(
        entities=[
            Entity(kind="domain", value="a1b2c3.tunnel.malicious.net"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_MIMIKATZ_TASK = AnalystTask(
    task_id="botsv3_mimikatz_hash",
    hypothesis_id="mimikatz-lsass-dumper",
    goal="Investigate LSASS dumper file hash 31d6cfe0d16ae931b73c59d7e0c089c0 reputation on VirusTotal and endpoint process logs on host BSTOLL-L.",
    scope=Scope(
        entities=[
            Entity(kind="file_hash", value="31d6cfe0d16ae931b73c59d7e0c089c0"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_PHISHING_TASK = AnalystTask(
    task_id="botsv3_phishing_domain",
    hypothesis_id="phishing-domain-credential-harvest",
    goal="Is domain secure-login-account.com known-malicious, and did host BSTOLL-L access it?",
    scope=Scope(
        entities=[
            Entity(kind="domain", value="secure-login-account.com"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_EXFIL_IP_TASK = AnalystTask(
    task_id="botsv3_exfil_ip",
    hypothesis_id="data-exfiltration-ip",
    goal="Is external IP 104.20.208.59 known-malicious, and what volume of network traffic was sent to it by host BSTOLL-L?",
    scope=Scope(
        entities=[
            Entity(kind="ip", value="104.20.208.59"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_RANSOMWARE_TASK = AnalystTask(
    task_id="botsv3_ransomware_note",
    hypothesis_id="ransomware-note-hash",
    goal="Check VirusTotal reputation for ransomware payload hash 8f4e2b109156a297e68c123456789abc and search endpoint file logs on host BSTOLL-L.",
    scope=Scope(
        entities=[
            Entity(kind="file_hash", value="8f4e2b109156a297e68c123456789abc"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_USER_AUTH_TASK = AnalystTask(
    task_id="botsv3_suspicious_user_auth",
    hypothesis_id="suspicious-user-authentication",
    goal="Investigate authentication logs for user account bostoll on host BSTOLL-L.",
    scope=Scope(
        entities=[
            Entity(kind="user", value="bostoll"),
            Entity(kind="host", value="BSTOLL-L"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BOTSV3_HARD_MULTI_VECTOR_TASK = AnalystTask(
    task_id="botsv3_hard_multivector",
    hypothesis_id="multivector-compromise-bstoll",
    goal="Investigate full-spectrum compromise on host BSTOLL-L involving user bostoll: check VirusTotal reputation for domain coinhive.com, C2 IP 217.182.164.14, and powershell payload hash e2ac36894c2560d2b277ff9618b76c8c. Correlate user authentication logs, network connections, and endpoint process executions in SIEM index botsv3.",
    scope=Scope(
        entities=[
            Entity(kind="user", value="bostoll"),
            Entity(kind="host", value="BSTOLL-L"),
            Entity(kind="domain", value="coinhive.com"),
            Entity(kind="ip", value="217.182.164.14"),
            Entity(kind="file_hash", value="e2ac36894c2560d2b277ff9618b76c8c"),
        ],
        time_window=(
            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
        ),
    ),
)

BENCHMARK_CASES: dict[str, tuple[AnalystTask, list[ToolFamily]]] = {
    "botsv3_coinhive": (DEFAULT_BOTSV3_TASK, ["siem", "vt"]),
    "botsv3_hdoor_tool": (BOTSV3_HDOOR_TASK, ["siem", "vt"]),
    "botsv3_c2_beacon": (BOTSV3_C2_IP_TASK, ["siem", "vt"]),
    "botsv3_web_shell_url": (BOTSV3_WEB_SHELL_TASK, ["siem", "vt"]),
    "botsv3_dns_tunneling": (BOTSV3_DNS_TUNNELING_TASK, ["siem", "vt"]),
    "botsv3_mimikatz_hash": (BOTSV3_MIMIKATZ_TASK, ["siem", "vt"]),
    "botsv3_phishing_domain": (BOTSV3_PHISHING_TASK, ["siem", "vt"]),
    "botsv3_exfil_ip": (BOTSV3_EXFIL_IP_TASK, ["siem", "vt"]),
    "botsv3_ransomware_note": (BOTSV3_RANSOMWARE_TASK, ["siem", "vt"]),
    "botsv3_suspicious_user_auth": (BOTSV3_USER_AUTH_TASK, ["siem"]),
    "botsv3_hard_multivector": (BOTSV3_HARD_MULTI_VECTOR_TASK, ["siem", "vt"]),
}


EXPECTED_CITATIONS: dict[str, dict[AnalystDomain, tuple[str, ...]]] = {
    "botsv3_coinhive": {
        # BSTOLL-L is the endpoint mining Monero (BOTSv3 Q210); chrome#5 was
        # the process at 100% CPU (Q208); six coinhive destinations were
        # visited, over coinhive.com plus ws001/ws005/ws011/ws014/
        # ws019.coinhive.com; Symantec fired JSCoinminer Download 8 (SID
        # 30358). network: the DNS queries plus VT mal=11 on the domain
        # are what the narrative must have cited to have seen this.
        #
        # network ONLY. A live run of this exact scope on 2026-08-30
        # retrieved 46 dns_resolutions rows and 124 connections rows and
        # zero process rows -- the Broker planned siem-dns and
        # siem-connections and no process step, because the case's entities
        # are a domain and a host and its goal asks what the host did WITH
        # the domain. An endpoint expectation would not be reliably
        # elicited by this case, and scoring it would penalise the analyst
        # for evidence the plan never asked for. chrome#5 at 100% CPU is
        # real and documented (Q208) but belongs to a different case,
        # scoped to elicit process evidence -- out of scope here.
        #
        # No identity entry either -- BOTSv3 documents no authentication
        # anomaly for this activity, and asserting one would be inventing
        # an answer.
        "network": ("dns_resolutions",),
    },
    "botsv3_c2_beacon": {
        # C2 at 45.77.53.176 / 45.77.65.211, URL paths /admin/get.php,
        # /news.php, /login/process.php (Q322) -- a `connections` row is
        # what shows the host talking to the C2, not a DNS lookup of it.
        "network": ("connections",),
    },
    "botsv3_hdoor_tool": {
        # MD5 586EF56F4D8963DD546163AC31C865D7 is hdoor.exe (Q307), a
        # network scanner/backdoor, downloaded over port 3333 inside
        # logos.png (Q314, Q316). Either the VT reputation lookup on the
        # hash or a process row for hdoor.exe running on the host proves
        # the narrative saw it -- see the disjunction note below.
        "endpoint": ("reputation", "processes"),
    },
}
"""The BOTSv3 answer key: per case and per domain, which evidence category the
narrative must cite to have seen the row that establishes the documented fact.

Each value is a tuple of citation categories, matched against the prefix of a
citation header id before its `#` (e.g. `dns_resolutions#1` ->
`dns_resolutions`). A tuple is a DISJUNCTION, not a conjunction: ANY ONE of the
listed categories appearing among the domain's citations is a match, not all
of them. `botsv3_hdoor_tool` lists `("reputation", "processes")` because
either the VT lookup on the hash or a process listing on the host sees the row
that proves hdoor.exe was there -- citing both is not required, and scoring it
as if it were would penalise a narrative for reaching the same fact through a
different, equally valid, evidence set. A single-element tuple states the only
qualifying category for that domain.

Sparse and deliberately so: a case absent here has no documented answer in
BOTSv3, which is the honest state for most of `BENCHMARK_CASES` -- see
`SYNTHETIC_INDICATOR_CASES` for the ones built on indicators the dataset does
not contain. Per-domain rather than one entry per case (R6): `HypothesisFindings`
has no overall verdict -- deciding across domains is the Analyst Agent's job,
and `combine()` was deleted for crossing that line. A domain missing from a
case's entry (e.g. no `identity` for `botsv3_coinhive`) is not "expected no
citation" -- it means BOTSv3 documents no answer for that domain, and
asserting one would be inventing it.
"""


SYNTHETIC_INDICATOR_CASES = frozenset({
    "botsv3_web_shell_url",
    "botsv3_dns_tunneling",
    "botsv3_mimikatz_hash",
    "botsv3_ransomware_note",
    "botsv3_exfil_ip",
    "botsv3_phishing_domain",
    "botsv3_hard_multivector",
})
"""Cases whose indicators BOTSv3 does not contain, kept for coverage anyway.

They still earn their place -- they exercise the empty-result path and keep
entity-kind routing coverage (`url` and `file_hash` have no other case) -- but
none of them has a documented answer, so none appears in
`EXPECTED_CITATIONS`. What is actually wrong, per case:

- `botsv3_web_shell_url` -- host `po18-s92-l01` and the `shell.php` URL appear
  nowhere in BOTSv3; VT NOT FOUND.
- `botsv3_dns_tunneling` -- `a1b2c3.tunnel.malicious.net` is a placeholder
  (`a1`/`b2`/`c3` sequential) and does not resolve. BOTSv3's DNS finding is a
  statistic -- average third-level subdomain length 8.10 on `brewertalk.com`
  (Q224) -- which is not a disposition, so there is nothing to expect here.
- `botsv3_mimikatz_hash` -- MISLABELLED, not merely synthetic.
  `31d6cfe0d16ae931b73c59d7e0c089c0` is the NTLM hash of an empty password. It
  is not Mimikatz, not malware, and not a file hash in the sense the case
  name claims. A correct system returns `inconclusive`; the case name says it
  should find a credential dumper.
- `botsv3_ransomware_note` -- `8f4e2b109156a297e68c123456789abc` is a
  placeholder (sequential hex tail `123456789abc`). BOTSv3 has no ransomware
  component at all.
- `botsv3_exfil_ip` -- `104.20.208.59` is Cloudflare (AS13335). BOTSv3 shows
  `104.20.209.59` -- one digit different -- as a DNS response for
  coinhive.com, not an exfil destination. BOTSv3's actual exfiltration is via
  S3, which is out of scope per R2.
- `botsv3_phishing_domain` -- not in BOTSv3, but the domain is real: our own
  saved VT lookup has `secure-login-account.com` at `mal=14`. VT-only case;
  expect no SIEM rows.
- `botsv3_hard_multivector` -- only ONE of its three reputation indicators is
  the problem: the file hash `e2ac36894c2560d2b277ff9618b76c8c` is absent from
  BOTSv3 (VT NOT FOUND). The domain `coinhive.com` and the IP
  `217.182.164.14` are both genuine BOTSv3 data. Repointing the hash is a
  scope decision left to the controller, not made here; this case stays out
  of `EXPECTED_CITATIONS` because a fabricated indicator sits alongside two
  real ones and no single citation expectation can be asserted for the case
  as a whole.
"""


class RunMetrics(BaseModel):
    """Metrics captured for a single benchmark run."""

    arm: str  # "S" -- the only topology, kept so older reports stay readable
    case_id: str
    run_index: int
    wall_clock_seconds: float
    total_cost_micro_usd: int
    cost_by_role: dict[str, int]
    input_tokens: int
    output_tokens: int
    cache_read_input_tokens: int = 0
    """Prefix tokens billed at the cache-read rate rather than full input price.

    The only observable proof that prompt caching is actually engaged: the cache
    point is silently ignored below the provider's minimum cacheable prefix, so
    a run that fails to cache looks completely normal apart from this being 0.
    """
    cache_creation_input_tokens: int = 0
    """Prefix tokens written to the cache, billed at ~1.25x input price."""
    model_calls: int
    """Settled entries in the budget ledger -- one per billed model call.

    Named for what it counts. It was `sequential_turns` until it was checked
    against the ledger, and it has never measured turns: a run whose Broker,
    siem subagent and vt lookup each billed once reports 3 regardless of how
    many turns any of them took.
    """
    queries_run_count: int
    index_scoping_correct: bool
    findings_completeness: dict[str, int]
    routing_correctness: bool
    citation_coverage_correct: bool | None = None
    """Whether each domain's citations covered at least one category from its
    entry in `EXPECTED_CITATIONS`. Renamed from `disposition_correct`
    (2026-08-31): the sub-analysts no longer emit a `Disposition` to compare --
    they translate rows into a narrative and cite the sets it rests on -- so
    the question this field answers moved from "did the verdict match" to "did
    the narrative cite the row that proves the documented fact".

    Three states, not two. `None` covers both "no answer key for this case"
    (absent from `EXPECTED_CITATIONS`) and "no findings to score at all" (no
    `SMARTOPS_ANALYST_MODEL_ARN`, or `--scripted`) -- the same
    no-answer-vs-wrong-answer distinction `StepOutcome.evaluated` and
    `RetrievalSummary` exist to preserve elsewhere in this codebase. Only a
    genuine miss, on a domain the case DOES have a documented answer for, is
    `False`. Always `None` today: `_execute_single_run` calls only
    `broker_task`, never `smartops.subagent_analysts.analyze`, so no
    per-domain findings ever reach this scope to compare -- see
    `compute_citation_coverage`.

    That "always `None` today" is not evidence this field is dead. Rescoping
    it from a `Disposition` comparison to a citation-category comparison is
    precisely what makes it scoreable WITHOUT a model verdict, the moment
    something wires the analyst tier into this bench -- a decision left to the
    controller, not made here (see the 2026-08-30 benchmark answer-sheet
    report). Deleting this field for being permanently `None` would delete
    that plan along with it.
    """
    stop_reason: str
    dispatched: list[str]
    skills_enabled: bool = False
    """Whether the skill pack was live *for this run*, read at execution time.

    Recorded per run, not only per report: a run whose configuration is not in
    its own record cannot be compared against a later one.
    """


class MetricStats(BaseModel):
    """Statistical summary (median and spread) for a single metric."""

    median: float
    min: float
    max: float
    spread: float


class ArmSummary(BaseModel):
    """Median and spread across the runs of one arm."""

    arm: str
    runs_count: int
    wall_clock_seconds: MetricStats
    total_cost_micro_usd: MetricStats
    input_tokens: MetricStats
    output_tokens: MetricStats
    cache_read_input_tokens: MetricStats
    model_calls: MetricStats
    queries_run_count: MetricStats
    total_findings_rows: MetricStats
    index_scoping_correct_pct: float
    routing_correctness_pct: float
    stop_reasons: dict[str, int]
    cost_by_role_median: dict[str, float]


class BenchmarkReport(BaseModel):
    """Complete benchmark execution report."""

    timestamp: str
    cases: list[str]
    arms: list[str]
    runs_per_arm: int
    scripted: bool
    skills_enabled: bool = False
    """The skill-pack setting this benchmark pinned onto *every* arm."""
    raw_runs: list[RunMetrics]
    arm_summaries: dict[str, ArmSummary]

    def to_markdown(self) -> str:
        lines: list[str] = [
            "# Benchmark Report — SmartOps SOC",
            "",
            f"- **Timestamp:** {self.timestamp}",
            f"- **Cases:** {', '.join(self.cases)}",
            f"- **Runs per case:** {self.runs_per_arm}",
            f"- **Scripted Mode:** {self.scripted}",
            f"- **Skill Pack ({SKILLS_ENABLED_ENV_VAR}):** {self.skills_enabled}",
            "",
            "## Summary",
            "",
            "| Metric | Median (min - max) |",
            "|---|---|",
        ]

        def _fmt_arm(arm: str, attr: str, fmt: str = ".2f") -> str:
            if arm not in self.arm_summaries:
                return "N/A"
            stats = getattr(self.arm_summaries[arm], attr, None)
            if stats is None:
                return "N/A"
            if isinstance(stats, MetricStats):
                return f"{stats.median:{fmt}} ({stats.min:{fmt}} - {stats.max:{fmt}})"
            return str(stats)

        def _fmt_pct(arm: str, attr: str) -> str:
            if arm not in self.arm_summaries:
                return "N/A"
            val = getattr(self.arm_summaries[arm], attr, None)
            return f"{val:.1f}%" if val is not None else "N/A"

        rows = [
            ("Wall clock (s)", "wall_clock_seconds", ".3f"),
            ("Total Cost (micro-USD)", "total_cost_micro_usd", ".0f"),
            ("Input Tokens (uncached)", "input_tokens", ".0f"),
            ("Cache Read Tokens", "cache_read_input_tokens", ".0f"),
            ("Output Tokens", "output_tokens", ".0f"),
            ("Model Calls", "model_calls", ".0f"),
            ("Queries Run", "queries_run_count", ".0f"),
            ("Findings Rows", "total_findings_rows", ".0f"),
        ]

        for label, attr, fmt in rows:
            lines.append(f"| {label} | {_fmt_arm('S', attr, fmt)} |")

        lines.append(
            f"| Index Scoping (% correct) | {_fmt_pct('S', 'index_scoping_correct_pct')} |"
        )
        lines.append(
            f"| Routing Correctness (% correct) | {_fmt_pct('S', 'routing_correctness_pct')} |"
        )

        lines.extend(["", "## Failure Modes", ""])
        for arm in self.arms:
            if arm in self.arm_summaries:
                reasons = self.arm_summaries[arm].stop_reasons
                reasons_str = ", ".join(f"{k}: {v}" for k, v in reasons.items()) or "(none)"
                lines.append(f"- **Arm {arm}:** {reasons_str}")

        lines.extend(["", "## Cost by Role (Median micro-USD)", ""])
        for arm in self.arms:
            if arm in self.arm_summaries:
                role_costs = self.arm_summaries[arm].cost_by_role_median
                role_str = ", ".join(f"{k}: {v:.0f}" for k, v in role_costs.items()) or "(none)"
                lines.append(f"- **Arm {arm}:** {role_str}")

        return "\n".join(lines)


_WILDCARD_INDEX = re.compile(r"\bindex\s*=\s*[\"']?\*", re.IGNORECASE)
_INDEX_TERM = re.compile(r"\bindex\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s()|,]+)", re.IGNORECASE)
_CIM_PREDICATE = re.compile(r"\b(sourcetype|datamodel|tag|eventtype)\s*=", re.IGNORECASE)


def _query_is_scoped(query: str, allowed: frozenset[str]) -> bool:
    """Whether one query stayed inside its allowlist.

    Scoped means: every index it names is allowlisted and none is a wildcard;
    or it names no index and scopes itself with a CIM predicate instead.
    """
    if _WILDCARD_INDEX.search(query):
        return False

    named = [m.group(1).strip("\"'").lower() for m in _INDEX_TERM.finditer(query)]
    if named:
        return all(name in allowed for name in named)

    return bool(_CIM_PREDICATE.search(query))


def check_index_scoping(results: list[SubtaskResult]) -> bool:
    """Whether every query a subagent *attempted* stayed inside its allowlist.

    Two things about this are deliberate, because the previous version got both
    wrong and reported 100% regardless.

    **It scores attempts, not successes.** `queries_run` holds only queries that
    already passed `IndexScopeGuard`; a query the guard cancelled produces an
    error tool result, which `_EvidenceCollector` drops. Scoring `queries_run`
    alone therefore measured a set the guard had already filtered, and could not
    fail -- while its entire reason for existing is the 2026-08-11 run in which
    every SPL was `index=*`. Now that a guard blocks those, `blocked_queries` is
    what keeps the attempt visible, and it counts here.

    **It does not consult the guard.** This used to call
    `IndexScopeGuard._reject_reason` directly, which made the measurement a
    restatement of the control rather than a check on it: relaxing the guard
    moved the metric with it, silently. The rule below is implemented here so
    the two can disagree, which is the only condition under which measuring is
    worth anything.
    """
    for res in results:
        attempted = [q.query for q in res.queries_run] + list(res.blocked_queries)
        if not attempted:
            continue

        family = res.task_id.split(":")[1] if ":" in res.task_id else "siem"
        try:
            allowlist = spec_for(family).index_allowlist  # type: ignore[arg-type]
        except KeyError:
            allowlist = ("botsv3",)
        if allowlist is None:
            continue

        allowed = frozenset(name.strip().lower() for name in allowlist)
        if not all(_query_is_scoped(query, allowed) for query in attempted):
            return False
    return True


def extract_findings_completeness(results: list[SubtaskResult]) -> dict[str, int]:
    """Extract category row counts from subtask result findings."""
    counts: dict[str, int] = {
        "dns_resolutions": 0,
        "connections": 0,
        "processes": 0,
        "auth_events": 0,
        "uncategorised": 0,
        "vt_verdicts": 0,
    }

    for res in results:
        if res.findings is not None:
            if isinstance(res.findings, SiemFindings):
                for bucket in (*get_args(CimCategory), "uncategorised"):
                    counts[bucket] = counts.get(bucket, 0) + sum(rs.row_count for rs in getattr(res.findings, bucket))
            elif isinstance(res.findings, VtFindings):
                counts["vt_verdicts"] += len(res.findings.verdicts)
    return counts


def compute_citation_coverage(
    case_id: str,
    findings: dict[AnalystDomain, list[str]] | None,
) -> bool | None:
    """Whether `findings` cites, per domain, at least one category required by
    the case's entry in `EXPECTED_CITATIONS`.

    `findings` maps each domain to the citation header ids its narrative used
    (e.g. `["dns_resolutions#1", "reputation#1"]`); only the prefix before `#`
    is compared against the required categories. A domain's requirement is a
    tuple -- see `EXPECTED_CITATIONS` for why it is a disjunction, not a
    checklist: any one listed category appearing among the domain's citations
    satisfies it.

    Only the domains present in the case's expectation are compared -- a
    domain `EXPECTED_CITATIONS` says nothing about is not scored, silence is
    not a wrong answer. Returns `None`, never `False`, in either of two
    distinct no-basis-to-score states: the case has no documented answer at
    all (absent from `EXPECTED_CITATIONS`), or no findings were produced for
    this run (`findings is None`). Collapsing those into `False` would read as
    "the analyst got it wrong" when the truth is "we have no answer key" or
    "nobody looked" -- see `RunMetrics.citation_coverage_correct`.
    """
    expected = EXPECTED_CITATIONS.get(case_id)
    if expected is None or findings is None:
        return None

    def _cited_categories(citations: list[str]) -> set[str]:
        return {citation.split("#", 1)[0] for citation in citations}

    return all(
        bool(_cited_categories(findings.get(domain, [])) & set(required))
        for domain, required in expected.items()
    )


async def _execute_single_run(
    task: AnalystTask,
    arm: str,
    run_index: int,
    expected_families: list[ToolFamily],
    *,
    model: ModelChoice,
    budget_usd: float = 1.0,
    scripted: bool = False,
    families: list[ToolFamily] | None = None,
) -> RunMetrics:
    budget = Budget.from_usd(budget_usd)
    target_families = list(families) if families is not None else list(expected_families)

    t0 = time.perf_counter()
    stop_reason = "end_turn"

    if scripted:
        invoke = _scripted_invoker(target_families)
    else:
        invoke = None

    if arm == "S":
        # Arm S's whole claim is that a dedicated subagent executes the step, so
        # the bench has to hand `broker_task` a real one. `run_subagent=None`
        # stood here until now, which `_dispatch()` resolves to
        # `broker._stub_subagent` -- a stand-in that calls no model and executes
        # no tool, returning NO_DATA with a tool count. Every family except `vt`
        # (the only one carrying a model-free enricher) therefore retrieved
        # NOTHING, while Arm F ran a real per-step model loop against live tools.
        # The A/B was comparing a real arm against a hollow one, and siem -- the
        # domain the case is about -- was the emptiest of them.
        #
        # Scripted runs keep the stub deliberately: `--scripted` exists to
        # exercise the plumbing without a provider, and `_stub_subagent` is what
        # makes that possible (its `vt` enricher still returns real evidence).
        outcome = await broker_task(
            task,
            budget,
            model=model,
            invoke=invoke,
            run_subagent=None if scripted else domain_runner(model=model, budget=budget),
        )
    else:
        raise ValueError(f"Unknown arm: {arm!r}")

    wall_clock = time.perf_counter() - t0

    cost_by_role = budget.spend_by_role()
    total_cost = sum(cost_by_role.values())

    input_tokens = sum(entry.usage.input_tokens for entry in budget.ledger)
    output_tokens = sum(entry.usage.output_tokens for entry in budget.ledger)
    cache_reads = sum(entry.usage.cache_read_input_tokens for entry in budget.ledger)
    cache_writes = sum(entry.usage.cache_creation_input_tokens for entry in budget.ledger)
    calls = len(budget.ledger)

    queries_count = sum(len(res.queries_run) for res in outcome.results if res.queries_run)
    scoping_correct = check_index_scoping(outcome.results)
    findings_map = extract_findings_completeness(outcome.results)
    routing_correct = set(outcome.dispatched) == set(expected_families)
    # No `HypothesisFindings` reaches this scope: this function calls only
    # `broker_task`, never `smartops.subagent_analysts.analyze`, so there is
    # nothing here to compare against `EXPECTED_CITATIONS` yet. Wiring the
    # analyst step into the bench so a real comparison can happen is a design
    # decision left to the controller, not made here.
    citation_coverage_correct = compute_citation_coverage(task.task_id, None)

    if outcome.classification and outcome.classification.rationale:
        if "stop_reason=" in outcome.classification.rationale:
            stop_reason = outcome.classification.rationale.split("stop_reason=")[1].split(")")[0]
        elif scripted:
            stop_reason = "scripted"

    return RunMetrics(
        arm=arm,
        case_id=task.task_id,
        run_index=run_index,
        wall_clock_seconds=round(wall_clock, 4),
        total_cost_micro_usd=total_cost,
        cost_by_role=cost_by_role,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_input_tokens=cache_reads,
        cache_creation_input_tokens=cache_writes,
        model_calls=calls,
        queries_run_count=queries_count,
        index_scoping_correct=scoping_correct,
        findings_completeness=findings_map,
        routing_correctness=routing_correct,
        citation_coverage_correct=citation_coverage_correct,
        stop_reason=stop_reason,
        dispatched=[str(d) for d in outcome.dispatched],
        skills_enabled=skills_enabled(),
    )


def compute_metric_stats(vals: Sequence[float]) -> MetricStats:
    """Compute median, min, max, and spread for a list of values."""
    if not vals:
        return MetricStats(median=0.0, min=0.0, max=0.0, spread=0.0)
    s = sorted(vals)
    n = len(s)
    median = s[n // 2] if n % 2 != 0 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    min_val = s[0]
    max_val = s[-1]
    spread = max_val - min_val
    return MetricStats(median=float(median), min=float(min_val), max=float(max_val), spread=float(spread))


def compute_arm_summary(arm: str, runs: list[RunMetrics]) -> ArmSummary:
    """Compute ArmSummary containing median and spread for all metrics across runs."""
    wall_clocks = [r.wall_clock_seconds for r in runs]
    costs = [float(r.total_cost_micro_usd) for r in runs]
    inputs = [float(r.input_tokens) for r in runs]
    outputs = [float(r.output_tokens) for r in runs]
    cache_reads = [float(r.cache_read_input_tokens) for r in runs]
    calls = [float(r.model_calls) for r in runs]
    queries = [float(r.queries_run_count) for r in runs]
    total_rows = [float(sum(r.findings_completeness.values())) for r in runs]

    index_pct = (sum(1 for r in runs if r.index_scoping_correct) / len(runs)) * 100.0 if runs else 0.0
    routing_pct = (sum(1 for r in runs if r.routing_correctness) / len(runs)) * 100.0 if runs else 0.0

    stop_reasons: dict[str, int] = {}
    for r in runs:
        stop_reasons[r.stop_reason] = stop_reasons.get(r.stop_reason, 0) + 1

    all_roles: set[str] = set()
    for r in runs:
        all_roles.update(r.cost_by_role.keys())

    cost_by_role_median: dict[str, float] = {}
    for role in all_roles:
        role_vals = [float(r.cost_by_role.get(role, 0)) for r in runs]
        cost_by_role_median[role] = compute_metric_stats(role_vals).median

    return ArmSummary(
        arm=arm,
        runs_count=len(runs),
        wall_clock_seconds=compute_metric_stats(wall_clocks),
        total_cost_micro_usd=compute_metric_stats(costs),
        input_tokens=compute_metric_stats(inputs),
        output_tokens=compute_metric_stats(outputs),
        cache_read_input_tokens=compute_metric_stats(cache_reads),
        model_calls=compute_metric_stats(calls),
        queries_run_count=compute_metric_stats(queries),
        total_findings_rows=compute_metric_stats(total_rows),
        index_scoping_correct_pct=round(index_pct, 1),
        routing_correctness_pct=round(routing_pct, 1),
        stop_reasons=stop_reasons,
        cost_by_role_median=cost_by_role_median,
    )


async def run_interleaved_benchmark(
    *,
    cases: list[str],
    arms: list[str] = ["S"],
    runs_per_arm: int = 3,
    scripted: bool = False,
    model: ModelChoice | None = None,
    budget_usd: float = 10.0,
    skills: bool = BENCH_SKILLS_ENABLED,
) -> BenchmarkReport:
    """Execute `runs_per_arm` runs of each case.

    `arms` survives the removal of the flat baseline because the artifact schema
    is keyed by it and older reports are still readable, but "S" is now the only
    topology -- the A/B this runner was built for ended when the flat broker was
    dropped in favour of the subagent design.

    `budget_usd` defaults to 10.0 rather than 1.0: one siem subagent RESERVES
    ~$1.24, so a 1.0 default refused siem on every run -- the one domain that
    matters -- and reported it as a domain failure rather than a budget one.
    """
    model_choice = model or (None if scripted else model_choice_from_env()) or _PLACEHOLDER_MODEL

    raw_runs: list[RunMetrics] = []

    # Pinned across every case, arm and run, so every run in one report shares a
    # skill-pack configuration. The pinned value is the header the report
    # carries; each run additionally records its own `skills_enabled` as
    # observed at execution time, so a run that somehow escaped the pin shows up
    # in the artifact rather than hiding behind the header.
    #
    # `skills` defaults to off and is a parameter rather than an environment
    # read: the pack is measurable on request, but only when a caller asked for
    # it in as many words. An ambient `SMARTOPS_SKILLS_ENABLED` still cannot
    # reach this -- that is the whole point of pinning rather than inheriting.
    with pinned_skills_enabled(skills):
        pinned_skills = skills_enabled()
        for case_name in cases:
            if case_name in BENCHMARK_CASES:
                task, expected_families = BENCHMARK_CASES[case_name]
            else:
                task = AnalystTask(
                    task_id=case_name,
                    hypothesis_id=f"hypothesis-{case_name}",
                    goal=f"Benchmark investigation for case {case_name}",
                    scope=Scope(
                        entities=[Entity(kind="domain", value="coinhive.com")],
                        time_window=(
                            datetime(2018, 8, 20, 0, 0, 0, tzinfo=UTC),
                            datetime(2018, 8, 21, 0, 0, 0, tzinfo=UTC),
                        ),
                    ),
                )
                expected_families = ["siem", "vt"]

            # Interleaved execution: run 0 (S, F), run 1 (S, F), run 2 (S, F)
            for run_idx in range(runs_per_arm):
                for arm in arms:
                    logger.info(
                        "Executing benchmark case=%s arm=%s run=%d/%d "
                        "(scripted=%s skills=%s)",
                        case_name,
                        arm,
                        run_idx + 1,
                        runs_per_arm,
                        scripted,
                        pinned_skills,
                    )
                    metrics = await _execute_single_run(
                        task,
                        arm,
                        run_idx,
                        expected_families,
                        model=model_choice,
                        budget_usd=budget_usd,
                        scripted=scripted,
                    )
                    raw_runs.append(metrics)

    arm_summaries: dict[str, ArmSummary] = {}
    for arm in arms:
        arm_runs = [r for r in raw_runs if r.arm == arm]
        if arm_runs:
            arm_summaries[arm] = compute_arm_summary(arm, arm_runs)

    return BenchmarkReport(
        timestamp=datetime.now(UTC).isoformat(),
        cases=cases,
        arms=arms,
        runs_per_arm=runs_per_arm,
        scripted=scripted,
        skills_enabled=pinned_skills,
        raw_runs=raw_runs,
        arm_summaries=arm_summaries,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartops-bench",
        description="smartops-bench: Interleaved A/B benchmark runner for Task Broker",
    )
    parser.add_argument(
        "--cases",
        default="botsv3_coinhive",
        help="comma-separated benchmark cases to run (default: botsv3_coinhive)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="number of runs per case (default: 3)",
    )
    parser.add_argument(
        "--scripted",
        "--mock",
        action="store_true",
        dest="scripted",
        help="run in offline/mock mode (zero cost, zero LLM calls)",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="output file path for JSON or Markdown benchmark report",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=10.0,
        help="budget per run in USD (default: 10.0)",
    )
    parser.add_argument(
        "--skills",
        action="store_true",
        help=(
            "attach the superman-splunk skill pack to the siem subagent "
            "(off by default; the report records which way it ran)"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable verbose INFO logging",
    )
    return parser


async def _run(argv: list[str] | None = None) -> int:
    load_dotenv(find_dotenv(usecwd=True))
    load_mcp_servers()
    # Before any case runs: a benchmark that raced its own connection would
    # measure the failure, not the system.
    await warm_mcp_clients()
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    cases = [c.strip() for c in args.cases.split(",") if c.strip()]

    report = await run_interleaved_benchmark(
        cases=cases,
        runs_per_arm=args.runs,
        scripted=args.scripted,
        skills=args.skills,
        budget_usd=args.budget_usd,
    )

    markdown_report = report.to_markdown()
    print(markdown_report)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.suffix.lower() == ".json":
            out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        else:
            out_path.write_text(markdown_report, encoding="utf-8")
        print(f"\nReport written to {out_path}")

    return 0


def run(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    raise SystemExit(asyncio.run(_run(argv)))


main = run


if __name__ == "__main__":
    run()
