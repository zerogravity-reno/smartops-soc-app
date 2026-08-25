"""`smartops-blind-compare`: run both analyst arms over one saved run's evidence.

The hypothesis-blind redesign (Tier 1, landed dark in `5caf246..8512f28`) rests on
one empirical claim: showing a domain analyst the hypothesis *anchors* how it reads
the evidence. The demo behind that claim -- `cli-20260823T112627`, `auth_events#6`,
hypothesis-shown reading "legitimate local logins" where hypothesis-blind read
"potential password spraying" -- was later traced to `formatting._format_auth_event`
silently dropping `EventCode`/`Logon_Type`. Both analysts had been shown six
near-blank rows with the one discriminating field already stripped, so neither
verdict was evidence of reasoning. The 2026-08-23 handover's verdict was explicit:
*"a code bug, not proof either analyst reasoned better."*

The projector is fixed (`8512f28`, `9576a8f`). This module re-runs the comparison
so the claim can be re-tested rather than re-asserted.

WHAT IS COMPARED, AND WHAT IS NOT
The two arms return different types on purpose: `run_one` -> `AnalystVerdict`
(carries a stance) and `gather_finding` -> `DomainFinding` (deliberately stance-free,
because an analyst who cannot see the hypothesis must not decide SUPPORTS/REFUTES).
So **stance is not a comparable quantity**. What is comparable is the read of the
evidence: the observations, the citations they rest on, and the confidence.

THE DECISION RULE, FIXED BEFORE THE RUN
Recorded here so the conclusion is not chosen after seeing the output.

- The original demo sampled each arm ONCE, at temperature 0.6. That cannot
  separate anchoring from sampling noise -- two draws from the same distribution
  also differ. So each arm is sampled N times and the between-arm difference is
  judged against the within-arm difference, which is the noise floor.
- **The premise survives** if between-arm agreement is lower than within-arm
  agreement: the arms differ from each other by more than each differs from itself.
- **The premise is dead** if the two arms are indistinguishable given within-arm
  variance, or if the original spraying-vs-legitimate flip does not reproduce now
  that `code=`/`logon_type=` are visible to both.
- A null result is a result, and the cheaper one: it says Tier 2 needs a
  justification other than the anchoring demo.

The agreement numbers are coarse lexical proxies (Jaccard over citation ids, and
over content words of the observation text). They exist to RANK within-arm against
between-arm using one consistent measure -- not to judge either in absolute terms.
Every sample's text is recorded verbatim in the artifact because reading it is the
actual deliverable; the proxies only say where to look.

Nothing here reimplements the pipeline. `route`, `pack_evidence`, `run_one` and
`gather_finding` are called exactly as production calls them, so every gate they
apply -- the empty-slice short-circuit, the bounded re-ask, `_finalize`'s grounding
downgrade, `_finalize_finding`'s citation drop -- is inside the measurement.

`--pack-only` routes and packs and calls no model at all: the zero-cost gate that
confirms the discriminating fields actually reach the prompt before any spend.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import statistics
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path
from typing import Any, Literal

from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel, Field

from contracts import (
    AnalystDomain,
    AnalystVerdict,
    BrokerReport,
    DomainFinding,
    Entity,
    InvestigationContext,
    Scope,
    Stance,
)
from smartops.broker import DEFAULT_RUNS_DIR, RUNS_DIR_ENV_VAR
from smartops.errors import NotConfigured

# Private, and imported rather than copied for the same reason as `_newest_run_in`
# below: a Windows console defaults to cp1252 and cannot encode the `→`/`·` the
# projectors emit, so printing this report raised `UnicodeEncodeError` *after* the
# measurement had been taken and paid for. `main` already solved that exact
# failure; a second copy of the fix is a second thing to keep working.
from smartops.main import _force_utf8_output

# Private, and imported rather than copied: `_newest_run_in` owns the
# `latest.txt`-then-highest-stamp rule that `save_run_artifacts` writes and
# `load_evidence_from_run` reads. A second implementation here would be a second
# thing to keep in step with the writer, and would drift the first time one moved.
from smartops.replay import _newest_run_in
from smartops.subagent_analysts.analyze import gather_finding, run_one
from smartops.subagent_analysts.model import AnalystModel, analyst_model_from_env
from smartops.subagent_analysts.packing import estimate_tokens, pack_evidence
from smartops.subagent_analysts.routing import DomainSlice, route

logger = logging.getLogger(__name__)

Arm = Literal["shown", "blind"]
ARMS: tuple[Arm, Arm] = ("shown", "blind")

DEFAULT_SAMPLES_PER_ARM = 5
"""Why not 1: see the decision rule above. Why not more: 3 domains x 2 arms x N is
the whole cost of the measurement, and the analyst model cold-starts."""


class CaseInfo(BaseModel):
    """Scope and hypothesis prose for a saved run that cannot supply its own.

    Neither is recoverable from an older run directory. `BrokerReport.scope` was
    only added in `430df12`, so every report saved before it has `scope: None`
    while `route()` needs one (`Scope.entities` is `min_length=1`). And the
    hypothesis PROSE is persisted nowhere at all, in old reports or new ones --
    `report.json` and `assessment.json` carry only `hypothesis_id`, which for a
    CLI run is the literal string `"cli-hypothesis"`.

    So both are reconstructed, and the artifact records that they were: a
    reconstructed input is a datum about the measurement, not a detail of it.
    """

    scope: Scope
    hypothesis: str
    provenance: str
    variants: dict[str, str] = Field(default_factory=dict)
    """Alternative hypotheses over the SAME evidence, for the anchoring test.

    Comparing the shown arm against the blind arm cannot isolate anchoring: the
    two differ in prompt, footer and output type all at once, so any divergence
    confounds "the hypothesis biased the read" with "the prompts are different".
    And the blind arm cannot be anchored at all -- it never receives a hypothesis,
    which is a structural guarantee rather than something to measure.

    Anchoring is a claim about the SHOWN arm alone: that its description of fixed
    evidence moves when the hypothesis moves. These variants are what make that
    testable -- they pull in deliberately opposite directions over identical rows.
    """


_BOTSV3_WINDOW = (
    datetime(2018, 8, 20, tzinfo=UTC),
    datetime(2018, 8, 21, tzinfo=UTC),
)

CASES: dict[str, CaseInfo] = {
    # The run the original anchoring demo was built on, and the only run whose
    # evidence can be held byte-identical to it. The hypothesis text below was
    # recovered from the untracked report artifact `docs/hard-test.html`, which
    # quotes the multi-clause claim verbatim; it is NOT in the run directory, and
    # `docs/hard-test-new-run.html` corroborates its shape ("the entire
    # multi-clause claim (hash + C2 IP + coinhive.com, together)").
    "cli-20260823T112627": CaseInfo(
        scope=Scope(
            entities=[
                Entity(kind="user", value="bostoll"),
                Entity(kind="host", value="BSTOLL-L"),
                Entity(kind="domain", value="coinhive.com"),
                Entity(kind="ip", value="217.182.164.14"),
                Entity(kind="file_hash", value="e2ac36894c2560d2b277ff9618b76c8c"),
            ],
            time_window=_BOTSV3_WINDOW,
        ),
        hypothesis=(
            "Host BSTOLL-L was compromised via PowerShell malware payload "
            "e2ac36894c2560d2b277ff9618b76c8c executed by user bostoll, initiating "
            "outbound C2 communication to 217.182.164.14 and coinhive.com"
        ),
        provenance=(
            "scope reconstructed from the run's own fetch plan objectives; "
            "hypothesis prose quoted from docs/hard-test.html (not persisted in "
            "the run directory)"
        ),
        # Three readings the same six auth rows could be bent toward. `original`
        # is the run's real hypothesis; `spraying` asserts the reading the demo
        # attributed to the blind arm; `benign` asserts its opposite. If the shown
        # arm's DESCRIPTION of `auth_events#6` follows whichever it was handed,
        # that is anchoring, shown directly.
        variants={
            "original": (
                "Host BSTOLL-L was compromised via PowerShell malware payload "
                "e2ac36894c2560d2b277ff9618b76c8c executed by user bostoll, "
                "initiating outbound C2 communication to 217.182.164.14 and "
                "coinhive.com"
            ),
            "spraying": (
                "User bostoll's account on host BSTOLL-L was compromised by a "
                "password-spraying attack: repeated failed authentication "
                "attempts preceded a successful logon"
            ),
            "benign": (
                "The authentication activity on host BSTOLL-L is routine: user "
                "bostoll locked and unlocked their own workstation, and nothing "
                "anomalous occurred"
            ),
        },
    ),
}


# ---------------------------------------------------------------------------
# Resolving the run, its scope, and its hypothesis
# ---------------------------------------------------------------------------


def resolve_run_dir(run_id_or_path: Path | str, base_dir: Path | str | None = None) -> Path:
    """The directory holding one run's `report.json`.

    Accepts a case id, a `<case>/<stamp>` pair, or a path, and defaults `base_dir`
    through `$SMARTOPS_RUNS_DIR` exactly as the writer does -- the same resolution
    `replay.load_evidence_from_run` performs for `evidence.json`.
    """
    if base_dir is None:
        base_dir = os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR

    path = Path(run_id_or_path)
    if not path.is_absolute() and not path.exists():
        path = Path(base_dir) / run_id_or_path

    if path.is_dir() and not (path / "report.json").is_file():
        path = _newest_run_in(path)

    if not (path / "report.json").is_file():
        raise FileNotFoundError(
            f"No report.json under {path}: nothing to compare. Name a run "
            "directory directly, or run the case first."
        )
    return path


def load_report(run_dir: Path) -> BrokerReport:
    """Load one saved `report.json`.

    Loads correctly for the whole saved corpus only since `1e893ea` gave
    `SubtaskResult.findings` a callable discriminator that resolves untagged legacy
    payloads by shape. Before it, 22 of 24 saved reports failed to validate and the
    two that passed did so only because every result had `findings: null`.
    """
    return BrokerReport.model_validate_json(
        (run_dir / "report.json").read_text(encoding="utf-8")
    )


def resolve_scope(report: BrokerReport, run_id: str) -> tuple[Scope, str]:
    """`(scope, where it came from)`. The report's own scope wins when it has one."""
    if report.scope is not None:
        return report.scope, "report.json (BrokerReport.scope)"
    case = CASES.get(run_id) or CASES.get(Path(run_id).name)
    if case is not None:
        return case.scope, f"blind_compare.CASES[{run_id!r}] -- {case.provenance}"
    raise NotConfigured(
        f"{run_id} predates BrokerReport.scope and has no blind_compare.CASES "
        "entry, so its evidence cannot be routed. Add a CASES entry naming the "
        "scope that run was fetched under."
    )


def resolve_hypothesis(run_id: str, override: str | None) -> tuple[str, str]:
    """`(hypothesis prose, where it came from)`.

    Never inferred from `hypothesis_id` or from the fetch `goal`: an id is a label
    and a goal is a QUESTION, while the shown arm needs an ASSERTION -- an
    assertion is the only thing that can anchor, so substituting a question would
    quietly measure something else.
    """
    if override:
        return override, "--hypothesis (command line)"
    case = CASES.get(run_id) or CASES.get(Path(run_id).name)
    if case is not None:
        return case.hypothesis, f"blind_compare.CASES[{run_id!r}] -- {case.provenance}"
    raise NotConfigured(
        f"No hypothesis prose for {run_id}: it is persisted nowhere in a run "
        "directory. Pass --hypothesis, or add a blind_compare.CASES entry."
    )


def resolve_variants(
    run_id: str, overrides: list[str] | None
) -> tuple[dict[str, str], str]:
    """`({label: prose}, where they came from)` for the anchoring test.

    `overrides` are raw `--hypothesis` values, optionally `label=prose`; an
    unlabelled one is named by position. Two or more are required -- one
    hypothesis cannot show that a read moves with the hypothesis.
    """
    if overrides:
        variants: dict[str, str] = {}
        for index, raw in enumerate(overrides, start=1):
            label, separator, prose = raw.partition("=")
            if separator and label.strip() and " " not in label.strip():
                variants[label.strip()] = prose.strip()
            else:
                variants[f"h{index}"] = raw.strip()
        return variants, "--hypothesis (command line, repeated)"

    case = CASES.get(run_id) or CASES.get(Path(run_id).name)
    if case is not None and case.variants:
        return dict(case.variants), f"blind_compare.CASES[{run_id!r}].variants"
    raise NotConfigured(
        f"No hypothesis variants for {run_id}. Pass --hypothesis twice or more, "
        "or add a `variants` mapping to its blind_compare.CASES entry."
    )


# ---------------------------------------------------------------------------
# Artifact shapes
# ---------------------------------------------------------------------------


class DomainEvidence(BaseModel):
    """What one domain analyst was shown, recorded verbatim.

    The packed text is in the artifact because the original demo's root cause was
    invisible in the verdicts and visible only in this string: six auth rows whose
    `EventCode`/`Logon_Type` had been projected away. A comparison that records
    conclusions but not the evidence text cannot be audited the way that one was.
    """

    domain: AnalystDomain
    has_evidence: bool
    evidence_text: str
    valid_citation_ids: dict[str, list[str]]
    estimated_tokens: int
    truncated: bool
    siem_set_count: int
    untagged_set_count: int
    vt_verdict_count: int
    total_rows: int


class ArmSample(BaseModel):
    """One arm's output for one domain, one draw."""

    arm: Arm
    domain: AnalystDomain
    sample_index: int
    model_called: bool
    hypothesis_label: str | None = None
    """Which hypothesis variant this draw was given. `None` for the blind arm,
    which receives no hypothesis at all -- that absence is the point of the arm,
    and it is why the blind arm is the anchoring test's control rather than one of
    its conditions."""
    stance: Stance | None = None
    """Present for the shown arm only. The blind arm has no stance by design."""
    confidence: float
    rationale: str
    observations: list[str]
    citations: list[str]
    citation_evidence: dict[str, list[str]] = Field(default_factory=dict)
    reasoning_trace: str | None = None
    prompt_tokens: int
    generation_tokens: int


class ArmStats(BaseModel):
    """One arm's spread across its samples for one domain."""

    arm: Arm
    samples: int
    model_calls: int
    failed_calls: int = 0
    """Draws whose model call never returned a generation.

    Both arms contain their own failures on purpose -- an errored call becomes an
    inconclusive verdict that says why, so one domain never sinks the assessment.
    The cost is that a run in which EVERY call failed looks, structurally, exactly
    like a run that succeeded: same sample count, same shape, exit code 0. That
    happened on the first live attempt here (30 draws, 30 `AccessDeniedException`s
    from a credential fault) and the report read as a completed measurement. A
    failed call reports zero prompt tokens, which is what this counts.
    """
    confidence_min: float
    confidence_median: float
    confidence_max: float
    mean_observation_count: float
    prompt_tokens: int
    generation_tokens: int
    within_arm_citation_agreement: float | None = None
    within_arm_text_agreement: float | None = None
    """Mean pairwise agreement among this arm's own samples -- the noise floor.
    `None` when the arm has fewer than two samples (nothing to pair)."""
    stances: dict[str, int] = Field(default_factory=dict)


class DomainComparison(BaseModel):
    domain: AnalystDomain
    evidence: DomainEvidence
    arms: dict[str, ArmStats] = Field(default_factory=dict)
    between_arm_citation_agreement: float | None = None
    between_arm_text_agreement: float | None = None
    diverges_beyond_noise: bool | None = None
    """True when between-arm agreement is below BOTH arms' within-arm agreement on
    the observation text -- the decision rule's condition, evaluated here rather
    than left to be eyeballed. `None` when there is not enough sampling to say."""


def _condition_of(sample: ArmSample) -> str:
    """Which sampling condition a draw belongs to.

    The hypothesis label when there is one, otherwise the arm -- so a blind draw
    is always `blind`, in either mode, because it has no hypothesis to name.
    """
    return sample.hypothesis_label or sample.arm


class AnchoringComparison(BaseModel):
    """Does the shown arm's read of FIXED evidence move with the hypothesis?

    The measurement the arm-versus-arm comparison cannot make. Same slice, same
    prompt template, same footer, same output type -- only the hypothesis text
    differs between conditions, so a difference in the read cannot be blamed on
    anything else.
    """

    domain: AnalystDomain
    variants: dict[str, ArmStats] = Field(default_factory=dict)
    """One entry per hypothesis, all shown-arm. Each carries its own within-variant
    agreement: that is the noise floor for this condition."""
    blind_control: ArmStats | None = None
    """The blind arm over the same evidence. Not a condition of the experiment --
    it cannot be anchored -- but it bounds how much of any spread is just this
    model's variance on this slice, with no hypothesis in play at all."""
    cross_variant_text_agreement: float | None = None
    cross_variant_citation_agreement: float | None = None
    read_tracks_hypothesis: bool | None = None
    """True when the read differs MORE across hypotheses than across repeats of
    the same hypothesis -- i.e. cross-variant agreement is below every variant's
    own floor. That is anchoring: the description follows what the analyst was
    told to look for. `None` when a variant was sampled too few times to have a
    floor."""


class BlindCompareReport(BaseModel):
    """The measurement artifact. Self-describing on purpose.

    Carries the inputs (run, scope, hypothesis, and where each came from), the
    configuration (model, temperature, sample count), the evidence text every arm
    saw, and every sample verbatim -- so the conclusion can be re-derived from the
    artifact alone rather than trusted.
    """

    timestamp: str
    run_id: str
    run_dir: str
    task_id: str
    hypothesis_id: str
    scope: Scope
    scope_source: str
    hypothesis: str | None
    hypothesis_source: str
    samples_per_arm: int
    pack_only: bool
    mode: Literal["arms", "anchoring"] = "arms"
    """`arms` compares shown against blind. `anchoring` holds the evidence fixed
    and varies the hypothesis within the shown arm."""
    variants: dict[str, str] = Field(default_factory=dict)
    variants_source: str = ""
    model: dict[str, Any]
    domains: list[DomainComparison] = Field(default_factory=list)
    anchoring: list[AnchoringComparison] = Field(default_factory=list)
    samples: list[ArmSample] = Field(default_factory=list)

    def _condition_order(self) -> list[str]:
        """Sampling conditions in report order.

        `arms` mode has two (the arms). `anchoring` mode has one per hypothesis
        plus `blind (control)` -- named so the artifact never reads as though the
        blind arm were one of the hypotheses being tested.
        """
        if self.mode == "anchoring":
            return [*self.variants, "blind"]
        return list(ARMS)

    def _conditions(self) -> list[tuple[str, str, ArmStats]]:
        """`(domain, condition, stats)` rows for the cost table, in report order."""
        rows: list[tuple[str, str, ArmStats]] = []
        if self.mode == "anchoring":
            for a in self.anchoring:
                for label in self.variants:
                    if label in a.variants:
                        rows.append((a.domain, label, a.variants[label]))
                if a.blind_control is not None:
                    rows.append((a.domain, "blind", a.blind_control))
            return rows
        for c in self.domains:
            for arm in ARMS:
                stats = c.arms.get(arm)
                if stats is not None:
                    rows.append((c.domain, arm, stats))
        return rows

    def call_counts(self) -> tuple[int, int]:
        """`(intended model calls, failed model calls)` across every domain and arm."""
        intended = sum(1 for s in self.samples if s.model_called)
        failed = sum(1 for s in self.samples if s.model_called and s.prompt_tokens == 0)
        return intended, failed

    def is_measurement(self) -> bool:
        """Whether anything was actually measured.

        False when every model call failed: the artifact is then a record of an
        outage, not a comparison, and must not be read as one.
        """
        intended, failed = self.call_counts()
        return intended > failed

    def to_markdown(self) -> str:
        lines = [
            "# Blind vs shown — analyst comparison",
            "",
            f"- **Run:** `{self.run_id}` (`{self.run_dir}`)",
            f"- **Task / hypothesis id:** `{self.task_id}` / `{self.hypothesis_id}`",
            f"- **Scope source:** {self.scope_source}",
            f"- **Hypothesis source:** {self.hypothesis_source}",
            f"- **Hypothesis:** {self.hypothesis or '(none — pack-only)'}",
            f"- **Samples per arm:** {self.samples_per_arm}"
            f"{'  *(pack-only: no model was called)*' if self.pack_only else ''}",
            f"- **Model:** `{self.model.get('model_arn') or '(none)'}` "
            f"temperature={self.model.get('temperature')} "
            f"top_p={self.model.get('top_p')} "
            f"max_gen_len={self.model.get('max_gen_len')}",
            f"- **Generated:** {self.timestamp}",
            "",
            "## Evidence each domain was shown",
            "",
            "| Domain | siem sets | untagged | VT | rows | est. tokens | truncated |",
            "|---|---|---|---|---|---|---|",
        ]
        for comparison in self.domains:
            e = comparison.evidence
            lines.append(
                f"| {e.domain} | {e.siem_set_count} | {e.untagged_set_count} | "
                f"{e.vt_verdict_count} | {e.total_rows} | {e.estimated_tokens} | "
                f"{'yes' if e.truncated else 'no'} |"
            )

        if self.pack_only:
            lines.extend(["", "## Packed evidence", ""])
            for comparison in self.domains:
                lines.extend(
                    [
                        f"### {comparison.domain}",
                        "",
                        "```",
                        comparison.evidence.evidence_text,
                        "```",
                        "",
                    ]
                )
            return "\n".join(lines)

        def _fmt(value: float | None) -> str:
            return "n/a" if value is None else f"{value:.2f}"

        if self.mode == "anchoring":
            lines.extend(
                [
                    "",
                    "## Anchoring — does the shown arm's read follow the hypothesis?",
                    "",
                    "Evidence held fixed; only the hypothesis text differs between "
                    "conditions. The blind arm is the control, not a condition: it "
                    "receives no hypothesis, so it cannot be anchored by "
                    "construction. The rule: cross-variant agreement below every "
                    "variant's own within-variant floor means the description "
                    "follows what the analyst was told to look for.",
                    "",
                ]
            )
            for label, prose in self.variants.items():
                lines.append(f"- **{label}** — {prose}")
            lines.extend(
                [
                    "",
                    "| Domain | cross-variant (text) | "
                    + " | ".join(f"within {label}" for label in self.variants)
                    + " | blind control | verdict |",
                    "|---" * (3 + len(self.variants)) + "|",
                ]
            )
            for a in self.anchoring:
                verdict = (
                    "n/a"
                    if a.read_tracks_hypothesis is None
                    else ("tracks the hypothesis" if a.read_tracks_hypothesis else "within noise")
                )
                floors = " | ".join(
                    _fmt(
                        a.variants[label].within_arm_text_agreement
                        if label in a.variants
                        else None
                    )
                    for label in self.variants
                )
                control = _fmt(
                    a.blind_control.within_arm_text_agreement if a.blind_control else None
                )
                lines.append(
                    f"| {a.domain} | {_fmt(a.cross_variant_text_agreement)} | "
                    f"{floors} | {control} | {verdict} |"
                )
        else:
            lines.extend(
                [
                    "",
                    "## Agreement — between arms vs within each arm",
                    "",
                    "Lexical Jaccard proxies, comparable to each other and not in "
                    "absolute terms. The decision rule: between-arm agreement below "
                    "both within-arm floors means the arms differ by more than "
                    "sampling noise. Note this cannot isolate anchoring — the arms "
                    "differ in prompt, footer and output type at once — which is "
                    "what the `anchoring` mode is for.",
                    "",
                    "| Domain | between (text) | within shown | within blind | "
                    "between (cites) | verdict |",
                    "|---|---|---|---|---|---|",
                ]
            )
        if self.mode == "arms":
            for c in self.domains:
                shown, blind = c.arms.get("shown"), c.arms.get("blind")
                verdict = (
                    "n/a"
                    if c.diverges_beyond_noise is None
                    else (
                        "diverges beyond noise"
                        if c.diverges_beyond_noise
                        else "within noise"
                    )
                )
                lines.append(
                    f"| {c.domain} | {_fmt(c.between_arm_text_agreement)} | "
                    f"{_fmt(shown.within_arm_text_agreement if shown else None)} | "
                    f"{_fmt(blind.within_arm_text_agreement if blind else None)} | "
                    f"{_fmt(c.between_arm_citation_agreement)} | {verdict} |"
                )

        lines.extend(
            [
                "",
                "## Confidence and cost",
                "",
                "| Domain | Condition | confidence (min/med/max) | mean observations | "
                "stances | failed | prompt tok | gen tok |",
                "|---|---|---|---|---|---|---|---|",
            ]
        )
        for domain, condition, stats in self._conditions():
            stances = (
                ", ".join(f"{k}:{v}" for k, v in sorted(stats.stances.items())) or "—"
            )
            confidence = (
                f"{stats.confidence_min:.2f} / {stats.confidence_median:.2f} / "
                f"{stats.confidence_max:.2f}"
            )
            lines.append(
                f"| {domain} | {condition} | {confidence} | "
                f"{stats.mean_observation_count:.1f} | {stances} | "
                f"{stats.failed_calls}/{stats.model_calls} | "
                f"{stats.prompt_tokens} | {stats.generation_tokens} |"
            )

        lines.extend(["", "## Every sample, verbatim", ""])
        for c in self.domains:
            lines.extend([f"### {c.domain}", ""])
            for condition in self._condition_order():
                shown_here = [
                    s
                    for s in self.samples
                    if s.domain == c.domain and _condition_of(s) == condition
                ]
                if not shown_here:
                    continue
                lines.extend([f"#### {condition}", ""])
                for sample in shown_here:
                    head = f"**#{sample.sample_index}**"
                    if sample.stance is not None:
                        head += f" — stance `{sample.stance}`"
                    head += f", confidence {sample.confidence:.2f}"
                    if not sample.model_called:
                        head += " *(no model call — empty slice)*"
                    lines.extend([head, "", f"> {sample.rationale or '(no rationale)'}", ""])
                    for observation in sample.observations:
                        lines.append(f"- {observation}")
                    if not sample.observations:
                        lines.append("- (no observations)")
                    lines.extend(
                        ["", f"citations: `{', '.join(sample.citations) or '(none)'}`", ""]
                    )
            lines.extend(
                [
                    "<details><summary>Evidence this domain was shown</summary>",
                    "",
                    "```",
                    c.evidence.evidence_text,
                    "```",
                    "",
                    "</details>",
                    "",
                ]
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agreement proxies
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[a-z0-9_#.:@-]{3,}")

_STOPWORDS = frozenset(
    """the and for with that this from are was were has have had not but its
    they their there then than which when what where who whom whose all any
    some only also into onto over under about across between during before after
    each both such same other another been being does did done can could would
    should may might must shall will these those""".split()
)
"""Trimmed by hand rather than pulled from a library: the proxy compares two sets
of analyst prose to each other, so the only words worth removing are the ones that
appear in every reply regardless of what it says."""


def _content_words(texts: list[str]) -> set[str]:
    words: set[str] = set()
    for text in texts:
        words |= {w for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS}
    return words


def _jaccard(left: set[str], right: set[str]) -> float:
    """1.0 for two empty sets: "both said nothing" is agreement, not a gap.

    Returning 0.0 there would read as maximal disagreement and would invert the
    comparison for any domain where both arms legitimately found nothing to cite.
    """
    union = left | right
    if not union:
        return 1.0
    return len(left & right) / len(union)


def _mean_pairwise(sets: list[set[str]]) -> float | None:
    """Mean Jaccard over every pair. `None` for fewer than two sets."""
    if len(sets) < 2:
        return None
    scores = [_jaccard(a, b) for a, b in combinations(sets, 2)]
    return round(sum(scores) / len(scores), 4)


def _mean_cross(left: list[set[str]], right: list[set[str]]) -> float | None:
    """Mean Jaccard over every (left, right) pair. `None` if either side is empty."""
    if not left or not right:
        return None
    scores = [_jaccard(a, b) for a in left for b in right]
    return round(sum(scores) / len(scores), 4)


# ---------------------------------------------------------------------------
# The measurement
# ---------------------------------------------------------------------------


def describe_evidence(slice_: DomainSlice) -> DomainEvidence:
    """Pack one slice and record what was packed.

    `pack_evidence` is deterministic given a slice, and both arms call it
    themselves with the same default budget -- so packing once here for the record
    reproduces exactly what each arm was shown. `test_blind_compare` pins that.
    """
    evidence_text, valid_ids, truncated, _row_cap = pack_evidence(slice_)
    rows = sum(rs.row_count for _, rs in slice_.siem_sets) + sum(
        rs.row_count for rs in slice_.untagged_sets
    )
    return DomainEvidence(
        domain=slice_.domain,
        has_evidence=slice_.has_evidence(),
        evidence_text=evidence_text,
        valid_citation_ids=valid_ids,
        estimated_tokens=estimate_tokens(evidence_text),
        truncated=truncated,
        siem_set_count=len(slice_.siem_sets),
        untagged_set_count=len(slice_.untagged_sets),
        vt_verdict_count=len(slice_.vt_verdicts),
        total_rows=rows,
    )


def _to_sample(
    arm: Arm,
    index: int,
    result: AnalystVerdict | DomainFinding,
    *,
    model_called: bool,
    hypothesis_label: str | None = None,
) -> ArmSample:
    if isinstance(result, AnalystVerdict):
        return ArmSample(
            arm=arm,
            domain=result.domain,
            sample_index=index,
            model_called=model_called,
            hypothesis_label=hypothesis_label,
            stance=result.stance,
            confidence=result.confidence,
            rationale=result.rationale,
            observations=list(result.key_observations),
            citations=list(result.citations),
            citation_evidence=dict(result.citation_evidence),
            reasoning_trace=result.reasoning_trace,
            prompt_tokens=result.prompt_tokens,
            generation_tokens=result.generation_tokens,
        )
    return ArmSample(
        arm=arm,
        domain=result.domain,
        sample_index=index,
        model_called=model_called,
        stance=None,
        confidence=result.confidence,
        rationale=result.rationale,
        observations=list(result.observations),
        citations=list(result.citations),
        reasoning_trace=result.reasoning_trace,
        prompt_tokens=result.prompt_tokens,
        generation_tokens=result.generation_tokens,
    )


def sample_domain(
    model: AnalystModel,
    context: InvestigationContext,
    scope: Scope,
    slice_: DomainSlice,
    *,
    samples_per_arm: int,
) -> list[ArmSample]:
    """Both arms over one slice, `samples_per_arm` draws each.

    An empty slice is sampled ONCE per arm, not N times: both arms short-circuit
    before the model on `not slice_.has_evidence()`, so further draws would be
    byte-identical copies of a deterministic branch, padding the artifact with
    repetition that looks like evidence of stability.
    """
    calls = 1 if not slice_.has_evidence() else samples_per_arm
    collected: list[ArmSample] = []
    for arm in ARMS:
        for index in range(1, calls + 1):
            logger.info(
                "domain=%s arm=%s sample=%d/%d", slice_.domain, arm, index, calls
            )
            if arm == "shown":
                result: AnalystVerdict | DomainFinding = run_one(
                    model, context, scope, slice_
                )
            else:
                result = gather_finding(model, scope, slice_)
            collected.append(
                _to_sample(arm, index, result, model_called=slice_.has_evidence())
            )
    return collected


def sample_anchoring(
    model: AnalystModel,
    scope: Scope,
    slice_: DomainSlice,
    variants: dict[str, str],
    *,
    samples_per_arm: int,
) -> list[ArmSample]:
    """The shown arm over one slice once per hypothesis, plus the blind control.

    Same slice object every time, so `pack_evidence` renders identical text for
    every condition: the hypothesis is the only thing that varies. The blind arm
    is drawn too, and labelled as the control rather than as a condition -- it
    receives no hypothesis, so it cannot be anchored, and its own spread is the
    reference for how much of any cross-variant difference is just this model's
    variance on this slice.
    """
    calls = 1 if not slice_.has_evidence() else samples_per_arm
    collected: list[ArmSample] = []
    for label, prose in variants.items():
        context = InvestigationContext(hypothesis=prose)
        for index in range(1, calls + 1):
            logger.info(
                "domain=%s hypothesis=%s sample=%d/%d", slice_.domain, label, index, calls
            )
            verdict = run_one(model, context, scope, slice_)
            collected.append(
                _to_sample(
                    "shown",
                    index,
                    verdict,
                    model_called=slice_.has_evidence(),
                    hypothesis_label=label,
                )
            )
    for index in range(1, calls + 1):
        logger.info("domain=%s arm=blind (control) sample=%d/%d", slice_.domain, index, calls)
        finding = gather_finding(model, scope, slice_)
        collected.append(
            _to_sample("blind", index, finding, model_called=slice_.has_evidence())
        )
    return collected


def _arm_stats(arm: Arm, samples: list[ArmSample]) -> ArmStats:
    confidences = [s.confidence for s in samples]
    stances: dict[str, int] = {}
    for sample in samples:
        if sample.stance is not None:
            stances[sample.stance] = stances.get(sample.stance, 0) + 1
    return ArmStats(
        arm=arm,
        samples=len(samples),
        model_calls=sum(1 for s in samples if s.model_called),
        failed_calls=sum(1 for s in samples if s.model_called and s.prompt_tokens == 0),
        confidence_min=min(confidences),
        confidence_median=round(statistics.median(confidences), 4),
        confidence_max=max(confidences),
        mean_observation_count=round(
            sum(len(s.observations) for s in samples) / len(samples), 3
        ),
        prompt_tokens=sum(s.prompt_tokens for s in samples),
        generation_tokens=sum(s.generation_tokens for s in samples),
        within_arm_citation_agreement=_mean_pairwise([set(s.citations) for s in samples]),
        within_arm_text_agreement=_mean_pairwise(
            [_content_words(s.observations + [s.rationale]) for s in samples]
        ),
        stances=stances,
    )


def compare_domain(evidence: DomainEvidence, samples: list[ArmSample]) -> DomainComparison:
    """Roll one domain's samples into the comparison, and apply the decision rule."""
    comparison = DomainComparison(domain=evidence.domain, evidence=evidence)
    by_arm = {arm: [s for s in samples if s.arm == arm] for arm in ARMS}
    for arm in ARMS:
        if by_arm[arm]:
            comparison.arms[arm] = _arm_stats(arm, by_arm[arm])

    if not (by_arm["shown"] and by_arm["blind"]):
        return comparison

    comparison.between_arm_citation_agreement = _mean_cross(
        [set(s.citations) for s in by_arm["shown"]],
        [set(s.citations) for s in by_arm["blind"]],
    )
    comparison.between_arm_text_agreement = _mean_cross(
        [_content_words(s.observations + [s.rationale]) for s in by_arm["shown"]],
        [_content_words(s.observations + [s.rationale]) for s in by_arm["blind"]],
    )

    between = comparison.between_arm_text_agreement
    floors = [
        comparison.arms[arm].within_arm_text_agreement
        for arm in ARMS
        if comparison.arms.get(arm) is not None
        and comparison.arms[arm].within_arm_text_agreement is not None
    ]
    # Both floors required: if only one arm was sampled repeatedly there is no
    # symmetric noise estimate, and calling it either way would be a guess.
    if between is not None and len(floors) == len(ARMS):
        comparison.diverges_beyond_noise = all(between < floor for floor in floors)
    return comparison


def compare_anchoring(
    domain: AnalystDomain, variants: dict[str, str], samples: list[ArmSample]
) -> AnchoringComparison:
    """Roll one domain's anchoring draws up, and apply the anchoring rule."""
    comparison = AnchoringComparison(domain=domain)
    blind = [s for s in samples if s.arm == "blind"]
    if blind:
        comparison.blind_control = _arm_stats("blind", blind)

    per_variant = {
        label: [s for s in samples if s.hypothesis_label == label] for label in variants
    }
    for label, draws in per_variant.items():
        if draws:
            comparison.variants[label] = _arm_stats("shown", draws)

    populated = {label: draws for label, draws in per_variant.items() if draws}
    if len(populated) < 2:
        return comparison

    def _texts(draws: list[ArmSample]) -> list[set[str]]:
        return [_content_words(s.observations + [s.rationale]) for s in draws]

    # Every unordered pair of DIFFERENT variants, pooled. Comparing only adjacent
    # pairs would let one outlier variant carry the verdict.
    cross_text = [
        score
        for left, right in combinations(populated, 2)
        for score in [_mean_cross(_texts(populated[left]), _texts(populated[right]))]
        if score is not None
    ]
    cross_cites = [
        score
        for left, right in combinations(populated, 2)
        for score in [
            _mean_cross(
                [set(s.citations) for s in populated[left]],
                [set(s.citations) for s in populated[right]],
            )
        ]
        if score is not None
    ]
    if cross_text:
        comparison.cross_variant_text_agreement = round(
            sum(cross_text) / len(cross_text), 4
        )
    if cross_cites:
        comparison.cross_variant_citation_agreement = round(
            sum(cross_cites) / len(cross_cites), 4
        )

    floors = [
        comparison.variants[label].within_arm_text_agreement
        for label in populated
        if comparison.variants[label].within_arm_text_agreement is not None
    ]
    # Every variant must have a floor: a condition sampled once has no noise
    # estimate, and calling the verdict either way from the rest would be a guess.
    if comparison.cross_variant_text_agreement is not None and len(floors) == len(
        populated
    ):
        comparison.read_tracks_hypothesis = all(
            comparison.cross_variant_text_agreement < floor for floor in floors
        )
    return comparison


def compare_run(
    run_id: str,
    *,
    hypothesis: str | None = None,
    variants: dict[str, str] | None = None,
    variants_source: str = "",
    samples_per_arm: int = DEFAULT_SAMPLES_PER_ARM,
    pack_only: bool = False,
    model: AnalystModel | None = None,
    base_dir: Path | str | None = None,
) -> BlindCompareReport:
    """Run the comparison over one saved run and return the artifact.

    `variants` switches modes. Without it, the arms are compared against each
    other. With two or more, the evidence is held fixed and the hypothesis varied
    inside the shown arm -- the only one of the two that can actually isolate
    anchoring.
    """
    run_dir = resolve_run_dir(run_id, base_dir)
    report = load_report(run_dir)
    scope, scope_source = resolve_scope(report, run_id)
    anchoring_mode = bool(variants and len(variants) >= 2)

    if pack_only:
        hypothesis_text, hypothesis_source = None, "(not resolved — pack-only)"
    elif anchoring_mode:
        hypothesis_text, hypothesis_source = None, variants_source
    else:
        hypothesis_text, hypothesis_source = resolve_hypothesis(run_id, hypothesis)

    routed = route(report, scope)
    evidence = {slice_.domain: describe_evidence(slice_) for slice_ in routed.slices()}

    model_config: dict[str, Any] = {}
    samples: list[ArmSample] = []
    domains: list[DomainComparison] = []
    anchoring: list[AnchoringComparison] = []

    if pack_only:
        domains = [
            DomainComparison(domain=slice_.domain, evidence=evidence[slice_.domain])
            for slice_ in routed.slices()
        ]
    else:
        if model is None:
            model = analyst_model_from_env()
        if model is None:
            raise NotConfigured(
                "SMARTOPS_ANALYST_MODEL_ARN is not set, so no arm can be sampled. "
                "Set it, or run with --pack-only for the zero-cost evidence check."
            )
        model_config = {
            "model_arn": getattr(model, "model_arn", None),
            "region": getattr(model, "region", None),
            "temperature": getattr(model, "temperature", None),
            "top_p": getattr(model, "top_p", None),
            "max_gen_len": getattr(model, "max_gen_len", None),
        }
        if anchoring_mode:
            for slice_ in routed.slices():
                domain_samples = sample_anchoring(
                    model,
                    scope,
                    slice_,
                    variants or {},
                    samples_per_arm=samples_per_arm,
                )
                samples.extend(domain_samples)
                # Evidence is still recorded per domain: the whole experiment
                # rests on it being identical across conditions.
                domains.append(
                    DomainComparison(
                        domain=slice_.domain, evidence=evidence[slice_.domain]
                    )
                )
                anchoring.append(
                    compare_anchoring(slice_.domain, variants or {}, domain_samples)
                )
        else:
            context = InvestigationContext(hypothesis=hypothesis_text or "")
            for slice_ in routed.slices():
                domain_samples = sample_domain(
                    model, context, scope, slice_, samples_per_arm=samples_per_arm
                )
                samples.extend(domain_samples)
                domains.append(compare_domain(evidence[slice_.domain], domain_samples))

    return BlindCompareReport(
        timestamp=datetime.now(UTC).isoformat(),
        run_id=run_id,
        run_dir=str(run_dir),
        task_id=report.task_id,
        hypothesis_id=report.hypothesis_id,
        scope=scope,
        scope_source=scope_source,
        hypothesis=hypothesis_text,
        hypothesis_source=hypothesis_source,
        samples_per_arm=samples_per_arm,
        pack_only=pack_only,
        mode="anchoring" if anchoring_mode else "arms",
        variants=dict(variants) if anchoring_mode else {},
        variants_source=variants_source if anchoring_mode else "",
        model=model_config,
        domains=domains,
        anchoring=anchoring,
        samples=samples,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _default_out(run_id: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    return Path("docs") / f"blind-vs-shown-{Path(run_id).name}-{stamp}.json"


def write_artifact(report: BlindCompareReport, out: Path) -> tuple[Path, Path]:
    """Write the JSON artifact and its markdown sibling. Returns both paths.

    Deliberately never writes under `.smartops/runs/`: those directories are the
    fixture this measurement rests on, and adding files to them would make the
    fixture a function of the measurements taken over it.
    """
    resolved = out.resolve()
    runs_root = Path(
        os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR
    ).resolve()
    if resolved == runs_root or runs_root in resolved.parents:
        raise ValueError(
            f"refusing to write the artifact inside the run fixture tree ({runs_root}); "
            "choose an --out outside it"
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown = out.with_suffix(".md")
    markdown.write_text(report.to_markdown(), encoding="utf-8")
    return out, markdown


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartops-blind-compare",
        description=(
            "Run the hypothesis-shown and hypothesis-blind analyst arms over one "
            "saved run's evidence, N samples each, and record the comparison."
        ),
    )
    parser.add_argument(
        "--run",
        required=True,
        metavar="RUN_ID",
        help=(
            "case id, <case>/<stamp>, or a path to a run directory under "
            "$SMARTOPS_RUNS_DIR (default .smartops/runs)"
        ),
    )
    parser.add_argument(
        "--hypothesis",
        action="append",
        default=None,
        metavar="[LABEL=]TEXT",
        help=(
            "the hypothesis prose the shown arm is given. Required unless the run "
            "has a blind_compare.CASES entry: prose is persisted nowhere in a run "
            "directory. Must be an assertion, not a question -- only an assertion "
            "can anchor. Repeat it (optionally `label=prose`) to run the ANCHORING "
            "test instead: same evidence, one condition per hypothesis."
        ),
    )
    parser.add_argument(
        "--anchoring",
        action="store_true",
        help=(
            "run the anchoring test using the run's committed hypothesis variants: "
            "the shown arm over identical evidence once per hypothesis, plus the "
            "blind arm as the control. This is the only mode that isolates "
            "anchoring -- comparing the arms to each other confounds it with the "
            "prompts being different, and the blind arm cannot be anchored at all."
        ),
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_SAMPLES_PER_ARM,
        help=(
            f"draws per arm per domain (default: {DEFAULT_SAMPLES_PER_ARM}). "
            "1 reproduces the original comparison, and its inability to separate "
            "anchoring from temperature noise."
        ),
    )
    parser.add_argument(
        "--pack-only",
        action="store_true",
        help=(
            "route and pack the evidence, call NO model, and write the artifact's "
            "evidence section only. Zero cost; the gate that confirms the "
            "discriminating fields reach the prompt before any spend."
        ),
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="JSON artifact path; a .md sibling is written alongside it",
    )
    parser.add_argument("--verbose", action="store_true", help="show INFO logs")
    return parser


def _run(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    load_dotenv(find_dotenv(usecwd=True))
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.samples < 1:
        print("--samples must be at least 1")
        return 2

    given = list(args.hypothesis or [])
    variants: dict[str, str] | None = None
    variants_source = ""
    if not args.pack_only and (args.anchoring or len(given) > 1):
        variants, variants_source = resolve_variants(args.run, given or None)
        if len(variants) < 2:
            print(
                "the anchoring test needs at least two hypotheses: one cannot show "
                "that a read moves with the hypothesis"
            )
            return 2

    report = compare_run(
        args.run,
        hypothesis=given[0] if len(given) == 1 else None,
        variants=variants,
        variants_source=variants_source,
        samples_per_arm=args.samples,
        pack_only=args.pack_only,
    )
    json_path, markdown_path = write_artifact(
        report, Path(args.out) if args.out else _default_out(args.run)
    )
    print(report.to_markdown())
    print(f"\nArtifact written to {json_path}\nSummary written to {markdown_path}")

    if report.pack_only:
        return 0

    intended, failed = report.call_counts()
    if not report.is_measurement():
        # Non-zero, loudly. An artifact of N failed calls has the same shape as
        # one of N successes, and exiting 0 here once already presented an
        # outage as a completed measurement.
        print(
            f"\nNOT A MEASUREMENT: all {intended} model call(s) failed. The "
            "artifact records the failures, not a comparison — read the "
            "rationale of any sample for the cause."
        )
        return 1
    if failed:
        print(f"\nWARNING: {failed} of {intended} model call(s) failed; the "
              "comparison rests on the rest.")
    return 0


def run(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    raise SystemExit(_run(argv))


main = run


if __name__ == "__main__":
    run()
