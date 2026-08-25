"""Tests for the blind-vs-shown comparison harness.

These pin the properties the measurement's validity rests on -- that `--pack-only`
really is free, that both arms really are shown the same evidence, and that every
draw reaches the artifact -- not the wording of the report.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from smartops import blind_compare
from smartops.blind_compare import (
    ArmSample,
    DomainEvidence,
    compare_domain,
    compare_run,
    resolve_run_dir,
    write_artifact,
)
from smartops.broker import RUNS_DIR_ENV_VAR
from smartops.errors import NotConfigured
from smartops.subagent_analysts.model import AnalystResponse

from contracts import (
    BrokerReport,
    CostSummary,
    Entity,
    ResultSet,
    Scope,
    SiemFindings,
    SubtaskResult,
    SubtaskStatus,
    TaskClassification,
)

_HYPOTHESIS = "bostoll was brute-forced on BSTOLL-L"

_EVIDENCE_RE = re.compile(r"<evidence>\n(.*)\n</evidence>", re.DOTALL)


def _scope() -> Scope:
    return Scope(
        entities=[Entity(kind="user", value="bostoll"), Entity(kind="host", value="BSTOLL-L")],
        time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
    )


def _report() -> BrokerReport:
    """A report with identity and endpoint evidence, and nothing for network.

    The empty network slice is not incidental: it exercises the short-circuit both
    arms take before the model, which the sampling loop treats specially.
    """
    findings = SiemFindings(
        auth_events=[
            ResultSet(
                query="index=botsv3 sourcetype=WinEventLog EventCode=4624",
                row_count=2,
                rows=[
                    {"_time": "2018-08-20T15:35:34", "user": "bstoll@froth.ly",
                     "src_ip": "127.0.0.1", "EventCode": "4624", "Logon_Type": "11"},
                    {"_time": "2018-08-20T15:35:44", "user": "bstoll@froth.ly",
                     "EventCode": "4648", "Logon_Type": "7"},
                ],
            )
        ],
        processes=[
            ResultSet(
                query="index=botsv3 New_Process_Name=*powershell*",
                row_count=1,
                rows=[{"_time": "2018-08-20T15:40:00", "New_Process_Name": "powershell.exe",
                       "Creator_Process_Name": "browser_broker.exe"}],
            )
        ],
    )
    result = SubtaskResult(
        task_id="t1:siem:s0",
        family="siem",
        status=SubtaskStatus.OK,
        findings=findings,
    )
    return BrokerReport(
        task_id="t1",
        hypothesis_id="h-42",
        results=[result],
        classification=TaskClassification(tool_families=["siem"], rationale="x"),
        scope=_scope(),
        cost=CostSummary(),
    )


def _save(report: BrokerReport, runs_dir: Path, run_id: str = "case-1") -> Path:
    run_dir = runs_dir / run_id / "20260825T000000000"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    (runs_dir / run_id / "latest.txt").write_text("20260825T000000000", encoding="utf-8")
    return run_dir


class _RecordingModel:
    """Answers both arms and keeps every (system, user) turn it was handed.

    Arm is detected by the `<hypothesis>` fence, which `build_user_turn` emits and
    `build_facts_user_turn` structurally cannot -- that absence is the whole point
    of the blind path.
    """

    _SHOWN = (
        "</think> VERDICT: supports\nCONFIDENCE: 0.8\n"
        "RATIONALE: repeated interactive logons for one account.\n"
        "OBSERVATIONS:\n- two 4624 logons ten seconds apart [auth_events#1]\n"
        "CITATIONS: auth_events#1"
    )
    _BLIND = (
        "</think> OBSERVATIONS:\n- two 4624 logons ten seconds apart [auth_events#1]\n"
        "CONFIDENCE: 0.7\nRATIONALE: a cached interactive logon and an unlock.\n"
        "CITATIONS: auth_events#1"
    )

    def __init__(self) -> None:
        self.turns: list[tuple[str, str, str]] = []

    @property
    def calls(self) -> int:
        return len(self.turns)

    def invoke(self, system: str, user: str) -> AnalystResponse:
        arm = "shown" if "<hypothesis>" in user else "blind"
        self.turns.append((arm, system, user))
        return AnalystResponse(
            generation=self._SHOWN if arm == "shown" else self._BLIND,
            prompt_tokens=100,
            generation_tokens=20,
            stop_reason="stop",
        )


def _evidence_of(user_turn: str) -> str:
    match = _EVIDENCE_RE.search(user_turn)
    assert match is not None, "user turn carried no <evidence> fence"
    return match.group(1)


class TestPackOnly:
    def test_calls_no_model_and_still_records_the_evidence(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        model = _RecordingModel()

        report = compare_run("case-1", pack_only=True, model=model)

        assert model.calls == 0
        assert report.samples == []
        assert report.hypothesis is None
        by_domain = {d.domain: d.evidence for d in report.domains}
        assert set(by_domain) == {"identity", "network", "endpoint"}
        # The discriminating pair the whole re-test exists to check.
        assert "code=4624 logon_type=11" in by_domain["identity"].evidence_text
        assert "auth_events#1" in by_domain["identity"].valid_citation_ids
        assert by_domain["network"].has_evidence is False

    def test_needs_no_hypothesis(self, tmp_path, monkeypatch):
        """The gate step must run for a run whose prose was never recorded."""
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs, run_id="prose-unknown")

        report = compare_run("prose-unknown", pack_only=True)

        assert report.pack_only is True
        assert report.hypothesis is None


class TestSampling:
    def test_every_draw_of_both_arms_reaches_the_artifact(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        model = _RecordingModel()

        report = compare_run(
            "case-1", hypothesis=_HYPOTHESIS, samples_per_arm=3, model=model
        )

        # identity and endpoint carry evidence: 2 arms x 3 draws each. network is
        # empty, so both arms short-circuit and are drawn once.
        assert model.calls == 2 * (2 * 3)
        counts: dict[tuple[str, str], int] = {}
        for sample in report.samples:
            key = (sample.domain, sample.arm)
            counts[key] = counts.get(key, 0) + 1
        assert counts[("identity", "shown")] == 3
        assert counts[("identity", "blind")] == 3
        assert counts[("network", "shown")] == 1
        assert counts[("network", "blind")] == 1

    def test_the_blind_arm_records_no_stance_and_the_shown_arm_does(
        self, tmp_path, monkeypatch
    ):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)

        report = compare_run(
            "case-1", hypothesis=_HYPOTHESIS, samples_per_arm=1, model=_RecordingModel()
        )

        blind = [s for s in report.samples if s.arm == "blind"]
        shown = [s for s in report.samples if s.arm == "shown"]
        assert blind and all(s.stance is None for s in blind)
        assert any(s.stance is not None for s in shown)

    def test_both_arms_are_shown_the_same_evidence(self, tmp_path, monkeypatch):
        """The claim the whole comparison rests on: same evidence, two framings.

        If the arms were ever packed differently, any divergence between them
        would be a difference in what they saw, not in how they read it -- which
        is precisely the failure the original demo turned out to be.
        """
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        model = _RecordingModel()

        report = compare_run(
            "case-1", hypothesis=_HYPOTHESIS, samples_per_arm=2, model=model
        )

        packed = {d.domain: d.evidence.evidence_text for d in report.domains}
        seen: dict[str, set[str]] = {}
        for arm, system, user in model.turns:
            # The system prompt names the domain; the identity bodies are the only
            # ones mentioning the authentication analyst.
            domain = (
                "identity"
                if "identity and authentication analyst" in system
                else "endpoint"
                if "endpoint and host-forensics analyst" in system
                else "network"
            )
            seen.setdefault(domain, set()).add(_evidence_of(user))
        for domain, texts in seen.items():
            assert len(texts) == 1, f"{domain} was packed more than one way"
            assert texts.pop() == packed[domain]
        # And the hypothesis really is absent from every blind turn.
        assert all(
            _HYPOTHESIS not in user for arm, _system, user in model.turns if arm == "blind"
        )

    def test_an_unconfigured_model_is_refused_rather_than_measured_empty(
        self, tmp_path, monkeypatch
    ):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        monkeypatch.delenv("SMARTOPS_ANALYST_MODEL_ARN", raising=False)
        _save(_report(), runs)

        with pytest.raises(NotConfigured, match="SMARTOPS_ANALYST_MODEL_ARN"):
            compare_run("case-1", hypothesis=_HYPOTHESIS)


class _EchoingModel(_RecordingModel):
    """The shown arm's read follows whatever the hypothesis told it to look for.

    A stand-in for a maximally anchored analyst: it lifts a keyword out of the
    hypothesis it was handed and reports that. Nothing about the evidence changes
    between conditions, so an anchoring test that cannot detect THIS is broken.
    """

    _KEYWORDS = ("spraying", "cryptomining", "routine")

    def invoke(self, system: str, user: str):
        arm = "shown" if "<hypothesis>" in user else "blind"
        self.turns.append((arm, system, user))
        if arm == "blind":
            return AnalystResponse(
                generation=self._BLIND, prompt_tokens=100, generation_tokens=20,
                stop_reason="stop",
            )
        found = next((k for k in self._KEYWORDS if k in user), "nothing")
        return AnalystResponse(
            generation=(
                f"</think> VERDICT: supports\nCONFIDENCE: 0.9\n"
                f"RATIONALE: the evidence indicates {found}.\n"
                f"OBSERVATIONS:\n- clear signs of {found} in these rows [auth_events#1]\n"
                f"CITATIONS: auth_events#1"
            ),
            prompt_tokens=100,
            generation_tokens=20,
            stop_reason="stop",
        )


_VARIANTS = {
    "spraying": "The account was compromised by password spraying against it",
    "cryptomining": "The host was compromised by cryptomining malware on it",
    "benign": "The activity is routine and nothing anomalous happened at all",
}


class TestAnchoringMode:
    """The measurement the arm-vs-arm comparison cannot make.

    Comparing shown against blind confounds anchoring with the prompts simply
    being different, and the blind arm cannot be anchored at all -- it never
    receives a hypothesis. Anchoring is a claim about the shown arm alone: that
    its read of FIXED evidence moves when the hypothesis moves.
    """

    def test_every_condition_sees_byte_identical_evidence(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        model = _EchoingModel()

        report = compare_run(
            "case-1", variants=_VARIANTS, samples_per_arm=2, model=model
        )

        assert report.mode == "anchoring"
        identity_turns = [
            _evidence_of(user)
            for _arm, system, user in model.turns
            if "identity and authentication analyst" in system
        ]
        assert len(set(identity_turns)) == 1, "the hypothesis must be the ONLY difference"

    def test_the_hypothesis_is_the_only_thing_that_differs(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        model = _EchoingModel()

        compare_run("case-1", variants=_VARIANTS, samples_per_arm=1, model=model)

        shown = [user for arm, _s, user in model.turns if arm == "shown"]
        for prose in _VARIANTS.values():
            assert any(prose in user for user in shown), f"{prose!r} was never sent"

    def test_an_anchored_read_is_detected(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)

        report = compare_run(
            "case-1", variants=_VARIANTS, samples_per_arm=3, model=_EchoingModel()
        )

        identity = next(a for a in report.anchoring if a.domain == "identity")
        assert identity.read_tracks_hypothesis is True
        assert set(identity.variants) == set(_VARIANTS)
        assert identity.blind_control is not None

    def test_a_read_that_ignores_the_hypothesis_is_not_flagged(
        self, tmp_path, monkeypatch
    ):
        """The control on the control: `_RecordingModel` answers identically
        whatever it is told, so no anchoring must be reported."""
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)

        report = compare_run(
            "case-1", variants=_VARIANTS, samples_per_arm=3, model=_RecordingModel()
        )

        identity = next(a for a in report.anchoring if a.domain == "identity")
        assert identity.read_tracks_hypothesis is False

    def test_the_blind_arm_is_the_control_not_a_condition(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)

        report = compare_run(
            "case-1", variants=_VARIANTS, samples_per_arm=2, model=_EchoingModel()
        )

        blind = [s for s in report.samples if s.arm == "blind"]
        assert blind, "the control must still be sampled"
        assert all(s.hypothesis_label is None for s in blind)
        identity = next(a for a in report.anchoring if a.domain == "identity")
        assert "blind" not in identity.variants

    def test_one_hypothesis_is_not_an_anchoring_test(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)

        report = compare_run(
            "case-1",
            hypothesis=_HYPOTHESIS,
            variants={"only": _HYPOTHESIS},
            samples_per_arm=1,
            model=_RecordingModel(),
        )

        assert report.mode == "arms"


class TestVariantResolution:
    def test_labels_are_parsed_and_bare_prose_is_numbered(self):
        variants, source = blind_compare.resolve_variants(
            "whatever", ["spray=an account was sprayed", "a bare hypothesis"]
        )

        assert variants == {
            "spray": "an account was sprayed",
            "h2": "a bare hypothesis",
        }
        assert "command line" in source

    def test_a_run_with_no_variants_is_refused(self):
        with pytest.raises(NotConfigured, match="No hypothesis variants"):
            blind_compare.resolve_variants("unknown-run", None)

    def test_the_seeded_case_carries_opposing_variants(self):
        variants, source = blind_compare.resolve_variants("cli-20260823T112627", None)

        assert len(variants) >= 2
        assert "CASES" in source
        # The point of the variants: they must pull in different directions, or
        # a stable read across them proves nothing.
        assert "spraying" in variants and "benign" in variants


class _FailingModel:
    """Every call raises, the way an AccessDenied credential fault does."""

    def invoke(self, system: str, user: str):
        raise RuntimeError("AccessDeniedException: resource ARN is from a different account")


class TestAllCallsFailingIsNotAMeasurement:
    """Both arms contain their own failures, so a total outage produces a
    structurally complete artifact and used to exit 0. It must not."""

    def test_is_measurement_is_false_and_the_failures_are_counted(
        self, tmp_path, monkeypatch
    ):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)

        report = compare_run(
            "case-1", hypothesis=_HYPOTHESIS, samples_per_arm=2, model=_FailingModel()
        )

        intended, failed = report.call_counts()
        assert intended == failed == 2 * (2 * 2)
        assert report.is_measurement() is False
        identity = next(d for d in report.domains if d.domain == "identity")
        assert identity.arms["shown"].failed_calls == 2

    def test_the_cli_exits_non_zero(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        monkeypatch.setattr(
            "smartops.blind_compare.analyst_model_from_env", lambda: _FailingModel()
        )

        exit_code = blind_compare._run(
            [
                "--run", "case-1",
                "--hypothesis", _HYPOTHESIS,
                "--samples", "1",
                "--out", str(tmp_path / "out" / "c.json"),
            ]
        )

        assert exit_code == 1

    def test_a_successful_run_exits_zero(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        monkeypatch.setattr(
            "smartops.blind_compare.analyst_model_from_env", lambda: _RecordingModel()
        )

        exit_code = blind_compare._run(
            [
                "--run", "case-1",
                "--hypothesis", _HYPOTHESIS,
                "--samples", "1",
                "--out", str(tmp_path / "out" / "c.json"),
            ]
        )

        assert exit_code == 0


class TestResolution:
    def test_a_bare_case_id_resolves_through_latest_txt(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        expected = _save(_report(), runs)

        assert resolve_run_dir("case-1") == expected

    def test_a_run_with_no_report_raises(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        (runs / "empty" / "20260825T000000000").mkdir(parents=True)

        with pytest.raises(FileNotFoundError, match="No report.json"):
            resolve_run_dir("empty")

    def test_a_legacy_report_with_no_scope_and_no_case_entry_is_refused(
        self, tmp_path, monkeypatch
    ):
        """Better to refuse than to invent a scope.

        `route()` needs one, and the scope decides which domains untagged result
        sets reach -- so guessing it would silently change what each analyst saw.
        """
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        legacy = json.loads(_report().model_dump_json())
        legacy["scope"] = None
        run_dir = runs / "legacy" / "20260825T000000000"
        run_dir.mkdir(parents=True)
        (run_dir / "report.json").write_text(json.dumps(legacy), encoding="utf-8")

        with pytest.raises(NotConfigured, match="no blind_compare.CASES entry"):
            compare_run("legacy", hypothesis=_HYPOTHESIS, pack_only=True)


class TestArtifactWriting:
    def test_refuses_to_write_inside_the_run_fixture_tree(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        report = compare_run("case-1", pack_only=True)

        with pytest.raises(ValueError, match="run fixture tree"):
            write_artifact(report, runs / "case-1" / "compare.json")

    def test_writes_json_and_a_markdown_sibling(self, tmp_path, monkeypatch):
        runs = tmp_path / "runs"
        monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(runs))
        _save(_report(), runs)
        report = compare_run("case-1", pack_only=True)

        json_path, md_path = write_artifact(report, tmp_path / "out" / "compare.json")

        assert json.loads(json_path.read_text(encoding="utf-8"))["run_id"] == "case-1"
        assert md_path.name == "compare.md"
        assert "code=4624 logon_type=11" in md_path.read_text(encoding="utf-8")


def _sample(arm: str, index: int, observations: list[str], citations: list[str]) -> ArmSample:
    return ArmSample(
        arm=arm,
        domain="identity",
        sample_index=index,
        model_called=True,
        stance="supports" if arm == "shown" else None,
        confidence=0.8,
        rationale="",
        observations=observations,
        citations=citations,
        prompt_tokens=1,
        generation_tokens=1,
    )


def _evidence() -> DomainEvidence:
    return DomainEvidence(
        domain="identity",
        has_evidence=True,
        evidence_text="# auth_events#1\nrow",
        valid_citation_ids={"auth_events#1": []},
        estimated_tokens=5,
        truncated=False,
        siem_set_count=1,
        untagged_set_count=0,
        vt_verdict_count=0,
        total_rows=1,
    )


class TestDecisionRule:
    def test_arms_that_agree_with_themselves_and_not_each_other_diverge(self):
        legitimate = ["legitimate local logins by the account owner"]
        spraying = ["password spraying against many accounts"]
        samples = [
            _sample("shown", 1, legitimate, ["auth_events#1"]),
            _sample("shown", 2, legitimate, ["auth_events#1"]),
            _sample("blind", 1, spraying, ["auth_events#1"]),
            _sample("blind", 2, spraying, ["auth_events#1"]),
        ]

        comparison = compare_domain(_evidence(), samples)

        assert comparison.diverges_beyond_noise is True

    def test_arms_as_noisy_within_as_between_do_not(self):
        samples = [
            _sample("shown", 1, ["cached interactive logon observed"], ["auth_events#1"]),
            _sample("shown", 2, ["password spraying against many accounts"], ["auth_events#1"]),
            _sample("blind", 1, ["cached interactive logon observed"], ["auth_events#1"]),
            _sample("blind", 2, ["password spraying against many accounts"], ["auth_events#1"]),
        ]

        comparison = compare_domain(_evidence(), samples)

        assert comparison.diverges_beyond_noise is False

    def test_a_single_draw_per_arm_yields_no_verdict_at_all(self):
        """The original comparison's exact shape, and why it settled nothing."""
        samples = [
            _sample("shown", 1, ["legitimate local logins"], ["auth_events#1"]),
            _sample("blind", 1, ["password spraying"], ["auth_events#1"]),
        ]

        comparison = compare_domain(_evidence(), samples)

        assert comparison.diverges_beyond_noise is None
        assert comparison.arms["shown"].within_arm_text_agreement is None
