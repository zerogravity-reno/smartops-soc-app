"""The published JSON Schema must not drift from the models it describes.

`contracts/schemas/hypothesis-findings.v1.schema.json` is what a consumer of
`findings.json` validates against -- the Analyst Agent is a separate component,
owned elsewhere, and this file is the boundary written down. A schema file that
silently falls behind the model is worse than no schema file: a consumer that
validates green against a stale contract has been told the wrong thing
authoritatively.

So the file is generated from the models and asserted equal here. When a model
changes, this test fails and the fix is to regenerate:

    uv run python contracts/schemas/generate.py

and, if the change is breaking for a consumer, to bump `schema_version` and
publish a new `vN` file beside this one rather than editing it in place.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from contracts import DomainJudgement, HypothesisFindings

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "hypothesis-findings.v1.schema.json"
)


def _published() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


class TestThePublishedFileMatchesTheModels:
    def test_the_schema_file_exists(self):
        assert SCHEMA_PATH.exists(), (
            f"{SCHEMA_PATH} is missing -- regenerate with "
            "`uv run python contracts/schemas/generate.py`"
        )

    def test_it_is_identical_to_what_the_model_generates(self):
        """Compared minus the two hand-added keys, which pydantic does not emit."""
        published = _published()
        published.pop("$schema", None)
        published.pop("$id", None)

        assert published == json.loads(
            json.dumps(HypothesisFindings.model_json_schema(), sort_keys=True)
        ), (
            "the published schema has drifted from HypothesisFindings -- "
            "regenerate with `uv run python contracts/schemas/generate.py`"
        )

    def test_it_declares_a_json_schema_dialect_and_id(self):
        """A bare pydantic dump is not a publishable schema: without `$schema` a
        validator has to guess the dialect, and without `$id` a consumer has no
        stable name to reference it by."""
        published = _published()

        assert published["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert published["$id"].endswith("hypothesis-findings.v1.schema.json")


class TestTheConstraintsAConsumerReliesOnSurvive:
    """Field-level assertions, not just "the file matches".

    Equality above catches drift but says nothing about whether the schema is
    *useful*. These pin the four properties a consumer would actually validate
    on, so that loosening one in the model fails here with a message naming it.
    """

    def test_disposition_is_a_closed_enum(self):
        prop = _published()["$defs"]["DomainJudgement"]["properties"]["disposition"]

        assert set(prop["enum"]) == {"benign", "suspicious", "malicious", "inconclusive"}

    def test_confidence_is_bounded_to_the_unit_interval(self):
        prop = _published()["$defs"]["DomainJudgement"]["properties"]["confidence"]

        assert prop["minimum"] == 0.0
        assert prop["maximum"] == 1.0

    def test_the_join_keys_are_required(self):
        """`task_id` joins back to report.json and prefixes every `Evidence.id`;
        `hypothesis_id` is the claim these findings attach to. Optional either one
        and the artifact stops being resolvable."""
        assert set(_published()["required"]) >= {"task_id", "hypothesis_id"}

    def test_the_reasoning_trace_is_not_published(self):
        """`DomainFinding.reasoning_trace` is "persisted for audit, never re-fed".
        Putting a model's private chain of thought into a contract handed to
        another model is exactly re-feeding it, so its absence from the wire
        projection is a security property, not an oversight."""
        judgement = _published()["$defs"]["DomainJudgement"]["properties"]

        assert "reasoning_trace" not in judgement
        assert "prompt_tokens" not in judgement
        assert "generation_tokens" not in judgement


class TestAllThreeDomainsProduceTheSameShape:
    """The actual question behind "fixed schema output from the three subagents".

    They share one `DomainFinding` -> `DomainJudgement` projection, so identical
    shape is structural rather than coincidental. Asserted anyway, on the failure
    path as well as the success path: an analyst whose model call died is where a
    shape would most plausibly diverge, and it is the case a consumer is least
    likely to have test data for.
    """

    DOMAINS = ("identity", "network", "endpoint")

    @pytest.mark.parametrize("domain", DOMAINS)
    def test_a_populated_judgement_has_the_published_key_set(self, domain):
        judgement = DomainJudgement(
            domain=domain,
            disposition="suspicious",
            confidence=0.85,
            rationale="a read.",
            observations=["something [auth_events#1]"],
            citations=["auth_events#1"],
        )

        published_keys = set(_published()["$defs"]["DomainJudgement"]["properties"])
        assert set(judgement.model_dump().keys()) == published_keys

    def test_an_empty_domain_has_the_same_keys_as_a_populated_one(self):
        """"We looked and found nothing" must be shaped like any other judgement.
        `HypothesisFindings` requires all three domains present precisely so a
        consumer cannot mistake an empty one for an absent one."""
        populated = DomainJudgement(
            domain="identity", disposition="malicious", confidence=0.95,
            observations=["x [auth_events#1]"], citations=["auth_events#1"],
        )
        empty = DomainJudgement(domain="endpoint", disposition="inconclusive", confidence=0.0)

        assert set(populated.model_dump()) == set(empty.model_dump())

    def test_the_three_domains_are_the_only_accepted_values(self):
        with pytest.raises(ValueError):
            DomainJudgement(domain="cloud", disposition="benign", confidence=0.5)


class TestEveryAssessmentTellsTheModelWhatNoteIsFor:
    """`note` is model-authored, so its description is the only thing steering it.

    It was declared four times -- once per family subclass -- and only
    `SiemAssessment` carried a description. The other three were
    `Field(default="", max_length=400)`: identical in every ENFORCED respect and
    missing the part that does the actual work.

    The cost was measured, not theorised. Shown a bare capped string, the vt
    subagent wrote a 500-character analysis of what the reputation data MEANT and
    was rejected twice by structured-output validation before truncating into the
    limit -- two turns spent on a rule it was never shown, while that rule ("NOT a
    summary of findings") sat on a sibling class it does not inherit from.

    Now declared once on `Assessment`. These tests fail if anyone redeclares it
    without one, which is how the drift happened the first time.
    """

    @pytest.mark.parametrize(
        "model_name", ["SiemAssessment", "VtAssessment", "EdrAssessment", "NdrAssessment"]
    )
    def test_note_carries_its_guidance(self, model_name):
        import contracts

        spec = getattr(contracts, model_name).model_json_schema()["properties"]["note"]

        assert spec.get("description"), f"{model_name}.note has no description"
        assert "NOT a summary of findings" in spec["description"]
        assert spec["maxLength"] == 400

    def test_it_is_declared_exactly_once(self):
        """The enforcement. Four identical copies is how three of them lost the
        description, and a redeclaration is invisible in review because it looks
        like the field simply being present."""
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[1] / "src" / "contracts" / "findings.py"
        ).read_text(encoding="utf-8")

        assert source.count("note: str") == 1, (
            "`note` is declared more than once -- put it on `Assessment` and let the "
            "family subclasses inherit it, or the description drifts out of three of them"
        )
