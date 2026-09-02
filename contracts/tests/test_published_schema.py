"""The published JSON Schema must not drift from the models it describes.

`contracts/schemas/hypothesis-findings.v<N>.schema.json` is what a consumer of
`findings.json` validates against -- the Analyst Agent is a separate component,
owned elsewhere, and this file is the boundary written down. A schema file that
silently falls behind the model is worse than no schema file: a consumer that
validates green against a stale contract has been told the wrong thing
authoritatively.

So the file is generated from the models and asserted equal here. When a model
changes, this test fails and the fix is to regenerate:

    uv run python contracts/schemas/generate.py

and, if the change is breaking for a consumer, to bump `schema_version` and
publish a new `vN` file beside the old one rather than editing it in place.

**Both halves of that rule are tested.** `CURRENT` is resolved from the model's
own `schema_version`, the same way `generate.py` names its output, so this file
follows a bump automatically. `V1_PATH` is pinned to the literal v1 name and
asserted to still carry the shape v1 was published with -- because a test that
only ever looks at the current version passes just as happily when someone
bumps `schema_version` and edits the old file in place, which is the one thing
the rule forbids.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from contracts import DomainJudgement, HypothesisFindings

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
CURRENT = HypothesisFindings.model_fields["schema_version"].default
SCHEMA_PATH = SCHEMA_DIR / f"hypothesis-findings.v{CURRENT}.schema.json"
V1_PATH = SCHEMA_DIR / "hypothesis-findings.v1.schema.json"


def _published() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _v1() -> dict:
    return json.loads(V1_PATH.read_text(encoding="utf-8"))


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
        assert published["$id"].endswith(f"hypothesis-findings.v{CURRENT}.schema.json")


class TestTheConstraintsAConsumerReliesOnSurvive:
    """Field-level assertions, not just "the file matches".

    Equality above catches drift but says nothing about whether the schema is
    *useful*. These pin the properties a consumer would actually validate on --
    and, since 2026-08-31, the two it must NOT find -- so that changing one in
    the model fails here with a message naming it.
    """

    def test_the_wire_shape_carries_no_verdict(self):
        """The inverse of the guard that stood here.

        Until 2026-08-31 this pinned `disposition` as a closed enum and
        `confidence` to the unit interval -- the two properties a consumer was
        told it could rely on. The sub-analysts no longer judge, so the useful
        assertion is the opposite one: neither field may reappear on the wire,
        because a consumer that finds one has been handed a verdict this tier
        has no standing to form.
        """
        judgement = _published()["$defs"]["DomainJudgement"]["properties"]

        assert "disposition" not in judgement
        assert "confidence" not in judgement
        assert "narrative" in judgement, "the prose the analyst does produce"

    def test_v1_on_disk_still_carries_the_shape_it_was_published_with(self):
        """The half that proves the version bump was honoured rather than faked.

        Removing `disposition` and `confidence` is breaking, so it published
        `hypothesis-findings.v2.schema.json` beside v1 instead of editing v1.
        A test that looked only at the current version would pass identically
        if someone had bumped `schema_version` and overwritten v1 in place --
        which leaves a pinned consumer validating green against a file that
        changed under it, the exact failure the versioning exists to prevent.
        """
        v1 = _v1()
        judgement = v1["$defs"]["DomainJudgement"]["properties"]

        assert v1["properties"]["schema_version"]["default"] == 1
        assert set(judgement["disposition"]["enum"]) == {
            "benign", "suspicious", "malicious", "inconclusive"
        }
        assert judgement["confidence"]["minimum"] == 0.0
        assert judgement["confidence"]["maximum"] == 1.0
        assert CURRENT > 1, "a breaking change must bump `schema_version`"

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
            narrative="one account authenticated twice from 10.0.1.50.",
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
            domain="identity", narrative="two logons for bostoll.",
            observations=["x [auth_events#1]"], citations=["auth_events#1"],
        )
        empty = DomainJudgement(domain="endpoint")

        assert set(populated.model_dump()) == set(empty.model_dump())

    def test_the_three_domains_are_the_only_accepted_values(self):
        with pytest.raises(ValueError):
            DomainJudgement(domain="cloud", narrative="something happened.")


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
        # Characters, not tokens. Nothing reads this field -- it is absent from
        # `broker._digest`, every prompt, and the analyst path -- so the cap bounds
        # what a model spends OUTPUT tokens on, not anyone's context.
        assert spec["maxLength"] == 2000

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
