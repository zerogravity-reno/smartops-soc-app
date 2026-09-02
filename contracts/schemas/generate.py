"""Regenerate the published JSON Schema files from the contract models.

Run after any change to `HypothesisFindings` or the models it nests:

    uv run python contracts/schemas/generate.py

`contracts/tests/test_published_schema.py` fails when the committed file and the
models disagree, so this is not optional bookkeeping -- a drifted schema tells a
consumer the wrong thing authoritatively, which is worse than shipping none.

A BREAKING change to the shape (a removed field, a narrowed type, a dropped enum
member) means bumping `HypothesisFindings.schema_version` and publishing a new
`vN` file beside the old one, NOT editing v1 in place: the point of a versioned
artifact is that a consumer pinned to v1 keeps validating.
"""

from __future__ import annotations

import json
from pathlib import Path

from contracts import HypothesisFindings

SCHEMA_DIR = Path(__file__).resolve().parent
DIALECT = "https://json-schema.org/draft/2020-12/schema"
BASE_URI = "https://renosystems.ai/smartops/schemas"


def main() -> None:
    # Derived from the model, not hardcoded. This read `...v1.schema.json`
    # literally, so bumping `schema_version` and running the generator would have
    # overwritten v1 with the v2 shape -- silently breaking every consumer pinned
    # to v1 while doing exactly what the docstring above forbids. Deriving the
    # name means a bump publishes a new file and leaves the old ones alone,
    # without anyone having to remember to edit this line.
    version = HypothesisFindings.model_fields["schema_version"].default
    target = SCHEMA_DIR / f"hypothesis-findings.v{version}.schema.json"
    schema = HypothesisFindings.model_json_schema()
    # Pydantic emits neither, and a schema without them is not publishable: a
    # validator has to guess the dialect, and a consumer has no stable name to
    # reference. Added here rather than in the models so the models stay free of
    # publication concerns.
    schema["$schema"] = DIALECT
    schema["$id"] = f"{BASE_URI}/{target.name}"
    target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {target.relative_to(SCHEMA_DIR.parent.parent)}")


if __name__ == "__main__":
    main()
