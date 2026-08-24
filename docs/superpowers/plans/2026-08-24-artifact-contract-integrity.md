# Artifact & Contract Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every saved run artifact readable and self-describing — legacy artifacts included — so a stored assessment can be traced back to the exact evidence it rests on.

**Architecture:** Four tasks. Task 1 commits the already-verified `edr`/`ndr`, `classification`, `scope`, and `run_dir` work sitting uncommitted in the working tree. Task 2 replaces the closed string discriminator with a callable one that resolves untagged legacy payloads by shape, making the 22 currently-unreadable artifacts load. Tasks 3 and 4 add the durable citation chain: a join key on `HypothesisAssessment`, then an `evidence_id` back-reference on projected rows plus a persisted citation-to-evidence map.

**Tech Stack:** Python 3.13, pydantic 2.13.4 (the callable `Discriminator`/`Tag` API used in Task 2 was confirmed working on this exact version before this plan was written), pytest (`asyncio_mode = "auto"`), `uv` workspace.

**Spec:** This plan implements the Evidence Store findings of the 2026-08-24 code review together with the Level 1+2 artifact-linking design approved in the same session. Sibling plan, already complete: `docs/superpowers/plans/2026-08-24-analyst-grounding-integrity.md`.

## Global Constraints

- Run tests with `uv run pytest` from the **repo root** — `[tool.pytest.ini_options]` lives at `pyproject.toml:13-15` and `testpaths` covers both workspace members. Do NOT `cd` into `backend/`.
- Baseline before starting: **637 passed**. Every task must end at 637 + the tests it added, zero failures.
- **Never stage `backend/src/smartops/bench.py`.** It carries 20 lines of deliberate, pre-existing, out-of-scope changes that predate this work. It must remain uncommitted.
- **Never delete or rewrite anything under `.smartops/runs/`.** Those are real run artifacts and they are the fixture Task 2 is validated against.
- New contract fields are additive with defaults, so they must not break the reload of an artifact written before them.
- Comments in this codebase explain *why*, citing the failure that motivated them. Match that density.

---

### Task 1: Commit the verified edr/ndr, classification, scope, and run_dir work

**Files:**
- Commit (already modified — do not re-edit): `contracts/src/contracts/findings.py`, `contracts/src/contracts/subtask.py`, `contracts/src/contracts/__init__.py`, `contracts/src/contracts/analyst_task.py`, `backend/src/smartops/domains.py`, `backend/src/smartops/broker.py`, `backend/src/smartops/main.py`, `backend/tests/test_broker.py`, `backend/tests/test_domains.py`
- Explicitly excluded: `backend/src/smartops/bench.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `EdrAssessment`, `NdrAssessment` (in `contracts.findings`); `BrokerReport.scope: Scope | None`; `BrokerReport.classification: TaskClassification`; `BrokerOutcome.run_dir: Path`; `_persist_assessment(task_id, assessment, run_dir=None)`. Tasks 2–4 build on these.

- [ ] **Step 1: Confirm the tree is green before committing anything**

Run: `uv run pytest`

Expected: **637 passed**, 0 failed. If not, stop — do not commit a red tree.

- [ ] **Step 2: Confirm the four fixes actually work, by execution**

Run:

```bash
uv run python -c "
from contracts.subtask import make_answer_model, SubtaskResult
from smartops.domains import ALL_FAMILIES, spec_for
for fam in ALL_FAMILIES:
    m = spec_for(fam).assessment_model
    SubtaskResult.from_answer(task_id=f't:{fam}:x',
        answer=make_answer_model(fam, m)(status='ok', assessment=m()), evidence=[])
    print(fam, m.__name__, 'OK')
"
```

Expected: four lines — `siem SiemAssessment OK`, `edr EdrAssessment OK`, `vt VtAssessment OK`, `ndr NdrAssessment OK`. Any `ValidationError` means the working tree is not in the state this plan assumes; stop and report rather than editing.

- [ ] **Step 3: Read the diff you are about to commit**

Run: `git diff -- backend/src/smartops/broker.py backend/src/smartops/main.py backend/src/smartops/domains.py contracts/`

You are committing in-flight work you did not write. Confirm it contains only the `edr`/`ndr` assessment classes, the `classification` retype, the `scope` field, and the `run_dir` plumbing. If it contains anything else, report it instead of committing it.

- [ ] **Step 4: Commit the contracts half**

```bash
git add contracts/src/contracts/findings.py contracts/src/contracts/subtask.py contracts/src/contracts/__init__.py contracts/src/contracts/analyst_task.py
git commit -m "contracts: add Edr/Ndr assessments, type classification, carry scope on BrokerReport

Three defects found by the 2026-08-24 review, each confirmed by execution:

- DomainSpec.assessment_model defaulted to the bare Assessment for edr/ndr,
  which carries no tool_family, so SubtaskResult.from_answer() raised
  ValidationError the moment either subagent returned -- surfacing as a generic
  'subagent failed'. EdrAssessment/NdrAssessment now join the union.
- BrokerReport.classification was typed Any, so load_run_artifacts() handed back
  a plain dict and every downstream attribute access raised. The same silent
  degradation the tool_family discriminator was added to eliminate, missed on
  the sibling field.
- BrokerReport did not carry scope, but route() and analyze() both require one,
  so a reloaded report structurally could not drive the pipeline it feeds."
```

- [ ] **Step 5: Commit the backend half**

```bash
git add backend/src/smartops/domains.py backend/src/smartops/broker.py backend/src/smartops/main.py backend/tests/test_broker.py backend/tests/test_domains.py
git commit -m "broker+main: hand the run directory to _persist_assessment directly

latest.txt is written at save time but its stamp comes from report.created_at,
so two overlapping runs of one case disagree about which directory is newest.
_persist_assessment resolved its target through that stale pointer and filed
run B's assessment into run A's folder -- confirmed by execution, and
undetectable afterwards because assessment.json carries no join key. The run
directory is now carried out on BrokerOutcome.run_dir and passed in; latest.txt
remains only as a fallback."
```

- [ ] **Step 6: Verify bench.py is still uncommitted and the tree is green**

Run: `git status --short backend/src/smartops/bench.py && uv run pytest`

Expected: `M backend/src/smartops/bench.py` still listed, and **637 passed**.

---

### Task 2: Make legacy artifacts loadable via a callable discriminator

**Files:**
- Modify: `contracts/src/contracts/subtask.py` — the `findings` and `assessment` field annotations on `SubtaskResult`
- Test: `backend/tests/test_broker.py`

**Interfaces:**
- Consumes: `EdrAssessment`, `NdrAssessment` from Task 1.
- Produces: `_findings_tag(value: Any) -> str | None` and `_assessment_tag(value: Any) -> str | None`, module-private in `contracts/src/contracts/subtask.py`. No later task calls them.

**Background:** 22 of the 24 saved reports under `.smartops/runs/` were written before the `tool_family` discriminator existed. Their `findings`/`assessment` objects carry no tag, so `load_run_artifacts()` raises `ValidationError: Unable to extract tag using discriminator 'tool_family'`. An evidence store that cannot read what it wrote is the hardest thing to defend when closing the card.

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_broker.py`, inside `class TestFetchPlanAndReport`:

```python
    def test_a_report_saved_before_the_discriminator_still_loads(self, tmp_path):
        # 22 of the 24 real artifacts under .smartops/runs/ predate the
        # tool_family discriminator and raise `union_tag_not_found` on load. An
        # evidence store that cannot read what it wrote is not one, so untagged
        # payloads are resolved by shape instead.
        import json

        legacy = {
            "schema_version": 1,
            "task_id": "legacy-1",
            "hypothesis_id": "h1",
            "classification": {"tool_families": ["siem"], "rationale": "why"},
            "cost": {"spend_by_role": {}, "total_spend_micro_usd": 0,
                     "budget_remaining_micro_usd": 0},
            "results": [
                {
                    "task_id": "legacy-1:siem:t0", "status": "ok",
                    # No tool_family on either payload -- this is the legacy shape.
                    "findings": {"auth_events": [{"query": "q", "row_count": 1,
                                                  "rows": [{"user": "bostoll"}]}]},
                    "assessment": {"covered": ["auth_events"], "not_covered": []},
                    "evidence": [],
                },
                {
                    "task_id": "legacy-1:vt:t1", "status": "ok",
                    "findings": {"verdicts": [{"kind": "domain", "value": "x.com",
                                               "found": True, "malicious": 3}]},
                    "assessment": {"looked_up": 1, "not_looked_up": []},
                    "evidence": [],
                },
            ],
        }
        run_dir = tmp_path / "legacy-1" / "20260101T000000000"
        run_dir.mkdir(parents=True)
        (run_dir / "report.json").write_text(json.dumps(legacy), encoding="utf-8")

        report = load_run_artifacts(run_dir)

        assert isinstance(report.results[0].findings, SiemFindings)
        assert report.results[0].findings.auth_events[0].rows == [{"user": "bostoll"}]
        assert isinstance(report.results[0].assessment, SiemAssessment)
        assert isinstance(report.results[1].findings, VtFindings)
        assert isinstance(report.results[1].assessment, VtAssessment)
```

Add `SiemAssessment`, `VtAssessment`, `VtFindings` to that file's `from contracts import ...` line if they are not already imported.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest backend/tests/test_broker.py -k test_a_report_saved_before_the_discriminator_still_loads -v`

Expected: FAIL with `ValidationError` — `Unable to extract tag using discriminator 'tool_family'`.

- [ ] **Step 3: Add the tag resolvers**

In `contracts/src/contracts/subtask.py`, add `Discriminator` and `Tag` to the existing `from pydantic import (...)` block, then add these two functions immediately above the `SubtaskResult` class:

```python
def _findings_tag(value: Any) -> str | None:
    """Resolve which `Findings` subclass a payload is, tag or no tag.

    A plain string discriminator refuses any payload without `tool_family`,
    which is every artifact written before that field existed -- 22 of the 24
    runs saved under `.smartops/runs/`. They fail with `union_tag_not_found`,
    and an evidence store that cannot read what it wrote is not one.

    So: trust the tag when it is there, and fall back to the shape when it is
    not. The shapes are unambiguous and always have been -- `VtFindings` is the
    only member carrying `verdicts`, `SiemFindings` the only one carrying CIM
    buckets -- so this recovers the subclass exactly rather than guessing.
    Newly written artifacts always carry the tag and never reach the fallback.
    """
    if isinstance(value, dict):
        tagged = value.get("tool_family")
        if tagged:
            return str(tagged)
        return "vt" if "verdicts" in value else "siem"
    return getattr(value, "tool_family", None)


def _assessment_tag(value: Any) -> str | None:
    """Resolve which `Assessment` subclass a payload is. See `_findings_tag`.

    The legacy shapes are distinguishable the same way: `VtAssessment` is the
    only member carrying `looked_up`, `SiemAssessment` the only one carrying
    `covered`. `EdrAssessment`/`NdrAssessment` postdate the discriminator
    entirely, so they always arrive tagged -- an untagged payload predates them
    by construction and can never need to resolve to one.
    """
    if isinstance(value, dict):
        tagged = value.get("tool_family")
        if tagged:
            return str(tagged)
        if "looked_up" in value:
            return "vt"
        return "siem"
    return getattr(value, "tool_family", None)
```

- [ ] **Step 4: Switch both fields to the callable discriminator**

In `SubtaskResult`, replace the `findings` field:

```python
    findings: Annotated[
        Annotated[SiemFindings, Tag("siem")] | Annotated[VtFindings, Tag("vt")],
        Discriminator(_findings_tag),
    ] | None = Field(
        default=None,
        description=(
            "The per-family typed payload, projected from `evidence` by code. A "
            "discriminated union keyed on each subclass's `tool_family`: pydantic "
            "needs the discriminator both to dump every subclass field (a bare "
            "`Findings` annotation would dump only the base class's, silently to "
            "`{}`) and to reload one -- without it `model_validate_json()` cannot "
            "tell a saved entry was `SiemFindings` and silently reconstructs the "
            "empty base class. The discriminator is CALLABLE rather than the field "
            "name, so a payload written before `tool_family` existed is resolved by "
            "its shape instead of rejected; see `_findings_tag`."
        ),
    )
```

And the `assessment` field:

```python
    assessment: Annotated[
        Annotated[SiemAssessment, Tag("siem")]
        | Annotated[VtAssessment, Tag("vt")]
        | Annotated[EdrAssessment, Tag("edr")]
        | Annotated[NdrAssessment, Tag("ndr")],
        Discriminator(_assessment_tag),
    ] | None = Field(
        default=None,
        description=(
            "The model's own small judgement, carried over from the concrete "
            "per-family answer model `make_answer_model()` built. Same callable-"
            "discriminator reasoning as `findings` above -- a plain `Assessment` "
            "annotation would silently lose every subclass field such as "
            "`SiemAssessment.covered`, both on dump and on reload. Not decorative: "
            "a fetch plan's completion rules read `covered` / `not_covered` to "
            "judge whether a step retrieved what was asked for. `None` for a "
            "rejected or errored subtask, where no model ever ran."
        ),
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest backend/tests/test_broker.py -v`

Expected: PASS, including the pre-existing `test_load_run_artifacts_round_trips_typed_findings`.

- [ ] **Step 6: Verify against the real corpus — the point of the task**

Run:

```bash
uv run python -c "
from pathlib import Path
from smartops.broker import load_run_artifacts
ok = fail = 0
for p in sorted(Path('.smartops/runs').glob('*/*/report.json')):
    try:
        load_run_artifacts(p.parent); ok += 1
    except Exception as e:
        fail += 1; print('FAIL', p.parent.name, str(e)[:80])
print(f'loadable {ok}  failing {fail}')
"
```

Expected: `loadable 24  failing 0`. Before this task it was `loadable 2  failing 22`. If any still fail, read the error and fix the resolver — do not weaken the test.

- [ ] **Step 7: Run the full suite and commit**

Run: `uv run pytest`

Expected: **638 passed**.

```bash
git add contracts/src/contracts/subtask.py backend/tests/test_broker.py
git commit -m "contracts: resolve untagged legacy findings/assessment payloads by shape

22 of the 24 reports saved under .smartops/runs/ predate the tool_family
discriminator, so load_run_artifacts() rejected them with union_tag_not_found
-- an evidence store that cannot read what it wrote. Swap the string
discriminator for a callable one that trusts the tag when present and falls
back to the payload's shape when absent. The shapes are unambiguous: verdicts
means vt, CIM buckets mean siem. All 24 artifacts now load."
```

---

### Task 3: Give HypothesisAssessment a join key

**Files:**
- Modify: `contracts/src/contracts/reasoning.py` — `HypothesisAssessment`
- Modify: `backend/src/smartops/subagent_analysts/analyze.py` — the `HypothesisAssessment(...)` construction (currently at line 267)
- Modify: `backend/src/smartops/main.py` — `_persist_assessment`
- Test: `contracts/tests/test_reasoning.py`
- Test: `backend/tests/test_broker.py` — the existing construction site around line 1376 needs the new required field

**Interfaces:**
- Consumes: `_persist_assessment(task_id, assessment, run_dir=None)` and `BrokerOutcome.run_dir` from Task 1.
- Produces: `HypothesisAssessment.task_id: str` (required) and `HypothesisAssessment.run_id: str | None`. Task 4 does not depend on these.

**Background:** All nine `assessment.json` files on disk carry `hypothesis_id: "cli-hypothesis"` — a constant hardcoded at `main.py:558` — and no `task_id` at all. The directory path is the only thing tying a verdict to the evidence it was drawn from, which is exactly what made the misfiling in Task 1's second commit undetectable after the fact.

- [ ] **Step 1: Write the failing test**

Add to `contracts/tests/test_reasoning.py`:

```python
class TestAssessmentJoinKey:
    def test_task_id_is_required(self):
        # Every assessment.json on disk carried hypothesis_id "cli-hypothesis" --
        # a hardcoded constant -- and no task_id, so the directory path was the
        # only link back to the report. That is what made a misfiled assessment
        # undetectable.
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HypothesisAssessment(
                hypothesis_id="h1", overall_stance="supports", confidence=0.5
            )

    def test_run_id_defaults_to_none_and_round_trips(self):
        a = HypothesisAssessment(
            task_id="cli-1", hypothesis_id="h1",
            overall_stance="supports", confidence=0.5,
        )
        assert a.run_id is None
        stamped = a.model_copy(update={"run_id": "20260101T000000000"})
        back = HypothesisAssessment.model_validate_json(stamped.model_dump_json())
        assert back.task_id == "cli-1"
        assert back.run_id == "20260101T000000000"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest contracts/tests/test_reasoning.py -k TestAssessmentJoinKey -v`

Expected: both FAIL — the first because construction succeeds without `task_id` and no `ValidationError` is raised, the second on the unknown `run_id` field.

- [ ] **Step 3: Add the fields**

In `contracts/src/contracts/reasoning.py`, inside `HypothesisAssessment`, directly after `schema_version`:

```python
    task_id: str = Field(
        min_length=1,
        description=(
            "The `BrokerReport.task_id` this assessment was drawn from -- the join "
            "key back to `report.json`. Required, and deliberately so: every "
            "assessment.json written before this field carried only a hardcoded "
            "`hypothesis_id` of 'cli-hypothesis', which left co-location in a "
            "directory as the sole link between a verdict and its evidence. An "
            "assessment that cannot name its report is not auditable."
        ),
    )
    run_id: str | None = Field(
        default=None,
        description=(
            "The timestamped run directory this assessment belongs to, stamped by "
            "`smartops.main._persist_assessment` at write time. Optional because "
            "`analyze()` legitimately does not know it -- the run directory is "
            "chosen by the persistence layer, not the analysis layer. It makes the "
            "artifact self-describing if it is ever copied out of its folder."
        ),
    )
```

- [ ] **Step 4: Populate it at the one production construction site**

In `backend/src/smartops/subagent_analysts/analyze.py`, in the `HypothesisAssessment(...)` call inside `analyze()`, add `task_id=report.task_id,` directly above the existing `hypothesis_id=report.hypothesis_id,` line.

- [ ] **Step 5: Stamp `run_id` when persisting**

In `backend/src/smartops/main.py`, inside `_persist_assessment`, replace the line that writes `assessment.json` with:

```python
        # Stamp the run directory onto the artifact. The analysis layer cannot
        # know it -- the persistence layer chooses it -- so it is set here, and
        # it makes the file self-describing if it is ever copied out of its
        # folder.
        stamped = assessment.model_copy(update={"run_id": run_dir.name})
        (run_dir / "assessment.json").write_text(
            stamped.model_dump_json(indent=2), encoding="utf-8"
        )
```

If `run_dir` at that point is a `str` rather than a `Path`, wrap it: `run_dir = Path(run_dir)` at the top of the function.

- [ ] **Step 6: Fix the other construction site**

Run: `uv run pytest`

The existing test near `backend/tests/test_broker.py:1376` constructs a `HypothesisAssessment` without `task_id` and will now fail. Add `task_id="..."` to it, matching the `task_id` that test's report uses. Do **not** make the field optional to avoid this — the requirement is the point of the task.

- [ ] **Step 7: Run the full suite and commit**

Run: `uv run pytest`

Expected: **640 passed**.

```bash
git add contracts/src/contracts/reasoning.py backend/src/smartops/subagent_analysts/analyze.py backend/src/smartops/main.py contracts/tests/test_reasoning.py backend/tests/test_broker.py
git commit -m "contracts+main: give HypothesisAssessment a join key back to its report

Every assessment.json on disk carried hypothesis_id 'cli-hypothesis' -- a
constant hardcoded in main.py -- and no task_id, so co-location in a directory
was the only thing tying a verdict to the evidence it rested on. That is what
made a misfiled assessment undetectable after the fact. task_id is now required
and set from the report; run_id is stamped by the persistence layer, which is
the only layer that knows it."
```

---

### Task 4: Make stored citations resolve to evidence

**Files:**
- Modify: `contracts/src/contracts/subtask.py` — add the shared `evidence_id()` helper
- Modify: `contracts/src/contracts/findings.py` — `ResultSet`, `VtVerdict`
- Modify: `contracts/src/contracts/reasoning.py` — `AnalystVerdict`
- Modify: `backend/src/smartops/subagents/__init__.py` — `_EvidenceCollector.evidence`, and the two `project(...)` call sites
- Modify: `backend/src/smartops/projection.py` — `project_siem`, `project_vt`, `project`
- Modify: `backend/src/smartops/subagent_analysts/packing.py` — `valid_citation_ids`
- Modify: `backend/src/smartops/subagent_analysts/analyze.py` — `_finalize`, `_finalize_finding`
- Test: `backend/tests/test_analyst_prompts.py`, `backend/tests/test_analyst_analyze.py`

**Interfaces:**
- Consumes: nothing from Tasks 2–3.
- Produces: `contracts.subtask.evidence_id(task_id: str, index: int) -> str`; `ResultSet.evidence_id: str | None`; `VtVerdict.evidence_id: str | None`; `packing.valid_citation_ids(slice_) -> dict[str, list[str]]` (**return type changes from `set[str]`**); `AnalystVerdict.citation_evidence: dict[str, list[str]]`.

**Background:** A stored citation like `connections#23` is a *position* — minted by `enumerate()` over the routed slice at pack time and never persisted. Resolving it back to rows requires re-running `route()` on the identical report with identical ordering, and if that ordering ever changes, every stored citation silently re-targets different evidence. Separately, `ResultSet` carries no back-reference to the `Evidence` it was projected from, so even the rows cannot be traced to a raw payload. The alignment that makes this fixable: `_EvidenceCollector.evidence()` mints ids from `enumerate(self.calls)`, and `project()` is handed that same `calls` list — so calls and evidence are index-aligned by construction.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_analyst_prompts.py`:

```python
def test_valid_citation_ids_maps_each_header_to_its_evidence():
    # A citation is a POSITION (`connections#23` means 'the 23rd connections set
    # in this slice'), minted by enumerate() at pack time and never stored. If
    # the routing order ever changes, every stored citation silently re-targets.
    from contracts import ResultSet, VtVerdict
    from smartops.subagent_analysts.packing import valid_citation_ids
    from smartops.subagent_analysts.routing import DomainSlice

    slice_ = DomainSlice(
        domain="network",
        siem_sets=[
            ("connections", ResultSet(query="a", row_count=0, evidence_id="t:siem:x:0")),
            ("connections", ResultSet(query="b", row_count=0, evidence_id="t:siem:x:1")),
        ],
        vt_verdicts=[VtVerdict(kind="domain", value="x.com", found=True,
                               evidence_id="t:vt:y:0")],
    )
    mapping = valid_citation_ids(slice_)

    assert mapping["connections#1"] == ["t:siem:x:0"]
    assert mapping["connections#2"] == ["t:siem:x:1"]
    # One reputation header covers every VT verdict in the slice, so it is a list.
    assert mapping["reputation#1"] == ["t:vt:y:0"]
```

Add to `backend/tests/test_analyst_analyze.py`:

```python
def test_a_verdict_records_which_evidence_its_citations_resolve_to():
    from contracts import AnalystVerdict
    from smartops.subagent_analysts.analyze import _finalize

    verdict = AnalystVerdict(
        domain="network", stance="supports", confidence=0.9,
        citations=["connections#1"], key_observations=[],
    )
    out = _finalize(verdict, {"connections#1": ["t:siem:x:0"]}, 10, 20)

    assert out.citations == ["connections#1"]
    assert out.citation_evidence == {"connections#1": ["t:siem:x:0"]}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest backend/tests/test_analyst_prompts.py::test_valid_citation_ids_maps_each_header_to_its_evidence backend/tests/test_analyst_analyze.py::test_a_verdict_records_which_evidence_its_citations_resolve_to -v`

Expected: both FAIL — the first with `ValidationError` on the unknown `evidence_id` field, the second on the unknown `citation_evidence` field.

- [ ] **Step 3: Add the shared id formula**

In `contracts/src/contracts/subtask.py`, add after `MAX_ENTITY_VALUE_LENGTH`:

```python
def evidence_id(task_id: str, index: int) -> str:
    """The id of the `index`-th evidence item collected under `task_id`.

    One formula, one place. It was previously inlined at two minting sites
    (`smartops.subagents._EvidenceCollector.evidence` and `smartops.broker`),
    and the projectors are about to become a third consumer -- three copies of
    a format string that must agree exactly, or a `ResultSet.evidence_id`
    silently points at nothing.
    """
    return f"{task_id}:{index}"
```

- [ ] **Step 4: Add the back-reference fields**

In `contracts/src/contracts/findings.py`, add to `ResultSet`:

```python
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
```

Add the same field to `VtVerdict`, with the description `"The `Evidence.id` this verdict was projected from. See `ResultSet.evidence_id`."`.

In `contracts/src/contracts/reasoning.py`, add to `AnalystVerdict`:

```python
    citation_evidence: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Each kept citation mapped to the `Evidence.id`s it resolves to, "
            "frozen when the verdict was finalised. This is what makes the "
            "grounding durable rather than merely enforced at runtime: the gate "
            "really does drop fabricated citations, but that decision was never "
            "recorded, so a stored verdict could not be traced to the rows it "
            "rested on without recomputing the routing. A list per citation "
            "because one `reputation#1` header covers every VT verdict in a slice."
        ),
    )
```

- [ ] **Step 5: Populate `evidence_id` in the collector and projectors**

In `backend/src/smartops/subagents/__init__.py`, add `from contracts.subtask import evidence_id as _evidence_id` to the imports and change `_EvidenceCollector.evidence` to use it:

```python
    def evidence(self, task_id: str, family: str, at: datetime) -> list[Evidence]:
        return [
            Evidence(
                id=_evidence_id(task_id, index),
                tool_family=family,  # type: ignore[arg-type]
                raw={"tool": call.tool, "query": call.query, "result": call.payload},
                collected_at=at,
            )
            for index, call in enumerate(self.calls)
        ]
```

In `backend/src/smartops/projection.py`, add the same import. Give `project_siem(calls, queries_run, task_id)`, `project_vt(calls, task_id)`, and `project(family, calls, queries_run, task_id)` the new parameter, with `project` passing it through. Inside `project_siem`, change the loop header to `for index, call in enumerate(calls):` and build the result set as:

```python
        result_set = ResultSet(
            query=call.query or f"<{call.tool}: query not recoverable from tool input>",
            row_count=len(rows),
            rows=rows,
            # Index-aligned with `_EvidenceCollector.evidence()`, which mints ids
            # from `enumerate(self.calls)` over this same list. That alignment is
            # the entire basis of the back-reference, so both sides call the one
            # shared formula rather than keeping two copies of a format string.
            evidence_id=_evidence_id(task_id, index),
        )
```

Inside `project_vt`, change the loop header to `for index, c in enumerate(calls):` and pass `evidence_id=_evidence_id(task_id, index)` into every `VtVerdict(...)` constructed from that call — there are three such constructions (the `isinstance(v, dict)` branch, the `unknown` branch, and the counted branch).

Update the two `project(...)` call sites in `backend/src/smartops/subagents/__init__.py` (near lines 533 and 554) to pass `mission.task_id`.

- [ ] **Step 6: Make `valid_citation_ids` return the map**

In `backend/src/smartops/subagent_analysts/packing.py`, replace `valid_citation_ids`:

```python
def valid_citation_ids(slice_: DomainSlice) -> dict[str, list[str]]:
    """Each emitted header id mapped to the `Evidence.id`s behind it.

    Mirrors `_render`'s block order and numbering exactly, so a model citation
    is valid iff it is a key here. Returns the MAP rather than a bare set, and a
    separate parallel function was deliberately NOT added: the two would each
    have to mirror `_render` identically and would rot the first time one
    changed. Callers that want only validity use the keys, which is what a
    membership test on a dict already does.

    A list per id because one `reputation#1` header covers every VT verdict in
    the slice. An entry is `[]` when the source predates `ResultSet.evidence_id`.
    """
    ids: dict[str, list[str]] = {}
    if slice_.vt_verdicts:
        ids["reputation#1"] = [
            v.evidence_id for v in slice_.vt_verdicts if v.evidence_id
        ]
    for i, (category, result_set) in enumerate(slice_.siem_sets, start=1):
        ids[f"{category}#{i}"] = (
            [result_set.evidence_id] if result_set.evidence_id else []
        )
    for i, result_set in enumerate(slice_.untagged_sets, start=1):
        ids[f"uncategorised#{i}"] = (
            [result_set.evidence_id] if result_set.evidence_id else []
        )
    return ids
```

`pack_evidence` needs no change: it already does `ids = valid_citation_ids(slice_)` and returns `ids`, and every downstream `in` test on the result now checks the dict's keys.

- [ ] **Step 7: Record the map on the verdict**

In `backend/src/smartops/subagent_analysts/analyze.py`, retype `_finalize`'s `valid_ids` parameter from `set[str]` to `dict[str, list[str]]`, then add to its `updates` dict directly after `"citations": kept,`:

```python
        # Freeze what each kept citation resolves to. The gate already dropped
        # the fabrications; recording the survivors is what makes that decision
        # survive into assessment.json, instead of being reproducible only by
        # re-running route() with identical ordering.
        "citation_evidence": {c: list(valid_ids.get(c, [])) for c in kept},
```

Retype `_finalize_finding`'s `valid_ids` the same way. `DomainFinding` gains no map — the Aggregator cycle that would consume it does not exist yet, and adding an unread field now would be speculative.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run pytest backend/tests/test_analyst_prompts.py backend/tests/test_analyst_analyze.py -v`

Expected: PASS. Any pre-existing test asserting `valid_ids` is a `set` needs updating to compare against the dict's keys — that change is intentional; do not revert the return type.

- [ ] **Step 9: Run the full suite and commit**

Run: `uv run pytest`

Expected: **642 passed**.

```bash
git add contracts/src/contracts/findings.py contracts/src/contracts/reasoning.py contracts/src/contracts/subtask.py backend/src/smartops/projection.py backend/src/smartops/subagents/__init__.py backend/src/smartops/subagent_analysts/packing.py backend/src/smartops/subagent_analysts/analyze.py backend/tests/test_analyst_prompts.py backend/tests/test_analyst_analyze.py
git commit -m "contracts+analysts: make a stored citation resolve to its evidence

A citation was a position, not an identity: 'connections#23' meant 'the 23rd
connections set in this slice', minted by enumerate() at pack time and never
persisted -- so resolving one required re-running route() with identical
ordering, and any change to that ordering silently re-targeted every stored
citation. ResultSet and VtVerdict now carry the Evidence.id they were projected
from, valid_citation_ids returns the header-to-evidence map rather than a bare
set, and _finalize freezes that map onto the verdict. The grounding gate was
already enforced at runtime; it is now durable in the artifact."
```

---

## Done when

- `uv run pytest` reports **642 passed**, zero failures.
- All 24 artifacts under `.smartops/runs/` load — the Task 2 Step 6 command prints `loadable 24  failing 0`.
- `backend/src/smartops/bench.py` is still uncommitted.
- A freshly written `assessment.json` contains a real `task_id`, a `run_id`, and per-verdict `citation_evidence`.
