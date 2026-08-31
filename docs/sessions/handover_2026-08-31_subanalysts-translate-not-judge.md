---
date: 2026-08-31
title: The three sub-analysts translate logs into plain English. They do not judge.
---

# Handover — the sub-analyst tier stops judging

**Branch `task-broker-agent` at `3ba94af`**, 13 commits ahead of
`origin/task-broker-agent`, **856 tests passing**, tree clean, 0 stale doc anchors.
The 2026-08-30 SDD run is closed (see the two session docs dated 2026-08-30). This
handover starts new work and **no code has been written for it yet**.

## The decision

**Mohammed's architectural call, 2026-08-30/31, in his words:** the three domain
sub-analysts (identity/network/endpoint) *"essentially just translate the logs they
get into plain English … no verdict no nothing purely saying what they saw."* The
component that assigns a disposition is the **Analyst Agent** — a separate system
owned elsewhere, on the far side of the `HypothesisFindings` boundary.

This **reverses a recorded decision**, deliberately. The 2026-08-23 hypothesis-blind
design gave this tier a `Disposition` on the reasoning that "blind does not mean
silent — the analyst still judges", drawing the line only at `Stance`
(supports/refutes). **That line moves: the tier judges nothing.**

Still asserting the old position, and now wrong: `contracts/reasoning.py:39-58`,
`:133-149`, `:396-424`; `docs/architecture.md` §2/§7/§12; `README.md:27`, `:83-87`;
and `prompts.py` throughout.

CLAUDE.md says a recorded decision is settled unless "its stated premise is no longer
true." Its premise was that per-domain evidence-*reading* belongs on our side of the
boundary. **The owner has changed that premise. Do not re-litigate this; implement
it.**

### Decisions already taken — do not re-ask these

| | Decision |
|---|---|
| **Output** | Plain-English narrative **plus** cited bullets. The bullets stay so the grounding gate keeps per-claim units; without them fabricated ids get much harder to catch. |
| **`confidence`** | **Dropped.** No verdict means no referent. |
| **Schema** | **Bump to v2, keep v1 on disk.** Honours `contracts/schemas/generate.py:9-14`'s own rule. |
| **Answer key** | **Rescope to citation coverage** — did the narrative cite the row that proves the documented BOTSv3 fact? |

---

## The judgement is not only in the DISPOSITION field

**This is the part a careless reading misses.** Deleting `DISPOSITION:` is the easy
half. The prompt asks for judgement in three more places, and all of them have to go:

| Where | Why it is judgement |
|---|---|
| "Identify every **security-relevant** finding" — `prompts.py:171`, `:203`, `:237` | Relevance is a judgement. A translator has no relevance filter. |
| `WHAT TO LOOK FOR` — brute force, spraying, beaconing, DNS tunnelling, LOLBins… `:181-186`, `:214-219`, `:248-253` | A detection checklist. Telling a model which patterns matter *is* asking it to assess. |
| The word "finding", and `_FINDING_*` on every constant | A finding is a conclusion. These are accounts of rows. |

### What this dissolves

The 2026-08-30 headline bug — `_FINDING_REASK` omitting `DISPOSITION`, so a model
obeying our own template could only ever land `inconclusive` — **cannot exist** after
this change. There is nothing to omit or default. The `79af0bb` fix keeps its value as
a *pattern* (one constant, both consumers, a test pinning it), reused in T2.

---

## The three rules that must not drift

**1. Translate, do not interpret.** The sentence to check every prompt edit against:

> **Say what happened in these rows — in order, naming the hosts, accounts,
> addresses, processes and times involved. Do not say what it means, whether it is
> normal or abnormal, whether it is an attack, or who was behind it.**

All three domain bodies currently read *"do not speculate about intent, **a
narrative**, or draw any broader conclusion"* (`prompts.py:173`, `:205`, `:239`).
**The prompt currently forbids the exact thing we now want.** The reversal is
surgical: keep the prohibition on intent and broader conclusions, remove only the one
on narrative. A grep for `a narrative` must return zero.

**2. Compress by aggregating, never by selecting.** This is new, and the whole rework
turns on it.

A live network slice on 2026-08-30 was 46 `dns_resolutions` + 124 `connections` rows.
Those cannot be recounted line by line inside a 3,072-token generation budget. The old
prompt resolved that by *selecting* — "report every distinct security-relevant
pattern" — which is a relevance judgement, the thing we just removed. **The
replacement is aggregation:**

> Group like rows and describe the group. Give counts, distinct values, time ranges
> and the shape of any repetition. "Host ABUNGST-L opened 124 connections to 12
> distinct destinations between 03:14 and 04:02; 46 of them went to 45.77.53.176 at
> roughly 60-second intervals" accounts for every row without picking a winner. Never
> drop a set because it looks uninteresting — say what it contains.

Aggregation describes the whole set. Selection picks favourites. Only the first is
translation.

**3. Truncation is a fidelity problem now.** `formatting.py:293-300` prints the header
as `# {category}#{index} · rows={true_total}` and appends `… (N more rows not shown)`
when the row cap bites. The prompt explains **only** `rows=0` (`prompts.py:179`,
`:212`, `:245`). A translator shown 20 lines under `rows=4000` will write "there were
20 connections" and be wrong. Under the old judgement framing that was tolerable —
you judge what you see. It is not tolerable now. **Add to each body:** `rows=N` is the
true count; fewer lines may be printed; when they are, say you are describing a sample
of N and give the number.

---

## T1 — contracts and the published schema

**Files:** `contracts/src/contracts/reasoning.py`, `contracts/schemas/generate.py`,
`contracts/tests/test_published_schema.py` (12 tests, 9 hits),
`contracts/tests/test_reasoning.py` (11 tests, 13 hits).

1. **`DomainFinding`** (`:133-200`): delete `disposition` and `confidence`. **Rename
   `rationale` → `narrative`**, described as the plain-English account of the rows —
   explicitly not a reading of what they mean. Do **not** add `narrative` beside
   `rationale`; one prose field, or we ship the duplication CLAUDE.md says to extract.
   Survivors: `domain`, `narrative`, `observations`, `citations`, `citation_evidence`,
   `reasoning_trace`, `prompt_tokens`, `generation_tokens`.
2. **`DomainJudgement`** (`:297-323`): same deletions and rename. **(D-E — the name.
   "Judgement" is now exactly wrong, and a name that says judgement is a drift vector.
   Recommendation: rename the wire shape to `DomainNarrative` — v2 is already
   breaking, and the wire name is what the other team reads — while leaving
   `DomainFinding` and `HypothesisFindings` as they are, because renaming those churns
   856 tests for no external benefit. Mixed naming is the cheaper wrong than either
   extreme; record the reasoning.)**
3. **`Disposition`** (`:39-58`): **keep the type, rewrite the docstring** as the
   vocabulary *the Analyst Agent decides in* — declared here because this is the
   shared contract package, not because this tier emits it. **(D-B — a reviewer may
   argue for deletion. Deleting it leaves the consumer's decision space undefined and
   removes the `Stance`/`Disposition` contrast, still the clearest statement of why
   this tier is blind.)**
4. **`HypothesisFindings`** (`:396-481`): the docstring asserts "An empty domain is
   reported as `inconclusive` with no observations." Rewrite: an empty domain appears
   with an **empty narrative and no observations**, and **`RetrievalSummary` is now
   the only signal** separating "we looked and found nothing" from "we did not look."
   That field exists for precisely this reason (`:350-365`) — this change makes it
   load-bearing rather than supplementary. Say so in as many words.
5. **Schema v2.** `schema_version: int = 1` → `2`. `generate.py:30` hardcodes the v1
   filename — derive it from the model's `schema_version` default so a future bump
   cannot forget the file. Emit v2; **leave v1 byte-identical on disk.**
6. **`test_published_schema.py:74-77`** (`test_disposition_is_a_closed_enum`) — do not
   just delete it. Replace with the inverse guard: the wire shape has **no**
   `disposition` and **no** `confidence`, **and v1 on disk still does**. That second
   half is what proves the version bump was honoured rather than faked.

---

## T2 — the prompt rewrite (largest task, highest drift risk)

**File:** `backend/src/smartops/subagent_analysts/prompts.py`. Tests:
`test_analyst_prompts.py` (43 tests, 14 hits).

1. **`_FINDING_ANSWER_BLOCK`** (`:98-120`) stays a single constant shared by the first
   ask and the re-ask — that is the `79af0bb` pattern and why the re-ask can no longer
   diverge. New content:

   ```
   NARRATIVE: <plain English: what these rows show, in order, naming the hosts,
   accounts, addresses and times. Group like rows and give counts. What happened,
   not what it means.>
   OBSERVATIONS:
   - <one distinct thing the rows state> [header_id]
   - <one line per distinct thing; repeat as many times as you have>
   CITATIONS: <comma-separated full header ids you actually used, e.g. auth_events#1>
   ```

   The bullets are now "one distinct thing the rows state", not "a security-relevant
   finding". They exist for the grounding gate, not for triage.
2. **Delete `JUDGING WHAT YOU SEE` and `CHOOSING BETWEEN suspicious AND
   inconclusive`** (`:149-165`) outright.
3. **Delete `WHAT TO LOOK FOR` from all three bodies** (`:181-186`, `:214-219`,
   `:248-253`). A detection checklist is judgement. Largest single deletion; frees
   real budget.
4. **Keep `EVIDENCE YOU RECEIVE`** (`:177-180`, `:209-213`, `:242-246`) and treat it
   as the most important block in the prompt — a translator needs the field glossary
   more than a judge did. Extend it per rule 3 above.
5. **Keep `GROUNDING RULES`**, reframed: citation fidelity matters more, not less. One
   line needs rewriting — "If none of the patterns above are present, say so
   explicitly" references the list deleted in item 3.
6. **Rewrite each opening line.** "act as the identity and authentication analyst …
   Identify every security-relevant finding" → the translator framing, plus rule 2's
   aggregation instruction.
7. **Rework `HOW MUCH TO REPORT`** (`:137-147`). Its dedup rules were measured and are
   worth keeping for `OBSERVATIONS`; the 10-item ceiling now bounds *distinct
   groupings* rather than relevance, so re-derive and re-word it. Give the narrative
   its own length discipline — "account for every set" and "write plain English" pull
   in opposite directions, and the model will resolve that badly if we leave it
   implicit.
8. **Do not touch `_FACTS_SECURITY_BLOCK`** (`:69-74`). Verified: it is
   prompt-injection defence — untrusted-data framing — not judgement.
9. **Leave the ~250-token Metis vendor preamble alone** (recorded twice).
10. **Rename `_FINDING_*` → `_NARRATIVE_*`** across the module's private constants.
    Cheap, module-private, and directly serves the "easy to read and follow" goal.
11. **THE ANTI-DRIFT TEST.** Extend the existing blind-guarantee test rather than
    adding a parallel one: render all three prompts and assert **zero** occurrences of
    `DISPOSITION`, `CONFIDENCE`, `benign`, `suspicious`, `malicious`, `inconclusive`
    **and `security-relevant`**, alongside the existing zero for
    `hypothesis`/`supports`/`refutes`. This test is the cheapest thing standing
    between this decision and its slow reversal.

**Budget:** items 2–3 free a large amount of system-prompt reserve. `packing.py`'s
`_SYSTEM_PROMPT_RESERVE` is measured at import, so margins recompute — but the
derivation test asserts specific values (identity 577 / network 500 / endpoint 590)
and **will fail**. That failure is correct. Re-measure and update the assertion; do
not loosen it. More evidence now fits per call, which is the right direction for a
translator.

---

## T3 — parse and analyze

**Files:** `parse.py`, `analyze.py`. Tests: `test_analyst_parse.py` (38 tests, 54
hits), `test_analyst_analyze.py` (54 tests, 54 hits) — the bulk of the rewrite.

1. **`parse.py`**: delete `_DISPOSITION_RE` (`:100`), `_DISPOSITION_KEYWORDS`
   (`:107-114`), `_normalise_disposition` (`:117-132`), `_CONFIDENCE_RE` (`:34`) and
   the confidence clamp (`:187-189`). In `parse_finding` (`:159-213`) delete the
   disposition extraction **and the `inconclusive` default at `:207`** — the line that
   manufactured the 2026-08-30 wrong verdict. Add `NARRATIVE:` extraction.
   **Recommendation: a missing narrative raises `FindingParseError`**, joining
   OBSERVATIONS and CITATIONS. The narrative is now the product; defaulting it to `""`
   is the same failure mode as the disposition default, one field over.
2. **`_apply_grounding`** (`analyze.py:264-321`) is shared with `shown.py`, which
   **keeps `Stance` and `confidence`**. Do not strip the downgrade arm from the shared
   function. Parameterise instead: it already takes `observations_field`,
   `stance_field` and `decisive`; add a `prose_field` (the note at `:320` hardcodes
   `rationale`) and let the blind caller pass no `stance_field`, skipping the downgrade
   arm.
3. **`_finalize_finding`** (`:423-460`): keep the citation-drop arm; its downgrade arm
   has nothing left to downgrade. **(D-A — what an all-citations-fabricated narrative
   becomes. Recommendation: keep the narrative, append the existing `[downgraded: no
   cited evidence resolved]` note, and let `observations: []` / `citations: []` /
   `exhibits: []` tell the consumer. Do not blank it — it is the audit record of what
   the model claimed. A reviewer should push back if ungrounded prose crossing the
   boundary is worse than losing it.)**
4. **`_as_judgement`** (`:463-519`): drop the two field copies (`:513-514`). Its
   zero-row warning (`:497-509`) keys off `disposition != "inconclusive"` — re-key to
   "has observations but every exhibit has zero rows", the same defect without needing
   a verdict.
5. **Empty-slice short-circuit** (`:368-373`): relies on `disposition`'s
   `inconclusive` default. Return an empty narrative and empty observations, and make
   sure `RetrievalSummary` carries the reason (T1 item 4).
6. **`_FINDING_REASK`** (`:334-347`) needs no content edit — it imports the block.
   **Do not restate the block in `analyze.py`.**
7. **Do not touch `shown.py`.** A/B harness, keeps `Stance`/`AnalystVerdict`, and
   ruling R16 deliberately parked its internal duplication. Sweeping it in is the most
   likely scope error in this whole rework.

---

## T4 — the edges that will `AttributeError` at runtime

None are caught by type checking; two surface only on a live run.

| Site | What breaks |
|---|---|
| `main.py:452` (`_print_findings`) | Formats `disposition`/`confidence`. Reformat around the narrative. |
| `main.py:492-495` | "no overall stance… is the Analyst Agent's call" — now *more* true. Strengthen: no disposition either. |
| `main.py:562` (`_persist_reasoning_traces`) | Writes both fields into `traces.json`. |
| `telemetry.py:217-218` | Spans `analyst.disposition` / `analyst.confidence`. **(D-D — recommendation: counts instead — observations, citations, narrative length.)** |
| `blind_compare.py:824` | Reads `result.confidence` off the **blind** arm. `ArmStats.confidence_min/median/max` (`:376-378`) and the report column (`:648-662`) lose that arm. **(D-C — recommendation: `ArmSample.confidence: float \| None`, shown-arm-only columns.)** |
| `blind_compare.py:21` | Docstring premise calls confidence a comparable quantity across arms. It is not one now. |

**What replaces verdict stability as a metric.** `within_arm_citation_agreement` and
`within_arm_text_agreement` already exist and survive untouched. Disposition agreement
and confidence spread — the two figures the 2026-08-27/29 variance work reported —
become unmeasurable **because there is no verdict**, not because we stopped measuring.
Write that down rather than leaving a reader to find empty columns. Citation agreement
is arguably the better metric for a translator anyway: it measures whether two runs
read the same rows.

---

## T5 — the answer key, rescoped

**File:** `bench.py`. Tests: `test_bench.py` (42 tests, 22 hits).

`EXPECTED_DISPOSITIONS` (`:288-336`) becomes an expectation about **citation
coverage**: for each documented case, which evidence category must the narrative cite
to have seen the row that proves the BOTSv3 fact?

- `botsv3_coinhive` → network cites `dns_resolutions`
- `botsv3_c2_beacon` → network cites `connections`
- `botsv3_hdoor_tool` → endpoint cites `reputation` or `processes`

This metric gets **stronger** under pure translation: a translator instructed to
account for every set should cite every set it was shown, so citation coverage becomes
a fair test of whether it did its job rather than a proxy for a verdict.

Keep the **sparseness** (absent = BOTSv3 documents nothing; R7), the three-state
`None`/`True`/`False` discipline (R13), and the key-vs-`task_id` drift guard from
`bc3ddf5`. Rename `compute_disposition_correct` (`:639-658`) and
`RunMetrics.disposition_correct` (`:418-432`) to match what they score.

**This does not make the bench live.** `_execute_single_run` (`:726`) still calls only
`broker_task`, never the analyst tier, so the key stays `None` in practice (R13). What
changes is that it becomes scoreable *without a model verdict* — which is why
rescoping beats deleting.

---

## T6 — documentation, in the same branch as the code

The 2026-08-30 lesson, twice over: code and doc land together or the map describes
code that no longer exists.

| File | Tracked | Now false |
|---|---|---|
| `README.md:27`, `:83-87` | yes | "each emit a `Disposition`" |
| `docs/architecture.md:31-36` | yes | §2 defines the four values as this tier's output |
| `docs/architecture.md:227-230`, `:288-291` | yes | the two field tables |
| `docs/architecture.md:454-464` | yes | §12's answer-key and variance items |
| `docs/confluence-findings-pipeline-evidence-store.md:82` | yes | "downgrades an ungrounded decisive disposition" |
| `docs/confluence-subagent-analysts.md:19-33`, `:203`, `:210-212` | **NO — keep untracked** | the tier's entire stated purpose |

**Edit `docs/confluence-subagent-analysts.md` on disk and do NOT `git add` it.** This
exact mistake happened on 2026-08-30 (`8cc2e05`, reverted by `b4ab05d`, ruling R14): a
task brief listed it as writable without saying "do not commit it". Whether it belongs
in git is Mohammed's open call.

Then:

    uv run python docs/check_anchors.py docs/architecture.md docs/confluence-*.md
    uv run python docs/compile_docs.py

**PROJECT_DOCS supersession.** `PROJECT_DOCS.md` carries 28 sessions asserting this
tier judges evidence, and CLAUDE.md tells readers to consult it before proposing
changes. Both this handover and the closing session doc must state the reversal
explicitly. This branch has already been bitten by exactly this twice.

---

## Verification

1. `uv run pytest` from the root. **Baseline 856.** Expect a large drop-then-recover
   across T1–T3; everything remaining must pass. A failure in a `gather`/blind test
   after T3 means the cut went too deep.
2. `uv run python contracts/schemas/generate.py` → v2 written, and
   `git diff --exit-code contracts/schemas/hypothesis-findings.v1.schema.json` clean.
3. **The anti-drift test** (T2.11): zero judgement vocabulary in any rendered prompt;
   blind guarantee still zero for `hypothesis`/`supports`/`refutes`.
4. **Grep for orphans:** `disposition`, `Disposition`, `confidence`,
   `security-relevant` across `backend/src` and `contracts/src`. Expected survivors
   and nowhere else: `shown.py`, `blind_compare.py` (shown arm),
   `contracts/reasoning.py` (`Stance`, `AnalystVerdict`, `HypothesisAssessment`, and
   `Disposition`'s declaration per D-B).
5. **Replay a saved run — no Splunk, no model.** `load_run_artifacts()` over a case in
   `backend/.smartops/runs/`, then `route()`, and assert citations still resolve.
   **Never write under `.smartops/runs/`** — point `SMARTOPS_RUNS_DIR` at a scratch
   directory and verify the tree afterwards (15 run directories).
6. `check_anchors.py` over the wider set — 0 stale, **after** T6.
7. `git status` — no `.env`, no `.smartops/`, and
   `docs/confluence-subagent-analysts.md` still `??`.
8. **Live run — the only step that proves it worked.** Needs `.env` and
   `SMARTOPS_ANALYST_MODEL_ARN`; use `env -u AWS_PROFILE` (an empty `AWS_PROFILE`
   reads as a profile literally named `""` and has already produced one false "no
   credentials" conclusion). Then read each narrative and answer three questions no
   test can answer:
   - Does it recount the rows, or has it started explaining what they mean?
   - Does it account for **every** set it was shown, or has it quietly gone back to
     picking the interesting ones?
   - When a set was truncated, does it say it is describing a sample of N?

## Open decisions for the implementer or reviewer

- **D-A** — what an all-citations-fabricated narrative becomes (T3.3).
- **D-B** — keep or delete the `Disposition` type in contracts (T1.3).
- **D-C** — `blind_compare` confidence columns: shown-arm-only, or removed (T4).
- **D-D** — telemetry attributes replacing `analyst.disposition`/`.confidence` (T4).
- **D-E** — rename `DomainJudgement` on the wire (T1.2).
- **Worth stating plainly in the docs, not an objection:** if the tier only
  translates, what does it add over handing the Analyst Agent `evidence.json`
  directly? The defensible answer, and the one the design should record, is that it
  compresses ~170 rows into prose that fits the consumer's own context budget, every
  claim is citation-checked by the grounding gate, and three domains run concurrently.
  If that answer stops being true, the tier is a pass-through.
- **Carried, unresolved:** does `docs/confluence-subagent-analysts.md` belong in git?
  (R14)
