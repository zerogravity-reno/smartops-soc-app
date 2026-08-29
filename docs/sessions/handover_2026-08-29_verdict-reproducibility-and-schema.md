---
date: 2026-08-29
title: The analyst verdict is reproducible now, and half the analyst layer is gone
---

# Handover — 2026-08-29: verdict reproducibility, dead-path removal, published schema

Answers the four questions Mohammed opened the session with, and lands the patching
that followed. **Four commits, `852e090..8376a0b` on `task-broker-agent`, 782 tests
passing.** Continues `handover_2026-08-27_analyst-verdict-variance.md`, whose measurement
is what made the first commit possible without re-measuring from scratch.

## The four questions, answered

**1. Is this a robust Strands solution?** Yes, on the fetch side. `subagents/__init__.py`
builds `Agent` with `structured_output_model`, hooks, `Limits`, `trace_attributes`,
`ModelRetryStrategy`, `SlidingWindowConversationManager`; MCP goes through the documented
`MCPClient.load_servers()`; `test_strands_compliance.py` pins the one private SDK import
and proves the deprecation filter fires. Two gaps, one now closed: the analyst layer is
raw boto3 and therefore produces **no OTEL spans** (still open), and its client had **no
retry config at all** (fixed — see below).

**2. Are we using Foundation-Sec-8B correctly?** Yes, and better than expected. Verified
against the model's real `tokenizer_config.json`: `<|system|>`, `<|user|>`, `<|assistant|>`,
`<think>` **are** this model's own special tokens (ids 128264–128268), not the Llama-3.1
`<|start_header_id|>` scheme. The template was right in substance and wrong by two
newlines, now fixed and pinned. Sampling was wrong for the job — see below.

**3. Are the three analysts' verdicts reliable?** They were not. They are now, on a warm
model copy. See the next section.

**4/5. Declutter + true-to-code docs.** **Not done.** This is the largest open item and
it is now urgent — see "Do this first".

## What changed

### `852e090` — the verdict is reproducible

Two causes, and they had to be fixed together.

**Temperature was 0.6**, copied verbatim from the model's `generation_config.json`. That
is its *conversational* default. Now **0**.

Greedy alone was not viable, which is why this was never a one-line change: the 08-27
measurement found greedy answered THINLY (one observation citing one block, on a slice
holding 15 tagged sets) and on network read `suspicious` where sampling twice read
`malicious` — the better call. Both were artefacts of a prompt that never said how much to
report. `_FINDING_FOOTER` now carries a **reporting floor** (enumerate against the WHAT TO
LOOK FOR list, dedupe by row and reason), a **`suspicious`/`inconclusive` tie-break** (a
citable anomalous row is at least `suspicious`; a clean full slice is `benign`, not
`inconclusive`), and a **preference for category-named sets over `uncategorised#N`**.

Verified live, three arms, two domains:

| | before (temp 0.6) | after (temp 0, floor) |
| :--- | :--- | :--- |
| identity, 3 draws | `benign`, `inconclusive`, `inconclusive` | identical ×3 |
| identity observations | 5, 17, 9 | 6, 6, 6 |
| network | varied | `malicious` 0.95 ×3, citing the VT row paired with a connection |
| confidence spread | 0.60 (σ 0.32) | 0.00 |

**The floor and temperature=0 are one change with two halves.** Raising the temperature
later is safe; removing the floor while leaving temperature at 0 brings the thin answers
straight back.

Also: the analyst boto3 client had **no retry config**. Three analysts hit one imported
model concurrently, so `ThrottlingException` is expected contention — and it surfaced as
the domain landing `inconclusive` at confidence 0.0, indistinguishable from an honest
"cannot judge". Adaptive retries now.

### `f49cb8a` — half the analyst layer deleted

`main.py` calls `gather()` (blind). `analyze()`, `combine()`, `run_one()`,
`parse_verdict()`, `system_prompt()` and the three shown prompt bodies sat interleaved with
it, so every concept existed twice under two names — verdict/finding, stance/disposition,
assessment/findings — with nothing marking which production used.

The comment at `analyze.py` said the blind tier was *"not yet called from analyze()"*. True
when it landed dark; **inverted** afterwards. A reader following it would conclude the only
live path was the dead one.

- **Deleted:** `analyze()`, `combine()`, `main._print_assessment`, `main._persist_assessment`.
- **Moved to `subagent_analysts/shown.py`:** `run_one`, `_finalize`, `parse_verdict`, the
  stance machinery, `_VERDICT_FOOTER`, the three shown bodies. `blind_compare` still calls
  `run_one` — a comparison you can no longer re-run is a claim, not a result.
- **Nothing deleted from `contracts/`.** `AnalystVerdict`/`Stance` are imported by the
  relocated arm, and `HypothesisAssessment` is a published shape `HypothesisFindings`
  defines itself against.

599 deletions against 109 insertions. `analyze.py` 686 → 546 lines.

### `0b1dd5b` — the row cap was hiding rows the budget could afford

`_ROW_CAP_LADDER`'s first rung is a **ceiling**, not a starting guess. It was 20, and
budget pressure never reached it: the three slices rendered at **5–13% of the 20,000-token
budget** while withholding 52 rows from identity and 110 from endpoint (including 80 of a
single 100-row processes set). And because the ladder never stepped *below* 20,
`truncated=False` was returned throughout — the loss was reported as "nothing was dropped".

Top rung 20 → 200. Now identity 11.6%, network 7.5%, endpoint 35.9%, all complete.

**⚠️ This was not verdict-neutral.** With all 72 auth rows visible, identity moved
`suspicious` → **`benign` 0.95** on 6 observations. Arguably correct (more evidence, better
grounding, and it now cites four `auth_events` sets rather than one block) but it was
committed as a plumbing fix and it moved a verdict. Worth a second opinion.

Considered and rejected: collapsing the 17–20 `rows=0` headers per slice. Saves 183–216
tokens (~1% of budget), not worth a prompt edit that could move the verdict — and those
headers are negative evidence three places in the code depend on.

### `8376a0b` — cost, and the published schema

The analyst model is **not token-billed**. Bedrock Custom Model Import bills
**$0.05718 per CMU per minute in 5-minute windows** from the first successful invocation,
scaling to zero after 5 idle minutes. `analyst_cost.AnalystSpend` records successful
invocations and derives windows from the gaps.

Measured: **9 calls → 1 window; 6 calls → 1 window.** The concurrent fan-out means all
three analysts share one billing window — already cost-optimal; serialising would be worse.

`contracts/schemas/hypothesis-findings.v1.schema.json` (draft 2020-12) is generated by
`contracts/schemas/generate.py` and asserted equal in `test_published_schema.py`, which
also pins the closed `disposition` enum, `confidence ∈ [0,1]`, the required join keys, the
absence of `reasoning_trace` from the wire projection, and that all three domains emit an
identical key set including on the empty path.

## Do this first

**`docs/architecture.md` §7 documents `combine()` → `HypothesisAssessment` as the live
endpoint. That code no longer exists.** The single map of the system currently contradicts
it. Its "Related docs" note also points at `agent_architecture.md`, which predates the
analyst tier.

The declutter plan is worked out and unexecuted, in
`C:\Users\pcc\.claude\plans\modular-doodling-truffle.md` (Phase 4). In short:

1. Edit `architecture.md` in place — it already self-declares as "the single map of the
   whole system" and is the newest of the five. **Do not create a new `ARCHITECTURE.md`.**
   Rewrite §7 for `gather()` → `HypothesisFindings` (no combiner, by contract), add a trace-chain
   section, fix the Related-docs note.
2. `git add` the cited-but-untracked measurement dumps **first** —
   `blind-vs-shown-*.{json,md}` are cited at
   `handover_2026-08-25_blind-vs-shown-remeasured.md:109,122`. Their look-alike sibling
   `anchoring-cli-*-n10.*` (~666KB) is cited nowhere and is disposable.
3. Then `.gitignore` `graphify-out/` (12MB), `docs/*.html`, `docs/diagrams/*.png`,
   `docs/images/*.png`; `git rm --cached` ~6.9MB of PNGs sitting beside 11–13KB SVGs of the
   same diagrams (keep both on disk — the confluence pages document PNG as the paste
   deliverable).
4. `git mv` `agent_architecture.md`, `broker_agent_architecture.md`,
   `agy-skddles-handover.md` to `docs/archive/`. Keep the three `confluence-*.md` — they are
   the live per-subsystem deep dives and the only files `check_anchors.py` validates.
5. `uv run python docs/check_anchors.py docs/architecture.md docs/confluence-*.md` —
   widen the invocation, do not edit the script (`:32` defaults to the confluence glob,
   `:155` takes argv).

## Also open

- **Cold-start determinism is unproven.** 8 warm draws identical; **1 cold draw differed**
  (identity `suspicious` where warm gives `benign`). Cold start is the only variable that
  differed, but the mechanism is unconfirmed — the confirmation probe couldn't reproduce it
  because the model stayed warm. Settling it needs a deliberate >5-minute idle wait then one
  call. Until then the supportable claim is *deterministic on a warm copy; the first call
  after a scale-up may differ* — which is weaker than `852e090`'s commit message says.
- **`SMARTOPS_ANALYST_CMU_COUNT` is unset**, so cost prints "unknown". Needs
  `aws login` then
  `aws bedrock get-imported-model --model-identifier arn:aws:bedrock:us-east-1:196936075264:imported-model/ft3j2o95okma`.
- **No answer key.** `bench.py` has `expected_families` for routing and **zero expected
  dispositions**. Verdicts can be made consistent; they cannot be shown *correct*. Labelling
  10–20 BOTSv3 cases is the highest-value next work.
- **The eval harness was scoped and not built.** `blind_compare.py:380-383` has
  `within_arm_citation_agreement`/`_text_agreement` but not disposition agreement or
  confidence spread — the two the verdict question turns on. `_mean_pairwise` (~:930) is
  there to reuse. The scratchpad probes worth committing are in this session's scratchpad:
  `probe_phase1.py` (three-arm sampling comparison), `probe_fullrows.py`, `probe_cold.py`,
  `budget.py` (budget-vs-usage measurement).
- **A rationale can still misstate its own cited row.** One draw called an IP "known
  malicious" whose cited row read `mal=1` of 91. The grounding gate checks that citations
  *resolve*, never that the claim matches the row — known as defect (c) at
  `analyze._as_judgement`. Now with a concrete example to point at.
- **No OTEL spans on the analyst path.** Broker and subagents stamp `trace_attributes`;
  the raw-boto3 analysts produce nothing.
- **The prompt-token estimator runs ~26% low.** `_CHARS_PER_TOKEN = 4` predicted 8,847 for
  endpoint; the model counted 11,975. Within budget, and `_invoke_with_one_reask` warns past
  20k, so this is a note rather than a defect.

## Do not break

- **Never write under `.smartops/runs/`.** Protected fixture. Point `SMARTOPS_RUNS_DIR` at a
  scratch dir; verify the tree afterwards.
- **The blind guarantee is structural.** `gather_finding(model, scope, slice_)` and
  `build_facts_user_turn(scope, evidence_text)` take no hypothesis, and
  `_invoke_with_one_reask` takes an already-built prompt STRING for that reason. A helper
  that could accept an `InvestigationContext` would downgrade the guarantee to a promise
  about callers.
- **`test_the_disposition_never_implies_a_hypothesis_exists` earns its keep.** It caught a
  tie-break rule this session that read "no row you can cite SUPPORTS any pattern" —
  putting a `Stance` word into the blind prompt. Do not weaken it.
- **Clear any shell `AWS_PROFILE` before a live probe.** Its login credential provider is
  not resolvable here and produced a false "no model credentials" conclusion in a prior
  session.
- **`docs/confluence-subagent-analysts.md` stays untracked**, per its own scope.

## Process note

The two findings that mattered most were both found by running the thing, not by reading
it. The row cap looked like a tuning constant until it was measured against the budget it
was supposedly protecting — 5% used. And the template defect survived four loose
`startswith`/`in`/`endswith` assertions that passed identically before and after it; one
byte-for-byte equality replaced them.

One thing to carry forward: the temperature decision was put to Mohammed as
"stable-but-thin vs variable" **before** the interaction with the reporting floor had been
measured. Once both halves existed, greedy dominated on every axis and the choice had been
framed on stale data. Measure the interaction before presenting the trade.
