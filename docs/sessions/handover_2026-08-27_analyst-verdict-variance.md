---
date: 2026-08-27
title: The analyst verdict is unstable run to run, and it is a sampling setting before it is a prompt
---

# Handover — 2026-08-27: analyst verdict variance, measured

Continues `handover_2026-08-27_verification-run-no-splunk.md`, which covers the eight
review-driven commits and the live verification. **Everything is committed and pushed** —
`2c4f27d..69d3160`, ten commits on `task-broker-agent`, level with
`origin/task-broker-agent`, working tree clean apart from pre-existing untracked scratch
files.

This session ended on a question from Mohammed: the three domain analysts return different
verdicts on different runs, and should they be made consistent. **Nothing was changed.**
This file records what was measured and what the options are, because the measurement is
the part that would be expensive to redo.

## THE HEADLINE: the verdict is not merely wobbly, it flips

Production runs at `SMARTOPS_ANALYST_TEMPERATURE=0.6`, `SMARTOPS_ANALYST_TOP_P=0.95`
(`.env`; the same values are `DEFAULT_TEMPERATURE` / `DEFAULT_TOP_P` at
`model.py:51-52`). Three draws per condition, identical slice, identical prompt, taken from
`cli-20260825T100434/20260825T100741262`:

| | identity @ 0.6 | identity @ 0.0 | network @ 0.6 | network @ 0.0 |
| :--- | :--- | :--- | :--- | :--- |
| dispositions | `benign`, `inconclusive`, `inconclusive` | `suspicious` ×3 | `suspicious`, `malicious`, `suspicious` | `suspicious` ×3 |
| confidence | 0.25 – 0.85, **spread 0.60**, σ 0.32 | 0.85, σ **0.00** | 0.85 – 0.95, σ 0.06 | 0.85, σ **0.00** |
| citation Jaccard | **0.27** (4 of 15 ids common) | **1.00** | **0.27** (3 of 11) | **1.00** |
| observations | 5, 17, 9 | 1, 1, 1 | 3, 1, 3 | 3, 3, 3 |
| generation tokens | 1002–1367 | **818 exactly, ×3** | 646–1548 | **1012 exactly, ×3** |

**At temperature 0 the draws are byte-identical.** Pooling every identity draw taken today
(five at 0.6, including two from full `gather()` runs) the domain produced **three of the
four possible dispositions** on the same rows — `suspicious`, `suspicious`, `benign`,
`inconclusive`, `inconclusive`. One 0.6 draw also invented `auth_events#16` and `#17`; the
grounding gate dropped both, which is the gate doing its job.

So the first lever is **a config value, not a prompt**: `SMARTOPS_ANALYST_TEMPERATURE=0`
with `TOP_P=1.0`.

## The trade-off that stops this being a one-line fix

Greedy decoding is stable and **thinner**:

- identity at temp 0: `suspicious` 0.85 on **one observation citing one block** — and that
  block was `uncategorised#3`, not an `auth_events` set, on a slice holding 15 tagged sets.
- identity at 0.6: 5 to 17 observations, 7 to 10 citations.
- network at temp 0: `suspicious`. But coinhive.com carries VT `mal=11`, and the
  `malicious` 0.95 that 0.6 produced twice is arguably the better read.

**Determinism is not correctness.** Setting temperature to 0 without also putting a
thoroughness floor in the prompt trades a wandering-but-thorough analyst for a
stable-but-terse one, and on the network slice it may trade *down* on accuracy.

## Prompt findings, ranked, none applied

Measured against the rendered blind prompts (`facts_system_prompt(domain)`, ~1,380–1,440
tokens each; the shown-path prompts are ~1,130–1,180 and are not what production runs).

1. **`CONFIDENCE: <0.0-1.0>` has no rubric.** Every value observed today: 0.85 ×4, 0.95 ×2,
   0.75, 0.7, 0.25. Confidence tracks the *disposition label* (malicious→0.95,
   suspicious→0.85), not evidence strength, so it carries almost no independent
   information. A band rubric tied to observable state — "0.9+ only when two independent
   categories corroborate; ≤0.4 when your only citations are `uncategorised#N`" — turns a
   guess into a lookup. Note nothing consumes confidence today except
   `_apply_grounding`'s `min(confidence, 0.3)` cap, so this is future value and operator
   trust, not current behaviour.
2. **Nothing specifies how much to report.** "CITATIONS: the ids you actually used" is
   unbounded, which is why one draw gave 1 observation and another 17. This is the fix that
   makes temperature 0 safe, and should land in the same change as it.
3. **`suspicious` and `inconclusive` overlap with no tie-break.** Current wording:
   suspicious = "abnormal or warrants follow-up"; inconclusive = "too little here to judge".
   On a slice with 15 sets and 157 rows both are defensible, which is the flip above. One
   ordering rule — "if you can cite a specific anomalous row it is at least `suspicious`;
   reserve `inconclusive` for when no cited row supports any pattern" — removes the coin
   flip without redefining the labels.
4. **~250 tokens of vendor boilerplate lead every call.** Lines 1–12 of every analyst prompt
   are the Metis model-card preamble: CVE/CWE identifier validity, cloud security and
   Terraform, "cite sources… explain your logic thoroughly", and an off-topic refusal
   policy. Task-irrelevant, and that one clause pulls directly against the terse bounded
   block the parser wants. **It is the vendor's recommended framing, so trim it last and
   only behind an eval.**
5. **"Reason step by step" precedes the output block.** The trace is discarded by
   `split_reasoning`, so its only effect on the consumer is which block it leads to; at
   temp>0 divergent reasoning is the mechanism producing divergent verdicts. Low priority —
   at temp 0 it stops mattering and the trace has audit value.
6. **Identity is routed 17 untagged sets against 15 tagged**, and greedy cited only an
   `uncategorised#N`. The prompt permits that with no preference for category-matched
   evidence. Possibly a routing observation (§6) rather than a prompt one.

## Recommended order, if this is taken up

1. `SMARTOPS_ANALYST_TEMPERATURE=0`, `SMARTOPS_ANALYST_TOP_P=1.0`.
2. Finding 2 (reporting floor) **in the same change**, or greedy gives thin answers.
3. Findings 1 and 3, one at a time, each measured.
4. Findings 4 and 5 only if an eval shows a gain.

## Two things that block the "correct" half of the request

- **There is no answer key.** `bench.py` carries `expected_families` for routing
  correctness (`bench.py:522`, `:578`) and **no expected dispositions anywhere in the
  repo**. Until 10–20 BOTSv3 cases are labelled with the disposition a human analyst would
  give, "correct" is not measurable and any prompt edit is being tuned against vibes.
- **The consistency harness already exists** and only needs extending.
  `blind_compare.py:381-383` computes `within_arm_citation_agreement` /
  `within_arm_text_agreement`, documented as "the noise floor", over `--samples N`. It
  tracks citation and text agreement but **not disposition or confidence agreement** —
  adding those two is the small piece of work that would make the loop measurable.

## The open question, unresolved on purpose

"The three analyst outcomes should have a consistent verdict" reads two ways, and only one
is a defect:

- **Per-domain run-to-run stability** — measured above, fixable, everything in this file
  addresses it.
- **The three domains agreeing on one verdict** — *not this layer's job.* `gather()` has no
  combiner by contract (`analyze.py`, and `reasoning.py:399-403`): deciding
  SUPPORTS/REFUTES is the Analyst Agent's. Three analysts reading different evidence
  **should** sometimes differ. Confirm which was meant before anyone builds toward the
  second reading.

## Where the scripts are

Scratchpad, session `779b709b`, under
`…/claude/d--projects-Smartops-SOC-App/779b709b-…/scratchpad/`:

- `variance_probe.py` — the table above. Takes `<domain> <draws>`, routes a saved run,
  calls `gather_finding` N times at the configured sampling and N at temperature 0, and
  reports distinct dispositions, confidence spread and σ, and citation Jaccard. **Worth
  committing if this work proceeds**, because it becomes the eval harness for findings 1–3.
- `gather_live.py` — runs production `gather()` over a saved run and checks every exhibit's
  `evidence_ids` against `evidence_by_id`. This is what closed §11's caveat.
- `verify_run.py` — loads every saved report, checks every stored result set's category
  against `_infer_cim_category`, and replays every case.

All three need `.env` loaded and any shell `AWS_PROFILE` cleared — its login credential
provider is not resolvable here, and that alone produced a false "no model credentials"
conclusion earlier in the session.

## Do not break

- **Never write under `.smartops/runs/`.** Protected fixture. Every run this session pointed
  `SMARTOPS_RUNS_DIR` at a scratch directory; verified afterwards that the tree was
  untouched (23 cases, 26 reports).
- **The blind guarantee is structural.** `gather_finding(model, scope, slice_)` and
  `build_facts_user_turn(scope, evidence_text)` take no hypothesis. The shared
  `_invoke_with_one_reask` takes an already-built prompt string for that reason. A helper
  that could accept a context would downgrade the guarantee to a promise about callers.
- **`docs/check_anchors.py` after any edit to a cited file.** It asserts the anchored line
  *defines* the symbol named beside it.
- **`docs/confluence-subagent-analysts.md` stays untracked**, as its own scope requires.

## Process note

The variance here was found by running the thing three times, not by reading the prompt. The
prompt reads well; static analysis scored its clarity 18–28/100 and most of what it flagged
was vendor boilerplate, which is the kind of finding that would have sent a prompt rewrite
in the wrong direction. **The measurement reordered the recommendations**: temperature is
the first lever and it is not a prompt at all, and the prompt work that matters most
(a reporting floor) is only necessary *because* fixing the temperature exposes a
thoroughness problem the noise was hiding.
