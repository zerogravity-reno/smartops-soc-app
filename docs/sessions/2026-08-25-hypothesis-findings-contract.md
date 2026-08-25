---
date: 2026-08-25
title: HypothesisFindings — the contract handed up to the Analyst Agent, and a disposition for the blind analysts
---

# HypothesisFindings: the analysis layer's contract to the Analyst Agent

## The ownership question, resolved by reframing it

`docs/open-questions-for-team.md` parked "who owns the Aggregator?" on
2026-08-24. The answer is that the question had one component where there are
two, and the seam between them is the ownership line:

- **The Analyst Agent** decides supports/refutes. Owned elsewhere; not built
  here. `combine()` is a local stand-in for it, not a competitor, and stays.
- **The contract fed into it** is ours.

So Tier 2 as specified — "an Aggregator that emits the `HypothesisAssessment`
directly, **deleting `combine()`**" — is not ours to build, and the deletion
question never arises.

## Blind does not mean silent

The correction that shaped the contract. `DomainFinding` was built stance-free on
the reasoning that "an analyst who cannot see the hypothesis must not decide
SUPPORTS/REFUTES" — true, but it withheld the judgement entirely, leaving only
observations. The analyst should judge; it just must not be *led*:

> the hypothesis says if there are 20 auth logs then this is malicious — the sub
> analyst sees the hypothesis and 20 auth events, it gets biased to the
> hypothesis and supports it. What I want is for it to see the auth events by
> itself and judge strictly on what it sees, not what it's told to confirm.

Two axes, and only one of them can be anchored:

| | `Stance` | `Disposition` |
| :--- | :--- | :--- |
| relative to | a hypothesis | the rows themselves |
| values | supports / refutes / inconclusive | benign / suspicious / malicious / inconclusive |
| leadable? | yes — tell the model the answer and it agrees | no — the model never sees a claim to agree with |
| decided by | the Analyst Agent | the domain analyst |

They are not convertible in either direction, and nothing tries: benign evidence
can refute one hypothesis and support another, and which it does depends on the
hypothesis. That mapping is the Analyst Agent's job.

## What landed

| Change | Where |
| :--- | :--- |
| `Disposition` literal | `contracts/reasoning.py` |
| `DomainFinding` += `disposition`, `citation_evidence`; `confidence` redefined | `contracts/reasoning.py` |
| `HypothesisFindings` — the contract | `contracts/reasoning.py` |
| `DISPOSITION` in the blind footer, with a "judge the evidence, not a theory about it" instruction | `subagent_analysts/prompts.py` |
| `DISPOSITION` added to `_LABEL`; `_DISPOSITION_RE` + `_normalise_disposition` | `subagent_analysts/parse.py` |
| `_finalize_finding` freezes `citation_evidence`; new `gather()` | `subagent_analysts/analyze.py` |

`uv run pytest` from the root: **702 passed, 0 failed** (from 688).

Additive, exactly as Tier 1 was: `analyze()`, `combine()`, `AnalystVerdict` and
`HypothesisAssessment` are untouched, and `gather()` has no production caller
yet. Being dark is expected here rather than a defect — the consumer is a
component owned elsewhere. That is what makes it a boundary contract.

## Three judgement calls, recorded because they are reversible

1. **One `confidence`, redefined** from "these observations are correctly
   grounded" to "confidence in the disposition". A second field was considered
   and dropped: an 8B model asked for two calibrated numbers returns one number
   twice. Grounding quality is separately observable now — from whether
   `citation_evidence` resolves. Safe to redefine rather than version because
   `gather_finding()` had no production callers, so no `DomainFinding` has ever
   been persisted.
2. **A missing `DISPOSITION` is `inconclusive`, not a parse failure.**
   `parse_finding` stays laxer than `parse_verdict`, which raises without a
   stance: the observations are still grounded evidence worth keeping, and
   `inconclusive` states the gap honestly. It is logged at info, so
   didn't-say is distinguishable from said-so in the record.
3. **`HypothesisFindings` is a separate model, not a widened
   `HypothesisAssessment`.** They share four envelope fields and differ on the
   two that matter. One model meaning two things depending on which fields are
   populated is the ambiguity the `tool_family` discriminator exists to prevent.

## Blindness is enforced structurally, and now tested end to end

`gather_finding(model, scope, slice_)` and `build_facts_user_turn(scope,
evidence_text)` have no hypothesis parameter. It is not passed in and withheld;
there is nothing to pass. `TestGather::test_the_hypothesis_never_reaches_the_model`
records every `(system, user)` pair a real `gather()` run hands the model and
asserts the hypothesis string appears in none of them — so adding a parameter
later fails a test rather than silently leaking.

Verified separately at the prompt level: `facts_system_prompt` contains zero
occurrences of "hypothesis" across all three domains, and no "supports"/"refutes".

## Next

1. **Show Mariam the contract.** Does `Disposition`'s vocabulary match what her
   Analyst Agent wants, and does she want evidence rows inline or is resolving
   `citation_evidence` against the evidence store acceptable?
2. **`gather()` has no caller.** Wiring it into `main.py` means choosing between
   the two paths at the CLI, which touches the Analyst Agent boundary — left
   alone deliberately.
3. **Open question A** from
   `docs/superpowers/specs/2026-08-25-evidence-link-contract-design.md` still
   gates any id-shape work, and `HypothesisFindings.citation_evidence` inherits
   whatever that decides.
