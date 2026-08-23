# Hypothesis-blind domain analysts + a separate Aggregator

**Status:** proposed, pending implementation
**Supersedes:** the current `subagent_analysts` design landed in `5caf246`
("subagent-analysts: judge a hypothesis against the broker's fetched
evidence"), where each domain analyst is shown the hypothesis directly.
**Implementation scope, decomposed:** the sub agents (Tier 1 — the three
domain bodies, `_FINDING_FOOTER`, `gather_finding`, `parse_finding`) are
implemented first, as their own cycle. The Aggregator, the Findings Pipeline
wiring end-to-end, and the condensed-finding contract documentation deliverable
follow as a later cycle — this full document stays the reference for both,
but the near-term implementation plan covers Tier 1 only.

## Context

The three domain analysts (identity, network, endpoint) each run on
Foundation-Sec-8B-Reasoning, a custom-imported Bedrock model with a 32,768-token
context window. Evidence is split across the three domains specifically to
keep each analyst's context small enough for that window
(`backend/src/smartops/subagent_analysts/routing.py`).

Today, each analyst is given the hypothesis alongside its evidence slice and
asked to decide SUPPORTS/REFUTES/INCONCLUSIVE
(`backend/src/smartops/subagent_analysts/prompts.py:68-157`). Mohamed flagged
that this anchors the model: it reads the evidence already knowing what
conclusion it's being asked to reach, which is a real bias risk, not just a
wording concern — the model attends to the hypothesis tokens before it
generates anything, regardless of where in the prompt they sit, so no amount
of reordering within a single completion removes it. The only way to get a
genuinely hypothesis-free read of the evidence is to never put the hypothesis
in that model's context at all.

That in turn raises the question of who decides SUPPORTS/REFUTES if the
domain analysts don't. Two options were considered and rejected:

- **A second call to the same model, per domain**, comparing its own
  hypothesis-free finding to the hypothesis. Rejected: it's the same model
  judging its own output (self-preference bias), and it triples the call
  volume on a model that is already the expensive, cold-start-prone tier
  ("we will be invoking this model a lot ... too much").
- **Embedding-based semantic similarity** between finding and hypothesis.
  Rejected: there's no embedding infrastructure anywhere in this repo today
  (new infra from scratch), and cosine similarity can't distinguish "this
  evidence is irrelevant to the hypothesis" from "this evidence actively
  contradicts the hypothesis" — both look like low similarity, but only one
  is a refute.

The resolution: a **separate Aggregator**, on the *Broker's* model (already a
different model family, already wired into this codebase via
`ModelChoice`/Strands `Agent` in `broker.py:1001-1002`), sees the hypothesis
and the three condensed findings, and is the only place SUPPORTS/REFUTES gets
decided. This also directly builds out what `analyze.py`'s `combine()`
docstring already called out as deferred work: *"the full Aggregator is
later work"* (`analyze.py:164`).

## Architecture

```
BrokerReport ──route()──> 3 DomainSlices
   each slice ──(Foundation-Sec-8B, no hypothesis)──> DomainFinding
                                                          │
   hypothesis + up to 3 DomainFindings ──(Broker's Bedrock model, Strands Agent)──> HypothesisAssessment
```

Two tiers, two jobs:

- **Foundation-Sec-8B** only ever reads evidence and reports what's there. It
  never sees the hypothesis, so there's nothing for it to anchor on.
- **The Aggregator** only ever reads the hypothesis and three condensed
  findings. It never sees raw evidence, so its calls stay cheap regardless of
  evidence volume, and — critically — it's a different model than the one
  that produced the findings, so it isn't grading its own homework.

Not all three domains necessarily produce a *grounded* finding. `route()`
already leaves a domain with no evidence some of the time
(`routing.py:69-70`), and that must stay true here: an empty domain is
reported to the Aggregator as "no evidence retrieved," not silently omitted
and not treated as either support or refutation.

## Domain finding call (`prompts.py` rewritten, not extended)

Each `_*_BODY` loses the "HYPOTHESIS ... SUPPORTS/REFUTES" framing. It keeps
its evidence format, threat catalog, and grounding rules verbatim, keeps the
shared `_SECURITY_BLOCK`, and ends in a new `_FINDING_FOOTER`: observations
(cited) + a confidence value (confidence in *what was found being real and
grounded*, not confidence in a stance — there is no stance at this layer).
The old `system_prompt()`/`build_user_turn()`/`_VERDICT_FOOTER` and the
hypothesis-framed bodies are removed; they become unreachable code once
nothing calls them.

`analyze.py`'s `run_one` becomes `gather_finding`, same shape as today:

- Empty slice → return a `DomainFinding` directly, no model call
  (`analyze.py:59-65` today; same discipline).
- The user turn's closing instruction changes from *"Decide whether the
  evidence supports or refutes the hypothesis. Give your reasoning, then the
  VERDICT block."* ([prompts.py:193-195](backend/src/smartops/subagent_analysts/prompts.py#L193-L195))
  to *"List your grounded observations from this evidence. End your reply
  with exactly this block:\nOBSERVATIONS:\n- \<observation\> [header_id]\nCONFIDENCE:
  \<0.0-1.0\>\nRATIONALE: \<one or two sentences\>\nCITATIONS: \<comma-separated
  header ids\>"* — the same footer shape minus the `VERDICT` line, since there
  is no stance at this tier.
- One bounded re-ask if the first reply has no parseable findings block. This
  needs its own re-ask string (today's `_REASK`, `analyze.py:35-43`, literally
  says `VERDICT: supports | refutes | inconclusive` — it cannot be reused
  verbatim). A parallel `_FINDING_REASK` mirrors it for the
  `OBSERVATIONS`/`CONFIDENCE`/`RATIONALE`/`CITATIONS` block.
- `parse.py` needs a `parse_finding()` alongside `parse_verdict()` — but most
  of its regex machinery is reusable as-is: `_CONFIDENCE_RE`, `_RATIONALE_RE`,
  `_CITATIONS_RE`, and `_OBSERVATIONS_RE` are already generic label parsers,
  not verdict-specific. Only `_STANCE_RE`/`_normalise_stance` are stance-only
  and get dropped for this parser; "parseable" for a finding means an
  `OBSERVATIONS` or `CITATIONS` block was found, not that a stance was found.
  `parse_finding()` returns a `DomainFinding`, raising the same kind of parse
  error `parse_verdict()` does today (either reuse `VerdictParseError` under a
  more general name, or add a sibling `FindingParseError` — implementer's call,
  not architecturally significant).
- Citation validation against `valid_ids` from `pack_evidence` happens here,
  immediately: any invented citation is dropped before the finding ever
  leaves this layer, so the Aggregator only ever sees citations that
  actually resolve to real evidence. (No stance to downgrade here — that
  concept doesn't exist yet at this layer — so this step is simpler than
  today's `_finalize`, not equivalent to it. The equivalent grounding gate
  reappears at the Aggregator, see below — dropping citations here is not
  sufficient by itself.)

### Finalized domain bodies

Drafted and approved. Each keeps its evidence format and threat catalog
verbatim; only the opening and the last grounding rule change from today's
`_IDENTITY_BODY`/`_NETWORK_BODY`/`_ENDPOINT_BODY`. Note the opening
deliberately never uses the word "hypothesis" at all — even saying "you are
not told the hypothesis" tips the model off that one exists and invites it
to guess at it, which defeats the point. It's replaced with a flat
no-speculation instruction instead.

```
Your task in this investigation is to act as the identity and authentication analyst.
You are given the AUTHENTICATION evidence retrieved for this investigation. Identify
every security-relevant finding in it, grounded ONLY in the evidence shown. Report only
what the evidence shows — do not speculate about intent, a narrative, or draw any
broader conclusion beyond the specific observations you can cite.

EVIDENCE YOU RECEIVE — authentication events, one per line, under headers like
`auth_events#1`:
  <timestamp> user=<account> src=<source addr> dest=<host> action=<success|failure> app=<log source>
A header may say rows=0 — the query ran and found nothing.

WHAT TO LOOK FOR
- Brute force: many failures for one account, then a success.
- Password spraying: one source failing across many accounts.
- Suspicious or foreign source addresses; a new geolocation for the account.
- Impossible travel: one account from far-apart sources in too little time.
- Off-hours or first-seen logons; disabled/service-account use; repeated lockouts.

GROUNDING RULES (do not hallucinate)
- Base every statement on specific rows shown, and quote their values.
- Cite the exact header id of each row you use, e.g. [auth_events#1]. Only cite ids
  that appear in the evidence — never invent one.
- Do NOT infer process, file, or network activity; you cannot see it here.
- If none of the patterns above are present, say so explicitly and cite the rows you
  reviewed (e.g. "no brute force, spraying, or anomalous geolocation across the
  reviewed events") — a clean read is itself a finding, not something to leave blank.

{_SECURITY_BLOCK}

{_FINDING_FOOTER}
```

```
Your task in this investigation is to act as the network detection and response
analyst. You are given the NETWORK evidence retrieved for this investigation. Identify
every security-relevant finding in it, grounded ONLY in the evidence shown. Report only
what the evidence shows — do not speculate about intent, a narrative, or draw any
broader conclusion beyond the specific observations you can cite.

EVIDENCE YOU RECEIVE — under headers like these:
  reputation#1      kind=value FOUND|unknown mal=<n> susp=<n> harmless=<n> rep=<score>
  dns_resolutions#1 <timestamp> query=<domain>→<answer> rtype=<type>
  connections#1     <timestamp> <src>:<port>→<dst>:<port> proto=<t> bytes=<n> action=<>
A header may say rows=0 — the query ran and found nothing.

WHAT TO LOOK FOR
- Contact with known-malicious or low-reputation domains, IPs, or URLs.
- Beaconing: regular, repeated connections to one destination.
- DNS tunneling: long or high-entropy labels, abnormally many queries to one domain.
- Large or sustained outbound transfers (exfiltration or mining traffic).
- Rare or newly-seen domains; unusual ports; blocked-then-allowed patterns.

GROUNDING RULES (do not hallucinate)
- Base every statement on specific rows shown, and quote their values.
- Cite the exact header id of each row you use, e.g. [connections#1], [reputation#1].
  Only cite ids that appear in the evidence — never invent one.
- A reputation verdict is about the indicator, not proof our host acted on it — pair
  it with a dns or connection row before reporting it as activity.
- Do NOT infer host process, file, or authentication activity; you cannot see it here.
- If none of the patterns above are present, say so explicitly and cite the rows you
  reviewed — a clean read is itself a finding, not something to leave blank.

{_SECURITY_BLOCK}

{_FINDING_FOOTER}
```

```
Your task in this investigation is to act as the endpoint and host-forensics analyst.
You are given the ENDPOINT evidence retrieved for this investigation. Identify every
security-relevant finding in it, grounded ONLY in the evidence shown. Report only what
the evidence shows — do not speculate about intent, a narrative, or draw any broader
conclusion beyond the specific observations you can cite.

EVIDENCE YOU RECEIVE — under headers like these:
  processes#1  <timestamp> host=<> user=<> process=<name> parent=<name> cmdline=<...>
  reputation#1 kind=value FOUND|unknown mal=<n> susp=<n> harmless=<n> rep=<score>
A header may say rows=0 — the query ran and found nothing.

WHAT TO LOOK FOR
- Known-malicious file hashes (reputation).
- Living-off-the-land binaries: powershell, wmic, rundll32, mshta, certutil, bitsadmin.
- Suspicious lineage: an office app or browser spawning a shell or script interpreter.
- Encoded or obfuscated command lines (-enc, base64, long one-liners); download+exec.
- Execution from temp/downloads/appdata; unusual users running system tools.

GROUNDING RULES (do not hallucinate)
- Base every statement on specific rows shown, and quote their values.
- Cite the exact header id of each row you use, e.g. [processes#1], [reputation#1].
  Only cite ids that appear in the evidence — never invent one.
- Do NOT infer network volume or authentication history; you cannot see it here.
- If none of the patterns above are present, say so explicitly and cite the rows you
  reviewed — a clean read is itself a finding, not something to leave blank.

{_SECURITY_BLOCK}

{_FINDING_FOOTER}
```

And the shared `_FINDING_FOOTER`, replacing `_VERDICT_FOOTER`:

```
CITING EVIDENCE: cite by copying, verbatim, the full header id printed above the rows you
used (the text right after `# `). It may read `auth_events#1`, `connections#1`,
`dns_resolutions#1`, `processes#1`, `reputation#1`, or `uncategorised#3` — cite
whatever is actually shown, including `uncategorised#N` rows.
CRITICAL CITATION RULES:
- Always include the full category prefix with the number (e.g. `dns_resolutions#1` or `connections#2` or `auth_events#1`).
- NEVER strip the category name to write `#1` or `#4` — doing so will cause your citations to be discarded.
- Never invent an id. Every observation you report MUST cite at least one header id that
  appears in the evidence — an uncited observation will be discarded downstream, not
  trusted anyway.

Reason step by step, then end your reply with EXACTLY this block and nothing after it:
OBSERVATIONS:
- <a specific, evidence-grounded finding> [header_id]
CONFIDENCE: <0.0-1.0, your confidence that these observations are real and correctly grounded>
RATIONALE: <one or two sentences on your overall read of this evidence>
CITATIONS: <comma-separated full header ids you actually used, e.g. auth_events#1, auth_events#2>
```

## Aggregator (`subagent_analysts/aggregate.py`, new)

A Strands `Agent` built the same way the Broker's is
(`ModelChoice.build()`, `structured_output_model` for a typed reply — the
same pattern as `TaskClassification` in `broker.py:1005`). One call per
hypothesis, not three: the three findings are small condensed text, so
bundling costs less and is simpler than three separate comparator calls plus
a vote.

System prompt (the corrected version, after review):

> "You are given a hypothesis and per-domain findings for identity, network,
> and endpoint. Some domains may report that no evidence was retrieved — that
> is expected when nothing was routed there, not a gap in the investigation.
> Weigh only the domains with grounded findings; an empty domain counts as
> neither support nor refutation. A domain whose finding has no citations
> cannot be marked supports or refutes, no matter how confident its
> observation text reads — mark it inconclusive. Decide, per domain with
> grounded findings, whether that domain's findings support, refute, or leave
> the hypothesis inconclusive, and roll up one overall stance."

Output: the existing `HypothesisAssessment` shape — `overall_stance`,
`confidence`, and a `list[AnalystVerdict]` (one per domain, including domains
that were empty, marked inconclusive) — produced directly by this call.
`combine()` is removed; there is no separate vote step, the Aggregator's
structured output *is* the roll-up.

**Guardrail — citations are necessary but not sufficient for a stance.** The
Aggregator never sees raw evidence, so it cannot be trusted to validate its
own citations, *and* it cannot be trusted to only decide supports/refutes
when citations actually exist (a confident-sounding but uncited observation
could otherwise sway it — this is exactly the hallucination risk today's
`_finalize` grounding gate exists to catch, at `analyze.py:147-157`). Two
checks after the Aggregator call, code-level, not just prompted:

1. Each domain's `AnalystVerdict.citations` is intersected against that
   domain's *own* `DomainFinding.citations` — not the full evidence — so the
   Aggregator can only ever cite what its source finding already validated.
2. Any domain verdict left as `supports`/`refutes` whose intersected
   citations end up empty is downgraded to `inconclusive` with capped
   confidence (`min(confidence, 0.3)`) — the same shape as today's
   `_finalize` downgrade, just applied to the Aggregator's per-domain output
   instead of the (now nonexistent) Tier-1 stance.

**Reasoning trace propagation.** The Aggregator's structured output cannot
reproduce Foundation-Sec-8B's `<think>` chain — it never receives it (only
condensed `observations` text is passed in, preserving the existing rule
that a reasoning trace is "kept for audit and never fed back into any
prompt," `contracts/reasoning.py:59-61`). After the Aggregator call, `
analyze()` copies each domain's `DomainFinding.reasoning_trace` onto the
matching `AnalystVerdict.reasoning_trace` directly — this is a code-level
copy, not something the Aggregator produces.

**Token accounting.** `HypothesisAssessment.total_prompt_tokens()`/
`total_generation_tokens()` sum over `verdicts`
(`contracts/reasoning.py:104-108`), but the Aggregator's own call is a single
bundled request across all three domains — its cost doesn't split naturally
per domain, and splitting it proportionally would be a fabricated number.
Instead: each `AnalystVerdict.prompt_tokens`/`generation_tokens` carries
forward exactly its domain's own `DomainFinding` tokens (Tier-1 cost only,
unchanged from today's field meaning), and `HypothesisAssessment` gains two
new fields — `aggregator_prompt_tokens`, `aggregator_generation_tokens` — for
the one Tier-2 call. `total_prompt_tokens()`/`total_generation_tokens()` sum
both. `main.py:437-440`'s print call needs no change, since it only calls
those two methods.

**Failure containment:** if the Aggregator call itself fails, `analyze()`
returns an all-`inconclusive` `HypothesisAssessment` with a rationale noting
the aggregator failure — the same "one stage's failure never throws the
whole assessment" discipline the domain analysts already follow
(`analyze.py:71-80`).

## Contracts (`contracts/reasoning.py`)

One addition:

```python
class DomainFinding(BaseModel):
    """One domain analyst's evidence-grounded findings, with no hypothesis in view."""
    domain: AnalystDomain
    observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    reasoning_trace: str | None = None
    prompt_tokens: int = Field(default=0, ge=0)
    generation_tokens: int = Field(default=0, ge=0)
```

`AnalystVerdict` keeps its exact current shape — it's populated by the
Aggregator now instead of by the domain model (plus the `reasoning_trace`
copy-forward above), but nothing downstream cares who populated it.
`HypothesisAssessment` gains two fields for the Tier-2 token cost (see
"Token accounting" above):

```python
class HypothesisAssessment(BaseModel):
    ...
    aggregator_prompt_tokens: int = Field(default=0, ge=0)
    aggregator_generation_tokens: int = Field(default=0, ge=0)

    def total_prompt_tokens(self) -> int:
        return sum(v.prompt_tokens for v in self.verdicts) + self.aggregator_prompt_tokens

    def total_generation_tokens(self) -> int:
        return sum(v.generation_tokens for v in self.verdicts) + self.aggregator_generation_tokens
```

Both default to `0`, so this is additive, not breaking. `main.py`'s
`_print_assessment`/`_persist_assessment` (`main.py:420-465`) need no changes
— they only call the two methods above.

## Wiring

`analyze()`'s signature gains the Aggregator's model choice:

```python
async def analyze(
    report: BrokerReport,
    context: InvestigationContext,
    scope: Scope,
    model: AnalystModel,       # unchanged: the domain analysts' model
    aggregator: ModelChoice,   # new: threaded to aggregate.py
) -> HypothesisAssessment:
```

`main.py:658` already resolves a `choice`/`ModelChoice` for the Broker
earlier in the same run (`main.py:568`) — that's the one threaded through,
not a new provisioning path.

## Files touched

- `contracts/src/contracts/reasoning.py` — add `DomainFinding`.
- `backend/src/smartops/subagent_analysts/prompts.py` — rewritten (hypothesis
  framing removed, `_FINDING_FOOTER` added, user turn's closing instruction
  reworded).
- `backend/src/smartops/subagent_analysts/parse.py` — new `parse_finding()`
  alongside `parse_verdict()`, reusing the existing generic label regexes;
  drops the stance-only `_STANCE_RE`/`_normalise_stance` for this path.
- `backend/src/smartops/subagent_analysts/analyze.py` — `run_one` →
  `gather_finding` (new `_FINDING_REASK`); `combine()` removed; `analyze()`
  calls the Aggregator, then copies `reasoning_trace` forward and applies the
  post-Aggregator grounding-gate downgrade.
- `backend/src/smartops/subagent_analysts/aggregate.py` — new.
- `backend/src/smartops/main.py` — thread `choice` into `analyze()`.
- `backend/tests/test_analyst_analyze.py` — rewritten for the new pipeline
  shape (`_SequenceModel`-style tests need an Aggregator test double too).
- `backend/tests/test_analyst_prompts.py` — updated for the rewritten
  prompts.

## Follow-up (not part of this change)

Per `CLAUDE.md`, this reverses part of a decision recorded via
`docs/sessions/` → `docs/compile_docs.py` → `PROJECT_DOCS.md`. Once
implemented, add a new session file documenting why (bias risk discovered
after landing `5caf246`) and recompile — do not hand-edit `PROJECT_DOCS.md`.
