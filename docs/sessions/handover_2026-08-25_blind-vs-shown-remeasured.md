---
date: 2026-08-25
title: Blind vs shown re-measured; the anchoring demo does not survive, and the analyst model had not authenticated since b18bf09
---

# Handover — 2026-08-25: the anchoring demo, re-measured

Continues `handover_2026-08-24_artifact-contract-integrity.md`, whose ranked queue
put one item first: *re-run the hypothesis-blind vs hypothesis-shown comparison
offline against `.smartops/runs/`*. That is done.

Branch `task-broker-agent`, HEAD `d8406d1` (nothing committed this session).
`uv run pytest` from the repo root: **671 passed, 0 failed** (up from 645).

## Pick this up here

1. **Tier 2's empirical case is gone.** The anchoring demo was a draw from a
   noisy distribution, not a property of the arms. Details below; do not commit
   effort to the Aggregator on the strength of that demo.
2. **A credential bug had silenced every analyst call in production** since the
   env-leak fix (`b18bf09`). Fixed here, with tests. This is the more urgent
   finding of the two.
3. **Three defects are recorded and deliberately unfixed** — see *Defects found
   by running it*. Fixing them was scoped out on purpose; they are triage input.
4. The comparison harness is committed this time
   (`backend/src/smartops/blind_compare.py`), because the previous one was a
   throwaway script and this session had to rebuild it from nothing.

## THE HEADLINE: the flip was one draw from a spread wider than the effect

The demo that justified the redesign — `cli-20260823T112627`, `auth_events#6`,
hypothesis-shown calling it "legitimate local logins" while hypothesis-blind
called it "potential password spraying" — was sampled **once per arm at
temperature 0.6**. Re-run on byte-identical evidence, the blind arm's draws of
the same identity read are:

| Draw | Blind arm's read | Confidence |
| :--- | :--- | :--- |
| 1 | "log deletion attempts... potential credential misuse" | 0.95 |
| 2 | "rapid re-authentication or session reuse" | 0.85 |
| 3 | **"probable password-spraying attack"** | 0.95 |
| 4 | "remote logon followed by workstation lockout" | 0.85 |
| 5 | **"all events legitimate, no anomalies"** | 1.00 |

Both of the original demo's headline readings are in that list, from the same
arm, on the same rows. The 2026-08-23 handover's own verdict — *"a code bug, not
proof either analyst reasoned better"* — was right about the cause and too
generous about what remained: with the projector fixed, there is no arm-level
effect left to explain.

**A framing correction, made mid-session and worth keeping.** The first draft of
this finding said the shown arm now "reads better", on the strength of three of
its draws describing the rows accurately ("Normal workstation unlock (Logon Type
11)", "code 4624 successful interactive logon... later 4648", "no failed logins or
brute-force patterns visible"). Mohamed pushed back, correctly: **accuracy of
conclusion is not the blind arm's contract.** `DomainFinding` is stance-free by
design and the Aggregator is what decides SUPPORTS/REFUTES, so grading the blind
arm on whether it reached the right conclusion imports a stance-level standard
into a layer built not to have one. That claim is withdrawn.

What survives the correction, and survives it more sharply:

- **The variance finding.** Both of the demo's readings came out of one arm on
  one set of rows. That says nothing about which arm is right and everything
  about what a single draw can support.
- **The fabrication is a grounding failure, which IS inside the blind layer's
  contract.** Draw #3's "2 failed logon attempts followed by a single success"
  describes rows that do not exist. "Report only what the evidence shows" is the
  blind prompt's own instruction. See *Defects*, item 1.
- **Confidence runs systematically higher in the blind arm** — at n=15, median
  0.95/0.95/0.85 across the three domains against the shown arm's 0.65/0.65/0.65.
  More confident, not better grounded.

## What the arm-vs-arm comparison cannot tell you

Recorded because this session spent real effort before noticing it, and the
harness now carries the correction.

The blind arm **cannot be anchored**. It never receives a hypothesis, so its
output is independent of one by construction — that is a structural guarantee, not
a hypothesis in need of a test. Anchoring is a claim about the **shown** arm
alone: that its read of fixed evidence *moves* when the hypothesis moves.

Comparing the arms to each other cannot isolate that, because the two differ in
system prompt, footer, output type, and whether a hypothesis is present — all at
once. Any divergence between them confounds "the hypothesis biased the read" with
"these are different prompts". The n=5 and n=15 runs below are therefore a
**variance** measurement, not an anchoring measurement, and should be cited as
nothing more.

The experiment that does isolate it holds the evidence fixed and varies the
hypothesis inside the shown arm, with the blind arm as a control that cannot move.
That is `--anchoring` (see *The anchoring test* below).

## The numbers

Both arms are called through their production entry points (`run_one`,
`gather_finding`), so every gate they apply is inside the measurement. Agreement
is a lexical Jaccard proxy — over citation ids, and over content words of the
observation text — and is meaningful only as a *ranking* of between-arm against
within-arm, never in absolute terms. The full text of every draw is in the
artifact because reading it is the actual deliverable.

The decision rule was fixed before the run (it is in the module docstring): the
premise survives only if between-arm agreement falls below **both** arms'
within-arm floors, i.e. the arms differ from each other by more than each differs
from itself.

**n=5 per arm** (`docs/blind-vs-shown-passA-cli-20260823T112627.json`), 30/30
calls succeeded:

| Domain | between (text) | within shown | within blind | verdict |
| :--- | :--- | :--- | :--- | :--- |
| identity | 0.094 | 0.172 | 0.115 | diverges |
| network | 0.147 | 0.266 | 0.122 | within noise |
| endpoint | 0.112 | 0.149 | 0.110 | within noise |

Identity clears the rule, but by 0.02 against a floor of 0.115 — and the floors
themselves are the story: **both arms disagree with themselves nearly as much as
they disagree with each other.** That is why n was raised.

**n=15 per arm** (`docs/blind-vs-shown-cli-20260823T112627-n15.json`), 90/90 calls
succeeded:

| Domain | between (text) | within shown | within blind | verdict |
| :--- | :--- | :--- | :--- | :--- |
| identity | 0.084 | 0.150 | 0.103 | diverges |
| network | 0.119 | 0.171 | 0.1191 | **tie — do not cite** |
| endpoint | 0.098 | 0.160 | 0.112 | diverges |

Identity and endpoint hold up with real margins. **Network's "diverges" is an
artifact of the threshold** — 0.1190 against a floor of 0.1191, a margin of one
ten-thousandth. The harness reports it as a divergence because the rule is a
strict inequality; it should be read as a tie, and this is exactly why the rule
is written down and the raw numbers are kept.

Read carefully, the honest summary of both tables is: the arms do produce
measurably different descriptions, but mostly because **the blind arm barely
agrees with itself** (0.103-0.119) — its self-agreement is only just above the
between-arm figure. The shown arm is the steadier of the two on this axis
(0.150-0.171), while still being nowhere near stable.

**The finding with the clearest operational consequence is not about the arms at
all.** At n=15 the shown arm's stance on identical evidence is close to a coin
flip: identity `refutes` x5 / `inconclusive` x10, endpoint `supports` x7 /
`inconclusive` x6 / `refutes` x2, network `supports` x7 / `inconclusive` x8. That
is the production path (`analyze()` -> `combine()`), and `combine()` rolls
whichever draw it happened to get into one `HypothesisAssessment` with a
confidence number attached. Nothing downstream can tell a stance that would
survive resampling from one that would not.

## The credential bug: no analyst call had authenticated since `b18bf09`

The first attempt at the measurement returned **30 of 30**
`AccessDeniedException: The provided resource ARN is from a different account.`
Both arms contain their own failures on purpose, so this surfaced as thirty
"analyst could not run" verdicts and a structurally complete report.

`model.py` set `AWS_BEARER_TOKEN_BEDROCK`, built the client, then restored the
variable, on a premise its own comment stated: *"botocore reads
`AWS_BEARER_TOKEN_BEDROCK` exactly once, at `boto3.client(...)` construction time
... never again per request."* **That is false in botocore 1.43.65.**
`handlers._should_prefer_bearer_auth` calls `get_token_from_environment(signing_name)`
on every request (`botocore/handlers.py:1462`), and that helper reads the real
`os.environ` — it ignores any injected mapping. With the variable restored away,
bearer was never selected, every request signed sigv4 from the default credential
chain, and that chain resolves to a different AWS account than the model ARN.

Two things had to be true at once, which is why the first two attempted fixes
failed:

- The **token** must reach the signer. Supplied through botocore's own injection
  point — `ScopedEnvTokenProvider(session, environ={...})` takes the mapping it
  reads (`botocore/tokens.py`) — so a private mapping holding just this key does
  the job with no global state.
- The **auth scheme** must actually be bearer. `InvokeModel` carries no auth
  trait (`operation_model.auth is None`), so botocore resolves the service
  default, sigv4, unless the env probe fires or the preference names bearer.
  `Config(auth_scheme_preference="httpBearerAuth")` is therefore not optional,
  and is set on this client only.

`TestBearerTokenNeverTouchesTheEnvironment` pins both halves against real
botocore with no network, and asserts `os.environ` is untouched before, during,
and after. The old tests asserted the disproven mechanism (that the token is
visible in `os.environ` during construction) and were rewritten, not deleted —
their subject was real, their premise was not.

**Worth noting for the record:** the env leak that `b18bf09` fixed was itself a
real bug, and the fix was correct about the danger and wrong about the mechanism.
Neither the fix nor the whole-branch review that approved it could have caught
this by reading, because the failure is in botocore's per-request behaviour, not
in ours.

## Defects found by running it, deliberately unfixed

Recorded as triage input, not touched — scoping them out was a deliberate call so
this session stayed a measurement.

1. **A fabricated citation passed the grounding gate at confidence 0.95.** Blind
   draw #3 reported *"2 failed logon attempts followed by a single success,
   indicating a probable password-spraying attack"* and cited `auth_events#1`.
   There are **zero** failed-logon rows anywhere in the identity slice (codes
   present: 4624 x13, 4627 x7, 4648 x5, 4611, 4634, 4647), and `auth_events#1` is
   a single row: `user=bstoll@froth.ly src=127.0.0.1 dest=BSTOLL-L code=4624
   logon_type=11 count=2`. The gate accepted it because the cited *id* had been
   emitted; it never checks that the block beneath supports the claim. This is the
   known limitation in `formatting.format_row`'s docstring, now with a live
   instance — and note the spec puts the equivalent gate at the Aggregator, which
   sees no evidence at all and so could not catch this either.
2. **`parse_finding` swallows markdown-heading labels as observations.**
   `_strip_md` strips `*` and backticks but not `#` (`parse.py:56`), and
   `_FINDING_OBSERVATIONS_RE`'s terminator allows only emphasis and whitespace
   before the label word (`parse.py:43-45`), never a `#`. So a model that writes
   `### CONFIDENCE: 0.85` neither
   terminates the OBSERVATIONS block nor registers the field: draw #4's
   observation list ends, literally, with `### CONFIDENCE: 0.85`. Confidence still
   parsed correctly only because `_CONFIDENCE_RE` searches the whole answer.
   Affects the Tier-1 path only.
3. **The identity analyst is shown network evidence.** Blind draw #2 reported on
   `dst_ip=217.182.164.14` and 34 coinhive DNS lookups, from `uncategorised#12`
   and `#13`. `routing._untagged_target_domains` offers untagged sets to every
   domain the scope's entity kinds imply, so a scope carrying both `user` and
   `ip` hands identity the network rows — while `_IDENTITY_FACTS_BODY` instructs
   it not to infer network activity. The routing is behaving exactly as
   documented ("they were retrieved and paid for"); the tension is between that
   rule and the per-domain prompts, so this is a design question rather than a
   bug.

## The harness

`backend/src/smartops/blind_compare.py` + `smartops-blind-compare`, with
`backend/tests/test_blind_compare.py`. Committed deliberately: the 2026-08-23
comparison was "a standalone comparison script — nothing production calls it yet",
was never committed, and this session had to rebuild it from scratch to answer a
question the previous handover had already queued.

Reuses rather than reimplements: `route`, `pack_evidence`, `run_one`,
`gather_finding`, `analyst_model_from_env`, and `replay._newest_run_in` for run
resolution. Two things it must supply itself, because no run directory carries
them:

- **`scope`** — `BrokerReport.scope` only arrived in `430df12`, so all 25 saved
  reports have `scope: None` while `route()` needs one. Resolution order is
  `report.scope`, then a committed `CASES` table, then a hard failure. Guessing
  was rejected: the scope decides which domains untagged sets reach, so an
  invented one silently changes what each analyst saw.
- **The hypothesis prose** — persisted *nowhere*, in old reports or new ones;
  only `hypothesis_id` (`"cli-hypothesis"`) is saved. The text for this case was
  recovered from the untracked artifact `docs/hard-test.html`. Never inferred from
  `hypothesis_id` or from the fetch `goal`: a goal is a question, and only an
  assertion can anchor.

Which source each came from is recorded in the artifact. A reconstructed input is
a datum about the measurement, not a detail of it.

`--pack-only` routes and packs and calls no model — the zero-cost gate, and the
first thing to run. It is what confirmed the premise was live before any spend:
`auth_events#6` now renders `code=4624 logon_type=11`, a `4648`, and a
`logon_type=7` unlock ten seconds later — the textbook laptop-unlock signature
that both analysts had previously been shown with the discriminating field
stripped.

**One harness bug found the hard way.** The first run exited **0** on thirty
failed calls. Both arms contain their own failures, so a total outage produces an
artifact with the same shape as a successful measurement — same sample count,
same structure. `is_measurement()`/`call_counts()` now detect it, the CLI exits
non-zero with `NOT A MEASUREMENT`, and `ArmStats.failed_calls` puts it in the
artifact. Tests cover both the all-failed and the partial-failure cases.

## Landmines

- **Never stage `backend/src/smartops/bench.py`.** Still `M`, still deliberate,
  verified untouched throughout this session.
- **Never write anything under `.smartops/runs/`.** `write_artifact` refuses an
  `--out` inside that tree and a test pins the refusal: the fixture must not
  become a function of the measurements taken over it.
- The agreement numbers are **lexical proxies**. They rank within-arm against
  between-arm and nothing more. Any claim about *what* an arm concluded has to
  come from reading the recorded text, which is why every draw is stored verbatim.
- `n=5` at temperature 0.6 settles nothing on its own — that is the lesson of
  this whole exercise. Do not quote a single-draw comparison as a result again.

## Still open, unchanged

Everything the previous handover left open is still open, minus the item this
session closed. Specifically: analyst spend still never enters `Budget` (no
`Budget` reference anywhere in `subagent_analysts/`, flagged as Mohamed's
decision), `_parse_citations` still splits on commas only, citation numbering is
still global rather than per-category, `combine()` can still return a decisive
stance at ~0.00 confidence, `_EvidenceCollector` still records structured-output
calls as `Evidence`, and `replay.py` still cannot read VT evidence from the
current enricher path.

The Asana cards ("Findings Pipeline", "Evidence Store", parent "Data Connector")
are still closeable — nothing here changed that. The parked Aggregator ownership
question in `docs/open-questions-for-team.md` now has an extra input: the
empirical case for the Aggregator that would delete Mariam's `combine()` is
weaker than when the question was parked.

## Process note

The previous handover's process note said: *"for this codebase, running it is the
only review that finds these."* This session is a third data point, and a sharper
one — the thing running found was not a defect in new work but a **false premise
in a comment**, load-bearing for a credential path, in code that had been
reviewed and approved. Reading it could not have caught it; the premise was about
botocore's behaviour, and only executing against botocore could disprove it.

The measurement itself makes the same point about method rather than code: the
demo everyone had been reasoning from was n=1 against a distribution whose spread
turned out to be wider than the effect.
