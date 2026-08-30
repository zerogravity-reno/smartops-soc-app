# SmartOps SOC — Analyst Subagents (Identity · Network · Endpoint)

> **Audience:** engineers and SOC leads working on the analysis tier.
> **Source of truth:** `docs/architecture.md` is the single map of the system; this page is
> the analyst tier in depth. Decisions and their history live in `docs/PROJECT_DOCS.md`.
> **~5 minute read.**

---

## 1. What they do

The Task Broker ends an investigation with a **`BrokerReport`**: evidence fetched from the
security backends and assembled into typed findings **by code**. Nothing in that tier
reasons about the evidence.

Three analyst subagents read it — **identity**, **network**, **endpoint** — each taking
their slice and deciding one thing, **without ever being told the hypothesis**:

> **What does this evidence show — `benign`, `suspicious`, `malicious`, or
> `inconclusive` — judged only from the evidence shown, with every claim cited to a
> specific row?**

That is a **`Disposition`**, deliberately a different axis from a **`Stance`**
(supports/refutes on a hypothesis). A `Stance` is relative to a claim, and a claim shown to
the analyst is a claim it can be led by — "20 auth events means malicious" plus 20 auth
events reliably yields `supports`. A `Disposition` is answerable from the evidence alone, so
it cannot be anchored by a hypothesis the analyst never saw. **Blind does not mean silent:**
the analyst still judges what it reads; it means the *hypothesis* is not this tier's call.

| | What it is |
|---|---|
| **In** | a `DomainSlice` and the `Scope` — **no hypothesis**. `gather_finding()` has no parameter that could carry one. |
| **Out** | a `DomainFinding` (disposition, confidence, rationale, observations, citations) plus audit fields — the reasoning trace and per-call token counts |

The three run **concurrently** (`asyncio.gather` over `asyncio.to_thread`), so wall-clock
cost is one analyst, not three. Each reasons in its own context window and is never
distracted by another domain's evidence.

---

## 2. The load-bearing claim

> **The analyst can only cite what code showed it.**

`pack_evidence()` returns both the rendered evidence *and* the exact set of header ids it
emitted. Any citation not in that set is dropped and logged. The model never sees raw tool
output — only code-projected rows — so it cannot cite a row that was not retrieved.

---

## 3. Routing — which evidence reaches which analyst

`route()` decides in code, from CIM category and entity kind. Never a model choice.

| Source | Goes to |
|---|---|
| `auth_events` | identity |
| `dns_resolutions`, `connections` | network |
| `processes` | endpoint |
| VirusTotal `ip` / `domain` / `url` | network |
| VirusTotal `file_hash` | endpoint |
| `uncategorised` sets | the domains the scope's entity kinds imply — flagged, never dropped |

**Known gap:** untagged sets fan out by entity kind, so a host in scope sends uncategorised
network rows to identity and endpoint too. That is how a network observation can surface in
an identity finding, crossing the cross-domain guardrail in §4 by *routing* rather than by
prompt. The fix belongs at the SIEM tier — reliable CIM tagging — not here.

---

## 4. What each analyst is told

Every prompt is **the Metis persona (verbatim) + a curated domain body**. The persona keeps
the output format identical across domains; the body is hand-written per domain and **never
mentions a hypothesis** — not even to say one is withheld, because naming one tips the model
off that a theory exists and invites it to guess.

| Analyst | Evidence format it expects | Threat catalog |
|---|---|---|
| **identity** | `auth_events#N`: `<ts> user= src= dest= action=<success\|failure> app=` | brute force, password spraying, foreign/first-seen source, impossible travel, off-hours logons, service-account use, lockouts |
| **network** | `reputation#N`; `dns_resolutions#N` (`query=<domain>→<answer>`); `connections#N` (`src:port→dst:port proto bytes action`) | malicious/low-rep indicators, beaconing, DNS tunneling, large transfers, rare or new domains, unusual ports |
| **endpoint** | `processes#N` (`host user process parent cmdline`); `reputation#N` (file hash) | malicious hashes, living-off-the-land binaries, suspicious lineage, encoded command lines, execution from temp/appdata |

Each body carries a **cross-domain guardrail** matched to its blind spots — identity: *do
not infer process, file or network activity*; network: *a reputation verdict is about the
indicator, not proof our host acted on it — pair it with a DNS or connection row*; endpoint:
*do not infer network volume or authentication history*. This is what "curated, not a
template" means: the network caution would be meaningless in the identity prompt.

The shared footer additionally carries a **reporting floor** (report every distinct pattern;
dedupe by row and reason), a **`suspicious`/`inconclusive` tie-break** (a citable anomalous
row is at least `suspicious`; a clean full slice is `benign`), and a preference for
category-named sets over `uncategorised#N`. Those landed with `temperature=0` — see §7.

*The prompts are the source of truth for their own wording:
`backend/src/smartops/subagent_analysts/prompts.py`.*

---

## 5. Anti-hallucination & failure containment

Each measure is code, not a request to the model.

- **Citation validation** drops invented ids, in both the trailing `CITATIONS:` line and
  inline observation citations. **Grounding downgrade** neutralises a decisive disposition
  whose citations all fail to resolve.
- **`citation_evidence` is frozen at finalisation**, so a stored finding's grounding can be
  audited without recomputing `route()`.
- **The evidence fence cannot be forged.** Every projected row value is sanitised before it
  becomes prompt text — whitespace collapsed, `&`/`<`/`>` escaped. Without this, an
  attacker-controlled field could inject a newline, close the `</evidence>` fence, and forge
  a second block under a header id that already passes citation validation.
- **The query that retrieved a set is withheld.** SPL written to test the hypothesis often
  contains the suspect indicator; on one measured run, 11 of 35 network-slice headers would
  have named the hypothesis subject through that channel alone. It stays in
  `ResultSet.query`, `report.json` and `Exhibit.query` — out of the prompt, not out of the
  audit trail.
- **A decisive disposition resting entirely on empty cited blocks is flagged, not
  downgraded.** An empty result set is legitimate negative evidence — "no failed logons in
  the window" genuinely supports `benign` — so penalising it would punish correct reasoning
  about an absence.
- **A claim its cited rows do not support is NOT caught, deliberately.** Whether a row
  supports a specific claim is a semantic question, and no code here attempts it. One
  observed draw called an IP "known malicious" whose cited row read `mal=1` of 91. It is not
  undetectable — `Exhibit` carries the real rows, so a reader can check — but it is an open
  gap.
- **Empty-slice short-circuit.** A domain with no routed evidence returns `inconclusive`
  with **no model call**, which also removes the temptation to invent a citation.
- **Bounded re-ask.** An unparseable first reply earns exactly one more attempt; both are
  billed. A second failure yields an honest `inconclusive` carrying the reasoning trace.
- **Per-analyst failure containment.** A call that raises becomes an `inconclusive` naming
  the error. One domain failing never sinks the analysis.

---

## 6. Why there is no combiner

`gather()` decides nothing. It routes, runs the three analysts, projects each to a
`DomainJudgement`, and assembles them into `HypothesisFindings` — attached to the hypothesis,
never shown it. No vote, no confidence math, no `overall_stance` field.

That is a boundary, not a gap. Reading three domains together and reasoning about the
hypothesis — which is where anchoring risk lives — is the **Analyst Agent**'s job, a separate
component that sees the hypothesis and all three judgements at once.

**The output shape is published and enforced:**
`contracts/schemas/hypothesis-findings.v1.schema.json`, generated by `generate.py` and
asserted against the models in `contracts/tests/test_published_schema.py`.

---

## 7. The model & how it is invoked

| | Broker / fetch subagents | Analyst subagents |
|---|---|---|
| Model | Claude Sonnet (Bedrock Converse) | Foundation-Sec-8B-Reasoning (Bedrock **imported**) |
| Call | Strands `Agent` | **raw `invoke_model`** — prompt in, text out |
| Prompt | messages + tool schemas | one string: `<\|begin_of_text\|>\n<\|system\|>…<\|user\|>…<\|assistant\|>\n<think>` |
| Structured output | yes | **none available** — no tool calling, no JSON mode, no constrained decoding |
| Cost | per token (`Budget`) | per **CMU-minute** (`analyst_cost`), not per token |
| Tracing | Strands auto-instruments | hand-rolled spans (`analysis_span`, `analyst_span`) |

- **Custom chat template.** `<|system|>`, `<|user|>`, `<|assistant|>` and `<think>` are this
  model's own special tokens (ids 128264–128268), *not* the Llama-3.1 base's
  `<|start_header_id|>` scheme. The generation prompt seeds `<think>`, so the model reasons
  first and then emits the labelled block; code splits on `</think>`. The template must match
  the published `chat_template` byte for byte — a test pins it.
- **Greedy decoding.** `temperature=0`, deliberately not the model's shipped 0.6 (its
  *conversational* default). At 0.6 one evidence slice produced three of the four possible
  dispositions across five draws. At 0 the draws are byte-identical — **on a warm model
  copy**; the first call after a scale-up has been observed to differ.
- **Evidence budget derived from a 32,768-token window, not a fixed number.**
  `_PACK_TOKEN_BUDGET` is the window minus named reserves (system prompt, generation,
  user-turn scaffolding, safety margin) — currently 25,751 tokens. `pack_evidence` caps
  rows per set on a ladder (**200 → 20 → 10 → 5 → 3 → 1 → header-only**) and reports the
  rung. `exhibits_for` re-derives the *same* rung, so the rows handed forward are exactly
  what the analyst read.
- **Cold-start retry.** Imported models are evicted when idle and raise
  `ModelNotReadyException` on the first call; `AnalystModel` waits and retries. Botocore-level
  adaptive retries cover throttling, which three concurrent analysts against one copy will hit.
- **Bearer-token auth** is injected via botocore's `ScopedEnvTokenProvider` — a private
  credential mapping scoped to this client — rather than a process-wide environment variable.
- **Cost is wall-clock.** Bedrock bills imported models per Custom Model Unit per minute in
  5-minute windows from the first successful invocation, scaling to zero after 5 idle minutes.
  So the concurrent fan-out costs the same as one analyst. Needs
  `SMARTOPS_ANALYST_CMU_COUNT` to print a dollar figure; reports "cost unknown" rather than
  guessing.

**Config** (env): `SMARTOPS_ANALYST_MODEL_ARN`, `_API_KEY`, `_TEMPERATURE` (**0**), `_TOP_P`
(0.95), `_MAX_GEN_LEN` (3072), `_READY_RETRIES` / `_WAIT_SECONDS`, `_CMU_COUNT` / `_CMU_PRICE`.

---

## Appendix — Module map

| Module | Responsibility |
|---|---|
| `subagent_analysts/routing.py` | `route()` — the three category/VT-kind/entity-kind maps. |
| `subagent_analysts/formatting.py` | Per-record-type field projectors; the citable header; `_sanitise`. |
| `subagent_analysts/packing.py` | The row-cap ladder, `blocks()`, `valid_citation_ids()`, `exhibits_for()`. |
| `subagent_analysts/prompts.py` | The Metis preamble, the three blind domain bodies, the shared finding footer. |
| `subagent_analysts/model.py` | `AnalystModel` — the boto3 `invoke_model` client, prompt template, cold-start and throttle retries. |
| `subagent_analysts/parse.py` | `split_reasoning`, `parse_finding`, disposition normalisation. |
| `subagent_analysts/analyze.py` | **`gather()`** — the production entry point; `gather_finding`, the grounding gate, `_as_judgement`. |
| `subagent_analysts/shown.py` | The hypothesis-SHOWN arm. **Not in the pipeline** — kept for `blind_compare`, the A/B harness that measured whether seeing the hypothesis anchors the read. |
| `smartops/analyst_cost.py` | CMU-minute billing windows. |
| `smartops/telemetry.py` | `analysis_span` / `analyst_span` — this tier's spans, hand-rolled because Strands cannot reach it. |
| `contracts/reasoning.py` | `DomainFinding`, `DomainJudgement`, `Exhibit`, `HypothesisFindings`. |

**Open, and worth knowing:** the answer key is **sparse** — `bench.py`'s
`EXPECTED_DISPOSITIONS` covers 3 of 11 cases, so most verdicts can still only be shown
consistent, not *correct*. Labelling the remaining BOTSv3 cases is the highest-leverage
next work.

---

*This page is untracked by design. Anchors elsewhere are checked by
`docs/check_anchors.py`.*
