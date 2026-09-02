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
their slice and translating it into plain English, **without ever being told the hypothesis**:

> **What do these rows show — tell us what happened, in order, naming the hosts,
> accounts, addresses, processes and times involved. Do not say what it means, whether it is
> normal or abnormal, whether it is an attack, or who was behind it.**

That is a **plain-English `narrative`** with **cited `observations`** — one distinct thing the
rows state — deliberately *not* a verdict. A verdict is a reading of what the evidence *means*,
and that belongs to the **Analyst Agent**, a separate component that sees both the hypothesis and
all three narratives at once.

The tier compresses ~170 rows per domain into prose that fits the consumer's context budget, every
claim is citation-checked by the grounding gate, and three domains run concurrently — saving cost
and allowing the Analyst Agent to see disagreement where it exists.

| | What it is |
|---|---|
| **In** | a `DomainSlice` and the `Scope` — **no hypothesis**. `gather_finding()` has no parameter that could carry one. |
| **Out** | a `DomainFinding` (narrative, observations, citations) plus audit fields — the reasoning trace and per-call token counts |

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

| Analyst | Evidence format it expects | What it is told to do |
|---|---|---|
| **identity** | `auth_events#N`: `<ts> user= src= dest= action=<success\|failure> app=` | Translate what these rows show: accounts, source and destination, actions and times involved. Group like rows. Do not say what it means. |
| **network** | `reputation#N`; `dns_resolutions#N` (`query=<domain>→<answer>`); `connections#N` (`src:port→dst:port proto bytes action`) | Translate what these rows show: sources, destinations, protocols, counts and times. Which hosts contacted which, when. Do not infer what the reputation verdict means for your host's behavior. |
| **endpoint** | `processes#N` (`host user process parent cmdline`); `reputation#N` (file hash) | Translate what these rows show: processes, parents, lineages and times. Do not infer network volume or authentication history. |

Each body carries a **cross-domain guardrail** matched to its blind spots — identity: *do
not infer process, file or network activity*; network: *a reputation verdict is about the
indicator, not proof our host acted on it — pair it with a DNS or connection row*; endpoint:
*do not infer network volume or authentication history*. This is what "curated, not a
template" means: the network caution would be meaningless in the identity prompt.

The shared footer additionally carries a **reporting floor** (report every distinct pattern;
never drop a set because it looks uninteresting), and a preference for category-named sets over
`uncategorised#N`. Those landed with `temperature=0` — see §7.

**The prompt currently forbids what we now want.** All three domain bodies read *"do not speculate
about intent, a narrative, or draw any broader conclusion"* — the exact reversal that happened
2026-08-31. The rewrite kept the prohibition on intent and broader conclusions, removed only the
one on narrative. A translator has no narrative to spare.

*The prompts are the source of truth for their own wording:
`backend/src/smartops/subagent_analysts/prompts.py`.*

---

## 5. Anti-hallucination & failure containment

Each measure is code, not a request to the model.

- **Citation validation** drops invented ids, in both the trailing `CITATIONS:` line and
  inline observation citations. **Grounding verification** catches a narrative with zero
  valid citations and flags it.
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
- **An observation resting entirely on empty cited blocks is kept, not flagged.** An empty
  result set is legitimate negative evidence — "no failed logons in the window" genuinely
  shows what happened — so penalising it would punish correct reading of an absence.
- **A claim its cited rows do not support is NOT caught, deliberately.** Whether a row
  supports a specific claim is a semantic question, and no code here attempts it. One
  observed draw called an IP "known malicious" whose cited row read `mal=1` of 91. It is not
  undetectable — `Exhibit` carries the real rows, so a reader can check — but it is an open
  gap.
- **Empty-slice short-circuit.** A domain with no routed evidence returns an **empty narrative
  and no observations** with **no model call**, which also removes the temptation to invent a
  citation. **`RetrievalSummary` is the only signal** separating "we looked and found nothing"
  from "we did not look" — that field is load-bearing now.
- **Bounded re-ask.** An unparseable first reply earns exactly one more attempt; both are
  billed. A second failure yields an honest response carrying the reasoning trace.
- **Per-analyst failure containment.** A call that raises becomes an empty narrative naming
  the error. One domain failing never sinks the analysis.

---

## 6. Why there is no combiner

`gather()` decides nothing. It routes, runs the three analysts, projects each to a
`DomainJudgement`, and assembles them into `HypothesisFindings` — attached to the hypothesis,
never shown it. No vote, no confidence math, no `overall_stance` field.

That is a boundary, not a gap. Reading three domains together and deciding whether their findings
support or refute the hypothesis — which is where anchoring risk lives — is the **Analyst Agent**'s
job, a separate component that sees the hypothesis and all three narratives at once.

**The output shape is published and enforced:**
`contracts/schemas/hypothesis-findings.v2.schema.json`, generated by `generate.py` and
asserted against the models in `contracts/tests/test_published_schema.py`. Schema v1 is kept
on disk for replay; v2 is the current wire.

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
  user-turn scaffolding, safety margin) — currently 25,150 tokens. `pack_evidence` caps
  rows per set on a ladder (**200 → 20 → 10 → 5 → 3 → 1 → header-only**) and reports the
  rung. `exhibits_for` re-derives the *same* rung, so the rows handed forward are exactly
  what the analyst read. **Per-domain spare margins as of 2026-08-31:** identity 601, network 500, endpoint 575.
  When the system-prompt reserve shrinks, the pack budget grows for all domains; the reserve is
  measured at import, so any future prompt edit that reduces its length gains evidence budget.
  Network is pinned at exactly `_SAFETY_MARGIN` by construction.
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
| `subagent_analysts/prompts.py` | The Metis preamble, the three blind domain bodies, the shared translation footer. |
| `subagent_analysts/model.py` | `AnalystModel` — the boto3 `invoke_model` client, prompt template, cold-start and throttle retries. |
| `subagent_analysts/parse.py` | `split_reasoning`, `parse_finding`, narrative and citation extraction. |
| `subagent_analysts/analyze.py` | **`gather()`** — the production entry point; `gather_finding`, the grounding gate, `_as_judgement`. |
| `subagent_analysts/shown.py` | The hypothesis-SHOWN arm. **Not in the pipeline** — kept for `blind_compare`, the A/B harness that measured whether seeing the hypothesis anchors the read. |
| `smartops/analyst_cost.py` | CMU-minute billing windows. |
| `smartops/telemetry.py` | `analysis_span` / `analyst_span` — this tier's spans, hand-rolled because Strands cannot reach it. |
| `contracts/reasoning.py` | `DomainFinding`, `DomainJudgement`, `Exhibit`, `HypothesisFindings`. |

**Open, and worth knowing:** the citation coverage validation is **sparse** — `bench.py`'s
`EXPECTED_CITATIONS` covers 3 of 11 cases, so most cannot yet be validated for correctness.
Labelling the remaining BOTSv3 cases is the highest-leverage next work.

---

*This page is tracked in git as of 2026-08-31. Anchors elsewhere are checked by
`docs/check_anchors.py`.*
