# SmartOps SOC — Findings Pipeline & Evidence Store

> **Audience:** engineers, SOC leads, and stakeholders who want to know how a row travels
> from a security backend to an analyst's judgement, and where the raw output it came from
> is kept.
> **Scope** (Asana "Findings Pipeline" and "Evidence Store", siblings under "Data
> Connector"): the two subsystems between the Task Broker and the domain analysts.
> **Source of truth:** `docs/architecture.md` §4–5 and the code in `smartops.projection`,
> `smartops.subagent_analysts.{routing,formatting,packing}`, `smartops.broker` and
> `smartops.replay`. Code-level detail is in the appendices.
> **Companion pages:** `docs/confluence-task-broker-architecture.md` (the fetch tier that
> produces the input), `docs/confluence-subagent-analysts.md` (the analysts that consume
> the output).

> ⚠️ **Status, 2026-08-26.** Both subsystems work. **All three closure blockers are
> closed** (§11). **Three items are open**, named in §10: the hardcoded `hypothesis_id`,
> the missing edr/ndr projector, and `combine()`'s absent confidence floor.
>
> Every figure here was produced by **executing** the code against the 26 saved runs under
> `.smartops/runs/` (§9), not by reading it. For this codebase, "the tests pass" and "I
> read the code" have both failed to catch a broken data path. Method: Appendix C.

---

## 1. Overview

Two subsystems sit between the Task Broker and the domain analysts, and almost every
misunderstanding of this layer comes from conflating them.

**The Findings Pipeline** carries **projected, typed rows** from a tool result to a domain
analyst's judgement and out to the Analyst Agent. Code projects the rows, routes them,
renders them, and checks the citations that come back; the only model-authored step is the
judgement at the end.

**The Evidence Store** holds the **raw tool output those rows were projected from**, on
disk, addressable by id — so a judgement can be traced to what produced it, audited, or
replayed offline at zero cost.

| | Findings Pipeline | Evidence Store |
|---|---|---|
| **Carries** | typed rows (`ResultSet.rows`, `VtVerdict`) | raw tool payloads (`Evidence.raw`) |
| **Lives** | in memory during a run, persisted in `report.json` | on disk, in `evidence.json` |
| **Read by** | `route()` → the analysts → the Analyst Agent | replay, audit, citation resolution |
| **Purpose** | produce a grounded judgement | prove what the judgement rested on |
| **Written by** | `projection.project()` | `broker.save_run_artifacts()` |

They are joined by **one thing only: an id** — not by data flow. See §3.

---

## 2. Core design principles

| # | Principle | What it means in practice |
|---|-----------|---------------------------|
| 1 | **Code projects every row; a model authors none** | `project()` turns raw tool output into typed `Findings` with no model call in it. |
| 2 | **Routing is a fact, not a model choice** | `route()` decides which evidence reaches which analyst from CIM category and entity kind, in code. |
| 3 | **The pipeline never reads the store** | Nothing in the analysis path opens `evidence.json` — §3. |
| 4 | **No model authors an id, at any hop** | A model may *cite* an id, never *create* one. |
| 5 | **Absence is rendered, not omitted** | An empty result set is still printed, with `rows=0`: a missing block is indistinguishable from a question never asked. |
| 6 | **Nothing is capped silently** | `pack_evidence()` shrinks a row cap down a ladder rather than truncating mid-block, and reports the rung, the rows withheld, and the shrink. |
| 7 | **A stored artifact must be readable by the system that wrote it** | Both halves round-trip, including artifacts written before the fields that make them typed existed. |

---

## 3. The load-bearing claim: the pipeline never reads the store

The property a reader gets backwards by default:

> **The analysts work off `ResultSet.rows` inside `report.json`. `evidence.json` is written
> alongside it, for replay, audit, and citation resolution — and no code path in the
> analysis pipeline ever reads it.**

Raw tool output is captured **once**, by `_EvidenceCollector`'s `AfterToolCallEvent` hook,
then forks two ways that never rejoin: **up** into `project()`, which writes typed rows onto
`SubtaskResult.findings`, and **down** into `Evidence`, persisted verbatim. `route()`,
`pack_evidence()`, the analyst, `_finalize_finding()` and `_as_judgement()` all sit on the
first branch and cannot see the second.

**The cost.** When projection under-reports, the correct rows sit in `evidence.json`
unreachable by any code path. Three real defects survived on exactly that:

| What went wrong | Why nothing looked broken |
|---|---|
| Row projectors matched CIM field names against Windows/Stream spellings, so **~97% of `processes` rows rendered blank** (1,648 of 1,887) | The header still said `rows=N` and the id stayed valid, so a fabricated claim citing `processes#1` passed the grounding gate |
| `structuredContent` was not unwrapped, so 54 SIEM items with real rows projected as `row_count=0` | The evidence was captured correctly throughout, so citations resolved and nothing failed |
| A log value could close the `</evidence>` fence and forge a second block under a valid header id | The forged block was well-formed and its id genuinely valid — the gate had nothing to reject |

The separation is kept anyway: letting an analyst read raw tool output is the one thing the
engine exists to prevent (`Evidence` is "never shown to an LLM directly"). The mitigation is
not to bridge the gap but that **the store is now the fixture every evidence-path change is
tested against.**

---

## 4. Architecture

> 🖼️ **Attach `docs/images/findings-pipeline-flow.png` here when pasting into Confluence**
> (source: `.../findings-pipeline-flow.svg`).
> *Caption: Raw tool output is captured once and forks. Upward, code projects it into typed
> rows, routes them by CIM category, packs them under a token budget, and carries the
> analyst's judgement out to `HypothesisFindings` — the analyst (amber) is the only step a
> model authors. Downward, the same output is persisted raw. The two never rejoin: no
> pipeline step reads `evidence.json` (red), and the only thing crossing the gap is the
> `Evidence.id` chain (violet).*

The three analysts run **concurrently** (`asyncio.gather` over `asyncio.to_thread`); the
diagram shows one lane for readability. Fan-out and fan-in belong to the analyst tier (§4 of
the Analyst Subagents page).

---

## 5. The pipeline path, in order

Nine steps. **One involves a model.**

| Step | Code | What it does |
|---|---|---|
| 1 | `projection.project()` — `projection.py:348` | Raw tool output → typed `SiemFindings`/`VtFindings`, dispatching to `project_siem` (`:183`) or `project_vt` (`:268`). Every family with a projector must dispatch *here*: a call site that appended one projector itself is why a vt subagent holding real evidence once reported `findings=None`. |
| 2 | `SubtaskResult.findings` — `subtask.py:473` | Carries the typed payload into `BrokerReport`. A **discriminated union**, so a JSON round trip returns the right subclass rather than the empty base class. |
| 3 | `routing.route()` — `routing.py:95` | Splits the report into three `DomainSlice`s by CIM category and entity kind. Untagged sets are offered to the domains the scope's entity kinds imply, flagged rather than dropped — they were retrieved and paid for. |
| 4 | `packing.pack_evidence()` — `packing.py:177` | Renders a slice under a 20k token budget, shrinking the row cap down a ladder (20 → 10 → 5 → 3 → 1 → header-only) instead of truncating mid-block. **Returns the cap it settled on**, so `exhibits_for` renders at the same rung. |
| 5 | `packing.blocks()` — `packing.py:65` | **The single definition of block order and citation numbering.** `_render`, `valid_citation_ids` (`:159`) and `exhibits_for` (`:129`) are thin readings of it. |
| 6 | **the analyst** | Reads the packed evidence — the projected rows, rendered as text — and authors a `Disposition`, observations, and citations. **The only model-authored step.** It reasons over those rows; what it never sees is the raw tool output behind them, and it can cite only the ids code minted. |
| 7 | `analyze._finalize_finding()` — `analyze.py:488` | The grounding gate: drops citations that do not resolve and observations resting only on invented ids, downgrades an ungrounded decisive disposition to `inconclusive`, and **freezes `citation_evidence`**. |
| 8 | `analyze._as_judgement()` — `analyze.py:528` | Projects onto the wire: audit fields (`reasoning_trace`, token counts) off, `Exhibit`s on. |
| 9 | `analyze.gather()` — `analyze.py:587` | Assembles `HypothesisFindings` plus `_retrieval_summary()` (`:643`). Assembles — does not decide. |

Steps 6–9 belong to the analyst tier and appear here because the gate at step 7 and the
projection at step 8 are what make a *stored* judgement traceable.

### Why numbering is per category, not per slice

`blocks()` numbers within each category. One counter over the whole slice numbered by
position instead, so the network slice of `cli-20260825T100434` emitted `connections#1..#9`
then `dns_resolutions#10..` — **with no `dns_resolutions#1`, the exact worked example the
analyst prompts hand the model.** A model citing it failed validation, lost the observation,
and was downgraded to `inconclusive` — which reads as a cautious analyst, not a bug, and is
why it survived.

---

## 6. The two-layer split: the model authors a judgement, code supplies every row

The anti-fabrication mechanism the layer rests on. From `smartops/projection.py`:

> The model authors a small assessment and says which CIM category each of its queries was
> after; **code** supplies every row, from what the tools actually returned.
>
> **Neither half can forge the other:** a model that never sees the rows cannot invent them,
> and code that never reads the prompt cannot be talked into re-categorising.

| Authored by the model | Assembled by code |
|---|---|
| which CIM category *its own query* was for | which rows land in which category |
| an assessment of what it covered and did not | every row of every result set |
| (later) the disposition and observations | `Evidence`, with ids and provenance |
| — | every id, at every hop |

It is also why `Assessment` is deliberately small (`contracts/findings.py`): a model forced
to emit retrieved rows as structured output would spend them as *output* tokens against a
cumulative `Limits(output_tokens=)` ceiling, and would admit hallucinated field values into
evidence — which `contracts.subtask.Evidence` forbids.

The category is the model's one contribution, and deliberately a classification of **its own
action** — knowable without inspecting a row. When it is missing, `_infer_cim_category()`
derives one from the SPL predicates (`stream:dns` → `dns_resolutions`, `EventCode=4688` →
`processes`); anything still untagged lands in `SiemFindings.uncategorised`, **an honesty
bucket, not a fifth category.** A full bucket is itself a signal that the model's reported
queries have stopped matching the ones it ran.

---

## 7. The Evidence Store

| Piece | Code | Note |
|---|---|---|
| **Write** | `save_run_artifacts()` — `broker.py:1079` | `<base>/<task_id>/<stamp>/` holding `report.json` + `evidence.json`, plus a sibling `latest.txt`. |
| **Read (report)** | `load_run_artifacts()` — `broker.py:1132` | Typed round trip, no re-fetch and no model call. Needs the callable `Discriminator`s at `subtask.py:400`/`:422` for payloads written before `tool_family` existed. |
| **Read (evidence)** | `load_evidence_from_file` (`replay.py:57`) / `load_evidence_from_run` (`:116`) | Resolves a bare case id via `latest.txt`, else the highest stamp — zero-padded, so a lexical sort is chronological. |
| **Address one record** | `evidence_by_id()` — `replay.py:148` | Keyed by `Evidence.id`, to resolve a single citation without scanning. |
| **The id** | `evidence_id()` — `subtask.py:63` | `f"{task_id}:{index}"`. **One formula, four minting sites** — `_EvidenceCollector.evidence` (`subagents/__init__.py:338`), `project_siem` (`projection.py:183`), `project_vt` (`:268`), the VT enricher (`broker.py:333`) — which must agree exactly or a stored `ResultSet.evidence_id` points at nothing. |
| **Replay** | `ReplayToolset` — `replay.py:214` | Serves recorded output offline: exact match → fuzzy → tool-only → an honest cache miss. Zero cost, no Splunk. |

### Why the path is timestamped

Keyed on `task_id` alone, every run of a case silently overwrote the previous one:

- the bench runs each case **N times** for a median and a spread, so **N−1 of every N runs
  left no artifact**;
- a `--scripted` run, which calls no model and retrieves nothing, would replace a live one
  that cost real money. **It happened** — a test-suite run destroyed the artifact of the
  live run being measured.

Two runs can share a millisecond, so the directory is created with `exist_ok=False` and a
numeric suffix on collision; silently reusing it would reintroduce the overwrite. `latest.txt`
is a plain file, not a symlink, because on Windows a symlink needs developer mode or
elevation and losing a run record to a missing pointer is the wrong trade.

---

## 8. The link contract — what makes the two subsystems one story

A citation the analyst writes (`auth_events#1`) is a **position in a rendering**, and on its
own resolves only against a recomputed routing — so a change in routing order would silently
re-target every stored citation. Three fields close that gap:

```
DomainFinding.citations           "auth_events#1"              what the analyst wrote
  └─► DomainFinding.citation_evidence
          {"auth_events#1": ["cli-…:siem:tooluse_…:2"]}        frozen at finalisation
        └─► ResultSet.evidence_id  "cli-…:siem:tooluse_…:2"    the record it came from
              └─► Evidence.id      in evidence.json            the raw tool output

full id shape:  {task_id}:{family}:{toolUseId}:{index}
                    │        │         │          │
              hypothesis  domain   dispatch   position in the capture list
```

**On the wire the link changes carrier, and this is easy to get wrong.**
`_as_judgement` projects a `DomainFinding` onto a **`DomainJudgement`**, which is what
`HypothesisFindings` and therefore `findings.json` actually hold — and `DomainJudgement`
has **no `citation_evidence` field**. It carries `citations` plus one **`Exhibit` per kept
citation**, and the ids ride on `Exhibit.evidence_ids`:

```
DomainJudgement.citations   ["auth_events#1", …]               the kept citations
  └─► DomainJudgement.exhibits[n]
        ├── citation        "auth_events#1"                    which citation this is
        ├── evidence_ids    ["cli-…:siem:tooluse_…:2"]         the same link, on the wire
        ├── rows            the projected text the analyst read
        ├── row_count       so a rows=0 exhibit is legible as one
        └── query           the SPL, withheld from the analyst, restored here
```

So `citation_evidence` is the **internal** freeze, kept with the audit fields; the exhibit
is what the Analyst Agent receives, and it is strictly better for that consumer — a
pointer needs the store, whereas the exhibit carries the rows with it. An earlier version
of this page drew `citation_evidence` hanging off `DomainJudgement`, which does not exist.

Three properties are load-bearing:

1. **No model authors an id, at any hop.** A model may cite one; it can never create one.
2. **`toolUseId` is the broker-dispatch join** — the only component separating two dispatches
   of the same family for the same hypothesis. Remove it and a re-dispatch overwrites the
   first dispatch's evidence ids.
3. **`citation_evidence` freezes the resolution at finalisation.** Until that decision was
   *recorded*, tracing a stored verdict to its rows meant recomputing the routing and
   trusting it came out identical.

### `Exhibit` — for a consumer that holds no store

A pointer is only useful to whoever holds the store, and the Analyst Agent may hold nothing.
So `_as_judgement()` attaches **`Exhibit`** (`reasoning.py:231`): the cited rows themselves,
rendered exactly as the analyst read them — same row cap, same `_sanitise`d text, not a
re-render. Carrying *every* routed block would be the opposite failure: on
`cli-20260825T100434` each domain was routed **32–35 blocks and cited one**, so the exhibit
set is about **2% of the pack.**

> **One asymmetry, because it looks like an oversight and is not.** `Exhibit.query` carries
> the SPL the analyst was **not** shown. The domain analyst is blind to the hypothesis and a
> query written to test it leaks it; the Analyst Agent is not blind and cannot judge an empty
> cited set without knowing what was asked. The query left the prompt, not the audit trail —
> it is untouched in `ResultSet.query`, `report.json`, and here. See §10.5.

---

## 9. Verified facts

Executed on 2026-08-26 against the 26 runs under `.smartops/runs/`, and **re-run on
2026-08-27 with no Splunk and no model reachable** — every figure below still holds.
Method, and the one figure that came out different from the document it was inherited
from: Appendix C.

| Fact | Result |
|---|---|
| saved reports that load (was **22 of 24 failing** — the 2026-08-24 blocker) | **26 of 26**, 0 failing. One run predates the timestamped layout (2026-08-14) and sits a directory shallower; both read doors handle it |
| evidence **headers** naming the hypothesis subject (was 2 / 11 / 2) | **0** of 32 / 35 / 34 for identity / network / endpoint. 19 network *row* lines mention it legitimately: `query=` is a real DNS row field |
| per-category citation numbering | **contiguous from `#1`** in all 9 category/slice pairs; network emits `connections#1..#9` **and** `dns_resolutions#1..#8` |
| model-authored answer records on disk | **60**, across **22 of 26** evidence files |
| their content | two distinct strings — 35 × `"Successfully validated SiemAnswer structured output"`, 25 × the `VtAnswer` equivalent. **No answer content at all** |
| answer tools reachable in a replay index | **0** across all 26 runs; the read door drops all 60 |
| `report.trace_id` on a fresh run | populated — `5c5dc4e16617d30965e23d1a1a71574c` |
| *analysis* artifacts exercising the link contract | **none yet** — 0 of 10 carry a top-level `task_id`, 0 carry any `citation_evidence` (§11) |
| stored result sets, and how many carry an `evidence_id` | **875** = 846 SIEM result sets + 29 VT verdicts; **72** carry one, all in `cli-20260825T100434` (§11) |
| a stored category the row set's own query contradicts | **0** of the 545 result sets whose query infers a category at all (§10.7) |
| tool records reachable for replay | **788** across 23 runs, **0** of them model-authored |
| runs that carry a `scope`, and so can be routed without reconstructing one | **1 of 26** — `BrokerReport.scope` postdates `430df12`, so replaying an older run means rebuilding its scope |
| the link contract, on a live blind run over saved evidence (2026-08-27) | **10 citations kept, 10 exhibits, 14 of 14 `Evidence.id`s resolving** against the run's 72-record `evidence.json` (§11) |

---

## 10. Known limitations & follow-ups

**The three items marked OPEN are not fixed.**

### 10.1 `hypothesis_id` is hardcoded where it should be generated — **OPEN**

`main.py:666` hardcodes `hypothesis_id: "cli-hypothesis"` on every CLI run, and a fresh run
today still does. All **9** `assessment.json` files carry that value; the one `findings.json`
is older still and carries **no `hypothesis_id` at all** — a bare list of three
pre-`HypothesisFindings` domain findings, with no `task_id`, `run_id` or `disposition`.

**This is not by design.** The id should be *generated* per hypothesis; the reason it is a
constant is that nothing generates one — the Task Broker is not that component, and the
Analyst Agent that would be is a separate epic with no code. **Generating it is scheduled
work for a later sprint**, not an accepted state.

Until it lands, **do not present hypothesis-level traceability as working.** The
`task_id`/`run_id` joins are real and populate on a fresh run; the hypothesis join carries no
information. Nothing in the codebase joins on it today, so the field is inert rather than
wrong — but a reader who filters by it gets every CLI run ever recorded.

### 10.2 60 model-authored records are still in the store — filtered on read, not deleted

`_EvidenceCollector` now refuses them **at capture** (`subagents/__init__.py:314`), but 22
runs predate the skip and hold 60 between them. They are filtered at **both read doors** as
of `e3dcd99`; `include_model_answers=True` still reads them for a forensic look at disk.

**Why they were not purged** — the clearest illustration of why the id shape matters:
`evidence_id()` is `f"{task_id}:{index}"`, so deleting a record **renumbers every record
after it** and silently re-targets every stored citation, the exact failure §8 exists to
prevent. Ids travel *inside* each record and are never recomputed from position, so dropping
one on *read* re-targets nothing. Filtering is safe; deleting is not.

What they did before the filter, neither of it theoretical:

- **They became citable evidence.** `_query_of` lifts the longest search-looking string out of
  a tool input and the answer's own `queries_run` supplied one, so the model's structured
  answer was filed under a **real CIM category** and reached the analysts as a citable
  `auth_events#N` **backed by the model's own words.**
- **They became tools.** `get_replay_tools_for_family` (`replay.py:321`) mints one replay tool
  per recorded name, so an unfiltered record became a tool literally called `VtAnswer` that
  handed a replayed subagent **the model's own prior answer as though a tool had returned it.**

Both are closed, and §9 confirms none of the 60 is reachable.

### 10.3 edr/ndr evidence would reach no analyst — **OPEN**

`project()` has projectors for **siem and vt only**, and `route()` skips a `None` findings
payload — so an edr or ndr subagent could retrieve rows, have them captured as `Evidence`,
and contribute **nothing** to any analyst.

**Latent today**: both families are always REJECTED for want of an MCP server, and a rejection
captures no evidence. **Live the day a connector lands.** `route()` now warns loudly
(`routing.py:132-138`) rather than passing over it silently, because the silence was the real
defect — the analysts would simply see less, with nothing saying so.

**It stays open deliberately.** A projector's job is to bucket rows into typed categories, and
no edr or ndr vendor has been chosen, so there is no row shape to bucket against. Writing one
now would mean guessing an envelope — and a guessed projector that returns non-`None`-but-empty
findings is **worse than the gap**, because it silences the warning above while still showing
the analysts nothing. The fix belongs **with the connector that defines the row shape.**

### 10.4 The store's older artifacts are read by inference, not declaration

A plain string discriminator refuses any payload without `tool_family` — every artifact
written before that field existed, failing with `union_tag_not_found`. So the discriminators
are **callable** (`subtask.py:400`/`:422`): trust the tag when present, fall back to the shape
when not. The shapes are unambiguous and always have been (`VtFindings` alone carries
`verdicts`, `SiemFindings` alone carries CIM buckets), so this recovers the subclass exactly
rather than guessing.

It works and it is tested — but **23 of the 24 reports that carry data are read by inference
from shape rather than by declaration**: by payload, **123 untagged against 14 tagged**, the
one fully tagged run being `cli-20260825T100434`, written after the discriminator landed. (The
other 2 of the 26 carry no typed payload at all; nothing was retrieved.) New artifacts always
carry the tag, so this ages out on its own — but it is inference, and should be named as such.

### 10.5 The query left the analyst's header on a structural argument, not an empirical one

`format_result_set` used to print the SPL query in each header. It no longer does, and the
reasoning needs stating precisely, because it is easy to overclaim.

**What was measured:** on `cli-20260825T100434`, **11 of the network slice's 35 headers named
the hypothesis subject**, and so did 2 of the identity slice's — a domain with no business
knowing a theory existed. That is a leak *channel*, demonstrated.

**What was not measured:** that it changed any verdict. **Do not cite the leak fix as evidence
that anchoring was occurring.** The anchoring demo that originally justified the blind redesign
did not survive re-measurement
(`docs/sessions/handover_2026-08-25_blind-vs-shown-remeasured.md`): it rested on a since-fixed
projector bug and was **one draw from a distribution wider than the effect it claimed**, and at
n=15 two of three domains show no arm-level effect distinguishable from each arm's own
resampling noise. The channel is closed on the structural argument instead: **a query the
analyst is never shown cannot leak a hypothesis, whether or not the bias was ever proven.**

Why nobody caught it earlier: `blind_compare.py` **holds evidence fixed across arms**, so the
leak was a constant in every arm *including the blind control* — which is why that harness
could not have detected it.

### 10.6 `combine()` has no confidence floor — **OPEN (dead path)**

`combine()` (`analyze.py:365`) has no floor back to `inconclusive`: a lone `supports` at 0.01
confidence returns `('supports', 0.01)`, a decided stance at essentially no confidence. It sits
on the hypothesis-shown path production no longer calls — nothing in `main.py` reaches it, and
the live path is `gather()`, which has no combiner by contract. **Dead code that would mislead
if revived**, recorded so whoever revives or replaces it (the Analyst Agent epic) does not
inherit it blind.

### 10.7 The model's CIM tag outranks the query it could be read from

`project_siem` files a result set under the category the model reported for that query
(`projection.py:205`). `_infer_cim_category` (`:121`) can derive the category independently,
straight off the SPL predicates — but it is consulted **only when the model's tag is absent or
not a valid bucket.** When the tag and the query disagree, the tag wins and the inference is
never evaluated.

The consequence is a misroute, not a bad row. A `sourcetype=stream:dns` query tagged
`auth_events` puts DNS rows in `SiemFindings.auth_events`; `route()` sends `auth_events` to
**identity** (`routing.py:35`), whose prompt tells it it cannot see network activity. The
network analyst never sees those rows, and the rows themselves are intact and citable the
whole way.

**As of 2026-08-27 the disagreement is computed and logged** (`projection.py`), on the same
principle as `route()`'s no-projector warning: the tag still decides, so routing is unchanged,
but a mislabelled query is no longer silent. A related warning fires when the tag lookup
misses entirely while the model *did* report queries — that is a mis-picked join key
(`_query_of` selects the longest search-looking string in a tool input), which is a different
thing from an untagged query and used to be indistinguishable from one.

**Measured across the whole history: it has not happened yet.** Of the 875 stored result
sets, 545 carry a query from which `_infer_cim_category` derives a category at all, and in
**0** of those does the derived category contradict the bucket the rows were filed under
(§9). So the warning is silent on every run on disk — which is what makes it worth having:
the first time it fires, it will be a real event and not noise.

Whether code should *override* the tag when it can read the truth is a live question and is
**not** settled here: the category is the one thing the model is asked to contribute (§6), and
inverting that precedence changes which analyst sees what.

---

## 11. Closure state

The 2026-08-24 audit recorded three gaps blocking closure of **"Findings Pipeline"**,
**"Evidence Store"** and their parent **"Data Connector"**. **All three are closed:**

| Gap | State |
|---|---|
| 1 — findings 4–7 uncommitted | **closed** — committed, tree clean |
| 2 — 22 of 24 reports fail to load | **closed** — **26 of 26 load** (§9) |
| 3 — artifact linking unstarted | **closed in the contracts** — `ResultSet.evidence_id`, `HypothesisAssessment.task_id`/`run_id`, `AnalystVerdict.citation_evidence`, `DomainFinding.citation_evidence`, `Exhibit.evidence_ids` all present, and `report.json` carries an `evidence_id` per result set. **Caveat below.** |

> ✅ **The caveat on gap 3 is now closed by a live run.** On **2026-08-27** the production
> blind path (`gather`) was run over the saved evidence of `cli-20260825T100434` — real model
> calls, no Splunk, no hypothesis passed — and the artifact it produced is traceable end to
> end: **10 citations kept, 10 exhibits attached** (one per kept citation, none stray),
> carrying **14 distinct `Evidence.id`s of which 14 resolve** against that run's 72-record
> `evidence.json`. `task_id` and `run_id` populate; `hypothesis` is `null`, as it must be
> when none is given.
>
> Two things that remain true. The **committed** artifacts still do not exercise it: all 10
> under `.smartops/runs/` (nine `assessment.json`, one `findings.json`) predate the fields —
> **0 carry a top-level `task_id`, 0 carry any `citation_evidence`** — and the live run above
> deliberately wrote outside that tree, which is a protected fixture. And on the fetch side
> **72 of the 875 stored result sets carry an `evidence_id`**, all 72 in that same run. So the
> chain is proven in code and by execution, and still almost absent from the history, for the
> plain reason that little has run since the fields landed.

The audit's "unscheduled Important tier" of five is **four closed, one dead-path**:

| Item | State |
|---|---|
| `_parse_citations` split on commas only | fixed |
| citation numbering global rather than per-category | fixed (§5) |
| `_EvidenceCollector` recording structured output as `Evidence` | fixed at capture, and now at both read doors (§10.2) |
| `replay.py` could not read VT evidence | resolves |
| `combine()` has no confidence floor | **open — dead path** (§10.6) |

> **The decision to close the Asana cards is not this page's to make.** The cards sit under
> the SubAgents epic; this page carries the evidence, and the call is Mohammed's.

---

## Open questions — left visible, not settled

| # | Question | Where it stands |
|---|---|---|
| A | Should `Evidence.id`'s trailing index become **content-addressed** rather than positional? | Open question A of `docs/sessions/2026-08-25-evidence-link-contract.md`, and the reason purging is unsafe today (§10.2). It would make ids reproducible and replay an exact lookup instead of fuzzy matching; it is also **expensive to reverse**, since every stored artifact is joined by these ids. **The one that gates any id-shape change.** |
| C | One `reputation#1` header covers **every** VT verdict in a slice, so `citation_evidence` maps it to a list. Should citation be per-verdict? | Open question C of the same document. For SIEM the chain is one-to-one; for VT it is one-to-many, and the precision is lost at the header where nothing downstream can recover it. `format_vt_verdicts` **sorts** by malicious+suspicious, so any positional scheme must mint ids from the sorted list. |
| — | Does the store need a **retention policy**? | 26 runs is fine. Nothing bounds growth and `save_run_artifacts` never prunes. **Not a defect, not yet decided.** |

Question B of that document — a citation can be *valid* and *resolve to nothing*,
indistinguishably, for sources predating `ResultSet.evidence_id` — is the artifact-level face
of §10.4 and is also open.

---

## Appendix A — Module map (code-level)

| Module | Responsibility |
|--------|----------------|
| `contracts/src/contracts/findings.py` | The two-layer payload: `Assessment` (model-authored) vs `Findings` (code-assembled); `ResultSet` (`:41`), `SiemFindings` (`:114`), `VtVerdict` (`:156`), `VtFindings` (`:194`), the `CimCategory` vocabulary (`:21`), and the `Edr`/`Ndr` assessments. |
| `contracts/src/contracts/subtask.py` | `Evidence` (`:278`), `evidence_id()` (`:63`) — the one id formula, `answer_tool_name()` (`:371`), `SubtaskResult` (`:447`) with the callable `Discriminator`s `_findings_tag` (`:406`) / `_assessment_tag` (`:428`), and `BrokerReport` (`:738`) including `trace_id` (`:744`). |
| `contracts/src/contracts/reasoning.py` | The wire contracts: `Exhibit` (`:231`), `DomainJudgement` (`:289`), `StepSummary` (`:318`), `RetrievalSummary` (`:342`), `HypothesisFindings` (`:388`); `DomainFinding` (`:125`) and `AnalystVerdict` (`:80`) carry `citation_evidence`. |
| `backend/src/smartops/projection.py` | `project()` (`:348`) — the dispatcher; `project_siem` (`:183`), `project_vt` (`:268`), `_infer_cim_category` (`:121`), `_rows_of` (`:76`, unwraps `structuredContent`), `_text_of` (`:41`). |
| `backend/src/smartops/subagents/__init__.py` | `_EvidenceCollector` (`:263`) — the `AfterToolCallEvent` hook at `HookOrder.SDK_FIRST`; the answer-tool skip (`:314`); `evidence()` (`:338`) mints ids from the same list the projectors enumerate. |
| `backend/src/smartops/subagent_analysts/routing.py` | `route()` (`:95`) — CIM category + entity kind → three `DomainSlice`s; the uncategorised fan-out; the no-projector warning (`:132`). |
| `backend/src/smartops/subagent_analysts/formatting.py` | Per-record-type field projectors; `format_result_set` (`:265`) and its `# {category}#{index} · rows=N` header — **no query, deliberately**; `format_vt_verdicts` (`:304`); `_sanitise()`. |
| `backend/src/smartops/subagent_analysts/packing.py` | `blocks()` (`:65`) — the single source of order and numbering; `pack_evidence()` (`:177`); `valid_citation_ids()` (`:159`); `exhibits_for()` (`:129`); `fitted_row_cap()` (`:222`). |
| `backend/src/smartops/subagent_analysts/analyze.py` | `_invoke_with_one_reask()` (`:138`) and `_apply_grounding()` (`:221`) — the orchestration and the grounding gate, each defined once and shared by both paths; `_finalize_finding()` (`:488`), `_as_judgement()` (`:528`), `gather()` (`:587`), `_retrieval_summary()` (`:643`) on the live path; `combine()` (`:365`) on the dormant one. |
| `backend/src/smartops/broker.py` | `save_run_artifacts()` (`:1079`) and `load_run_artifacts()` (`:1132`); `RUNS_DIR_ENV_VAR` / `DEFAULT_RUNS_DIR` (`:1076`). |
| `backend/src/smartops/replay.py` | `is_model_authored()` (`:45`), `load_evidence_from_file()` (`:57`), `load_evidence_from_run()` (`:116`), `evidence_by_id()` (`:148`), `_newest_run_in()` (`:177`), `ReplayToolset` (`:214`), `create_replay_subagent_runner()` (`:360`). |
| `backend/src/smartops/main.py` | `_print_findings()` (`:421`) / `_persist_findings()` (`:482`) write the operator view and `findings.json`; `hypothesis_id` is hardcoded at `:666` (§10.1). |

## Appendix B — The artifact on disk

One run directory per run, never overwritten:

```
.smartops/runs/                          ← $SMARTOPS_RUNS_DIR, default .smartops/runs
└── cli-20260825T100434/                 ← the case: BrokerReport.task_id
    ├── latest.txt                        ← "20260825T100741262" — the newest stamp
    └── 20260825T100741262/               ← one run, from report.created_at
        ├── report.json                   ← the BrokerReport: typed findings, scope,
        │                                   classification, step outcomes, trace_id
        └── evidence.json                 ← a flat list of Evidence records, raw
```

`report.json`, what `load_run_artifacts()` reads back:

```jsonc
{
  "task_id": "cli-20260825T100434",
  "hypothesis_id": "cli-hypothesis",          // the dead constant — §10.1
  "trace_id": "5c5dc4e16617d3…",              // resolves a run to its trace
  "scope": { "entities": [ … ], "time_window": [ … ] },
  "results": [
    {
      "task_id": "cli-20260825T100434:siem:tooluse_…",
      "findings": {
        "tool_family": "siem",                // the discriminator — §10.4
        "auth_events": [
          { "query": "index=botsv3 …",
            "row_count": 12,
            "rows": [ { … } ],
            "evidence_id": "cli-20260825T100434:siem:tooluse_…:2" }
        ],
        "uncategorised": [ … ]                // the honesty bucket — §6
      },
      "assessment": { "tool_family": "siem", "covered": [ … ], "not_covered": [ … ] }
    }
  ]
}
```

`evidence.json` — ids carried *inside* each record, so a filtered read re-targets nothing
(§10.2):

```jsonc
[
  {
    "id": "cli-20260825T100434:siem:tooluse_…:2",
    "tool_family": "siem",
    "raw": { "tool": "splunk__splunk_search",
             "query": "index=botsv3 …",
             "result": { … } },              // exactly what the tool returned
    "collected_at": "2026-08-25T10:07:41Z"
  }
]
```

**Never delete or rewrite anything under `.smartops/runs/`.** These are real run artifacts,
they cost real money, and they are the fixture this subsystem is validated against. A
measurement harness writing into that tree would make the fixture a function of the
measurements taken over it — `blind_compare.py` refuses an `--out` inside it, and a test pins
the refusal.

## Appendix C — How these numbers were produced

Every figure in §9 came from **executing** the production readers (`load_run_artifacts`,
`load_evidence_from_run`, `route`, `pack_evidence`, `valid_citation_ids`, `answer_tool_name`)
against the 26 runs under `.smartops/runs/` — not from reading the code or quoting an earlier
document. Per-figure method is in
`docs/sessions/handover_2026-08-26_confluence-page-written.md`. Any `--scripted` run used for
a figure points `SMARTOPS_RUNS_DIR` somewhere disposable — **never** under `.smartops/runs/`.

**Re-run on 2026-08-27, with neither Splunk nor a model reachable.** The saved runs are the
whole fixture, so the absence of both is a property of the check rather than a limit on it:

| Check | Result |
|---|---|
| `uv run pytest` | **764 passed**, 0 failed |
| `docs/check_anchors.py` | 83 anchors verified against the symbol named beside them, 0 stale |
| `smartops-blind-compare --run cli-20260825T100434 --pack-only` | all three domains packed from real rows at ~2.1k / 2.2k / 3.6k estimated tokens, none truncated, every header id resolving to a real `Evidence.id` |
| `load_run_artifacts` over every saved run | 26 of 26 |
| `load_evidence_from_run` + `ReplayToolset` over every case | 23 of 23, 788 records indexed, 0 model-authored |
| a `--scripted` broker run into a disposable `SMARTOPS_RUNS_DIR` | artifact written to a timestamped path with `latest.txt`, read back through `load_run_artifacts`, `trace_id` populated |
| **`gather()` — the production blind path — over the saved evidence, real model calls** | all three analysts returned: identity `suspicious` 0.7, network `malicious` 0.95, endpoint `suspicious` 0.7; 10 citations kept and 14 of 14 evidence ids resolving (§11). **One draw** — see the note below |

**On the model.** The imported analyst model is live; an idle one is evicted and reloads on
the next call, which surfaces as `ModelNotReadyException` for the first minute or two.
`_invoke_with_warmup` waits it out — up to 8 retries 30s apart — so a cold start is a delay
rather than a failure. Reaching it from a plain script means loading `.env` (the explicit
keys live there) and clearing any `AWS_PROFILE` whose login credential provider boto3 cannot
resolve here.

**Those dispositions are one draw, not a measurement.** The same evidence run twice through
the same blind path minutes apart gave identity `suspicious` at 0.85 with five citations, then
`suspicious` at 0.7 with one. The disposition held both times; the confidence and the citation
count did not. What the run demonstrates is that the path executes and the link contract holds
— not that a given confidence is reproducible.

**The run passed no hypothesis at all.** `gather` accepts one, but only to record on
`HypothesisFindings.hypothesis`; `gather_finding(model, scope, slice_)` has no parameter it
could reach an analyst through. Omitting it entirely means the run cannot be read as having
leaked one — and the artifact's `hypothesis` field is `null` accordingly. The **shown** arm,
which does take the prose, exists only in `smartops-blind-compare` and is not what production
runs.

**One thing the Splunk-less run demonstrated positively.** With the MCP server unreachable the
siem step came back `rejected`, carrying the reason, with `completed=false` **and**
`confirmed_empty=false` — the distinction between "we looked and found nothing" and "we never
got an answer" held, which is the one that must never collapse.

The anchor checker is now committed at `docs/check_anchors.py` rather than living in a session
scratchpad. It asserts that each anchored line *defines* the symbol named beside it; the
earlier version only checked the line existed, and reported success while every `analyze.py`
anchor on this page had slid onto an unrelated docstring.

**One inherited figure did not survive re-measurement.** The claim was *"22 of 26 artifacts
load through a shape fallback, not a tag"*; measured, it is **23 of 26**, with the sharper
picture in §10.4.

**One figure was true of the measurement, not of the code.** An earlier version of §9 said a
single glob misses the shallow run. That was a property of the throwaway verification script,
which enumerated runs by globbing. Production contains **no glob** — `load_run_artifacts` takes
an explicit run directory, and both read doors already resolve a case directory either way
(`replay.py:138-142`, `blind_compare.py:219-220`).

Three stale references were found while writing this page, all doc-only, all corrected in
their own commit alongside it:

| Where | Said | Actually |
|---|---|---|
| `contracts/subtask.py` — `Evidence`, `SubtaskResult` | the **aggregator** writes the evidence store and consumes the result | `broker.save_run_artifacts()` writes the store; the "aggregator" is the Analyst Agent, a separate epic with no code |
| `docs/architecture.md` §5 | the citable header carries `query="…"` | the query left the header in the blind redesign — §10.5 |
| `replay.py` (×2) and `test_replay.py` | `build_replay_tools` mints one replay tool per recorded name | **no such function exists** — it is `get_replay_tools_for_family` (`replay.py:321`), via `make_replay_tool` (`:305`) |

---

*Companion pages: `docs/architecture.md` (whole system),
`docs/confluence-task-broker-architecture.md` (the fetch tier that produces the input), and
`docs/confluence-subagent-analysts.md` (the analysts that consume the output). The id-shape
decisions and their open questions: `docs/sessions/2026-08-25-evidence-link-contract.md`.*
