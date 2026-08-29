# SmartOps SOC — Findings Pipeline & Evidence Store

> **Audience:** engineers working on the evidence path.
> **Source of truth:** `docs/architecture.md` is the single map of the system; this page is
> the evidence layer in depth. Decisions and their history live in `docs/PROJECT_DOCS.md`.
> **~5 minute read.**

---

## 1. Two subsystems, not one

Almost every misunderstanding of this layer comes from conflating them.

**The Findings Pipeline** carries **projected, typed rows** from a tool result to a domain
analyst's judgement and out to the Analyst Agent. **The Evidence Store** holds the **raw tool
output those rows were projected from**, on disk, addressable by id.

| | Findings Pipeline | Evidence Store |
|---|---|---|
| **Carries** | typed rows (`ResultSet.rows`, `VtVerdict`) | raw tool payloads (`Evidence.raw`) |
| **Lives** | in memory, persisted in `report.json` | on disk, in `evidence.json` |
| **Read by** | `route()` → the analysts → the Analyst Agent | replay, audit, citation resolution |
| **Purpose** | produce a grounded judgement | prove what the judgement rested on |
| **Written by** | `projection.project()` | `broker.save_run_artifacts()` |

They are joined by **one thing only: an id** — not by data flow.

---

## 2. Design principles

| # | Principle | In practice |
|---|---|---|
| 1 | **Code projects every row; a model authors none** | `project()` has no model call in it. |
| 2 | **Routing is a fact, not a model choice** | `route()` decides which evidence reaches which analyst from CIM category and entity kind, in code. |
| 3 | **The pipeline never reads the store** | Nothing in the analysis path opens `evidence.json` — §3. |
| 4 | **No model authors an id, at any hop** | A model may *cite* an id, never *create* one. |
| 5 | **Absence is rendered, not omitted** | An empty result set is still printed with `rows=0`: a missing block is indistinguishable from a question never asked. |
| 6 | **Nothing is capped silently** | `pack_evidence()` shrinks a row cap down a ladder rather than truncating mid-block, and reports the rung. |

---

## 3. The load-bearing claim: the pipeline never reads the store

> **The analysts work off `ResultSet.rows` inside `report.json`. `evidence.json` is written
> alongside it — for replay, audit and citation resolution — and no code path in the
> analysis pipeline ever reads it.**

Raw tool output is captured **once**, by `_EvidenceCollector`'s `AfterToolCallEvent` hook,
then forks two ways that never rejoin: **up** into `project()`, which writes typed rows onto
`SubtaskResult.findings`; **down** into `Evidence`, persisted verbatim. `route()`,
`pack_evidence()`, the analyst and the gate all sit on the first branch and cannot see the
second.

**The cost is real.** When projection under-reports, the correct rows sit in `evidence.json`
unreachable by any code path. Three defects survived on exactly that:

| What went wrong | Why nothing looked broken |
|---|---|
| Row projectors matched CIM field names against Windows/Stream spellings, so **~97% of `processes` rows rendered blank** (1,648 of 1,887) | The header still said `rows=N` and the id stayed valid, so a fabricated claim citing `processes#1` passed the grounding gate |
| `structuredContent` was not unwrapped, so 54 SIEM items with real rows projected as `row_count=0` | Evidence was captured correctly throughout, so citations resolved and nothing failed |
| A log value could close the `</evidence>` fence and forge a second block under a valid header id | The forged block was well-formed and its id genuinely valid — the gate had nothing to reject |

The separation is kept anyway: letting an analyst read raw tool output is the one thing the
engine exists to prevent. The mitigation is not to bridge the gap, but that **the store is
now the fixture every evidence-path change is tested against.**

---

## 4. The pipeline path

Nine steps. **One involves a model.**

| Step | Code | What it does |
|---|---|---|
| 1 | `projection.project()` — `projection.py:348` | Raw output → typed `SiemFindings`/`VtFindings`, dispatching to `project_siem` (`:183`) or `project_vt` (`:268`). Every family with a projector must dispatch *here*: a call site that appended one itself is why a vt subagent holding real evidence once reported `findings=None`. |
| 2 | `SubtaskResult.findings` — `subtask.py:473` | Carries the typed payload into `BrokerReport`. A **discriminated union**, so a JSON round trip returns the right subclass rather than the empty base. |
| 3 | `routing.route()` — `routing.py:95` | Splits the report into three `DomainSlice`s by CIM category and entity kind. Untagged sets go to the domains the scope's entity kinds imply — flagged, never dropped: they were retrieved and paid for. |
| 4 | `packing.pack_evidence()` — `packing.py:194` | Renders a slice under a 20,000-token budget, shrinking the row cap down a ladder (**200 → 20 → 10 → 5 → 3 → 1 → header-only**) instead of truncating mid-block. Returns the rung it settled on, so `exhibits_for` renders at the same one. |
| 5 | `packing.blocks()` — `packing.py:82` | **The single definition of block order and citation numbering.** `_render`, `valid_citation_ids` (`:176`) and `exhibits_for` (`:146`) are thin readings of it. |
| 6 | **the analyst** | Reads the packed evidence and authors a `Disposition`, observations and citations. **The only model-authored step.** It never sees the raw tool output behind those rows, and can cite only ids code minted. |
| 7 | `analyze._finalize_finding()` — `analyze.py:374` | The grounding gate: drops citations that do not resolve and observations resting only on invented ids, downgrades an ungrounded decisive disposition to `inconclusive`, and **freezes `citation_evidence`**. |
| 8 | `analyze._as_judgement()` — `analyze.py:414` | Projects onto the wire: audit fields (`reasoning_trace`, token counts) off, `Exhibit`s on. |
| 9 | `analyze.gather()` — `analyze.py:473` | Assembles `HypothesisFindings` plus `_retrieval_summary()` (`:549`). Assembles — does not decide. |

**Numbering is per category, not per slice.** One counter over the whole slice numbered by
position instead, so a network slice emitted `connections#1..#9` then `dns_resolutions#10..`
— **with no `dns_resolutions#1`, the exact worked example the analyst prompts hand the
model.** A model citing it failed validation, lost the observation, and was downgraded to
`inconclusive` — which reads as a cautious analyst rather than a bug, and is why it survived.

---

## 5. The two-layer split

The anti-fabrication mechanism the layer rests on:

> The model authors a small assessment and says which CIM category each of its queries was
> after; **code** supplies every row, from what the tools actually returned. **Neither half
> can forge the other.**

The category is the model's one contribution, and deliberately a classification of **its own
action** — knowable without inspecting a row. When missing, `_infer_cim_category()` derives
one from the SPL predicates (`stream:dns` → `dns_resolutions`, `EventCode=4688` →
`processes`); anything still untagged lands in `SiemFindings.uncategorised`, **an honesty
bucket, not a fifth category.** A full bucket signals that the model's reported queries have
stopped matching the ones it ran.

`Assessment` is deliberately small: a model forced to emit retrieved rows as structured
output would spend them as *output* tokens against a cumulative ceiling, and would admit
hallucinated values into evidence — which `Evidence` forbids.

---

## 6. The link contract

A citation the analyst writes (`auth_events#1`) is a **position in a rendering**, and alone
resolves only against a recomputed routing — so a change in routing order would silently
re-target every stored citation. Three fields close that gap:

```
DomainFinding.citations           "auth_events#1"              what the analyst wrote
  └─► DomainFinding.citation_evidence
          {"auth_events#1": ["cli-…:siem:tooluse_…:2"]}        frozen at finalisation
        └─► ResultSet.evidence_id  "cli-…:siem:tooluse_…:2"    the record it came from
              └─► Evidence.id      in evidence.json            the raw tool output

full id shape:  {task_id}:{family}:{toolUseId}:{index}
```

**On the wire the link changes carrier, and this is easy to get wrong.** `_as_judgement`
projects a `DomainFinding` onto a **`DomainJudgement`**, which is what `findings.json`
holds — and `DomainJudgement` has **no `citation_evidence` field**. It carries `citations`
plus one **`Exhibit` per kept citation**, with the ids on `Exhibit.evidence_ids`:

```
DomainJudgement.exhibits[n]
  ├── citation        "auth_events#1"                which citation this is
  ├── evidence_ids    ["cli-…:siem:tooluse_…:2"]     the same link, on the wire
  ├── rows            the projected text the analyst read
  ├── row_count       so a rows=0 exhibit is legible as one
  └── query           the SPL, withheld from the analyst, restored here
```

`citation_evidence` is the **internal** freeze; the exhibit is what the Analyst Agent
receives, and is strictly better for that consumer — a pointer needs the store, whereas the
exhibit carries the rows with it.

Three load-bearing properties:

1. **No model authors an id, at any hop.**
2. **`toolUseId` is the broker-dispatch join** — the only component separating two dispatches
   of the same family for the same hypothesis. Remove it and a re-dispatch overwrites the
   first's evidence ids.
3. **`citation_evidence` freezes the resolution at finalisation.** Until that was *recorded*,
   tracing a stored verdict to its rows meant recomputing the routing and trusting it came
   out identical.

It carries the cited rows exactly as the analyst read them — same row cap, same sanitised
text, not a re-render. Carrying *every* routed block would be the opposite failure: on one
run each domain was routed 32–35 blocks and cited one, so the exhibits are ~**2% of the
pack**.

> **One asymmetry that looks like an oversight and is not.** `Exhibit.query` carries the SPL
> the analyst was **not** shown. The domain analyst is blind to the hypothesis and a query
> written to test it leaks it; the Analyst Agent is not blind and cannot judge an empty cited
> set without knowing what was asked. The query left the prompt, not the audit trail.

---

## Appendix — Module map

| Module | Responsibility |
|---|---|
| `backend/src/smartops/projection.py` | `project()` (`:348`), `project_siem` (`:183`), `project_vt` (`:268`), `_infer_cim_category`. |
| `backend/src/smartops/subagent_analysts/routing.py` | `route()` (`:95`) — CIM category + entity kind → three `DomainSlice`s; the uncategorised fan-out. |
| `backend/src/smartops/subagent_analysts/formatting.py` | Per-record-type field projectors; the `# {category}#{index} · rows=N` header — **no query, deliberately**. |
| `backend/src/smartops/subagent_analysts/packing.py` | `blocks()` (`:82`) — the single source of order and numbering; `pack_evidence()` (`:194`); `valid_citation_ids()` (`:176`); `exhibits_for()` (`:146`); `fitted_row_cap()` (`:239`). |
| `backend/src/smartops/subagent_analysts/analyze.py` | `_invoke_with_one_reask()` (`:138`), `_apply_grounding()` (`:221`), `_finalize_finding()` (`:374`), `_as_judgement()` (`:414`), `gather()` (`:473`), `_retrieval_summary()` (`:549`). |
| `backend/src/smartops/broker.py` | `save_run_artifacts()` and `load_run_artifacts()`. |
| `backend/src/smartops/replay.py` | Offline replay against a stored run: `evidence_by_id()`, `ReplayToolset`. |
| `backend/src/smartops/main.py` | `_print_findings()` (`:427`) / `_persist_findings()` (`:566`) write the operator view and `findings.json`. |
| `contracts/schemas/hypothesis-findings.v1.schema.json` | The published output shape, generated by `generate.py` and enforced in `contracts/tests/test_published_schema.py`. |

**Known open items** are tracked in `docs/PROJECT_DOCS.md` and the session handovers — the
notable ones being `hypothesis_id` hardcoded for CLI runs, and `edr`/`ndr` evidence having no
routing target should those families ever be wired.

**Anchors in this page are checked.** `uv run python docs/check_anchors.py` verifies each
`file:line` names the symbol beside it; `docs/fix_anchors.py` repoints them after a refactor.

---

*Diagram source: `docs/images/findings-pipeline-flow.svg`. Attach the `.png` render when
pasting into Confluence.*
