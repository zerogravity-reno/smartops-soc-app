---
date: 2026-08-26
title: Handover — write the Confluence page for the Findings Pipeline and Evidence Store
---

# Handover — 2026-08-26: the Findings Pipeline / Evidence Store Confluence page

Branch `task-broker-agent`, HEAD `e3dcd99`. `uv run pytest` from the repo root:
**744 passed, 0 failed** (up from 718 at the start of the previous session).
Working tree clean apart from pre-existing untracked files under `docs/`.

The previous session did the audit and the fixes. **The remaining work is one
document**, deliberately not started there so it can be done in one pass with a
clean context.

## Pick this up here

1. **Write a NEW file: `docs/confluence-findings-pipeline-evidence-store.md`.**
2. **Do not touch `docs/confluence-subagent-analysts.md`.** That page covers the
   three analyst subagents and nothing else — that is its stated scope, and the
   Findings Pipeline and Evidence Store are separate Asana cards under a
   different parent ("Data Connector"). Read it for *style* and to avoid
   duplicating it; leave its content alone. Where the two subjects touch (the
   analyst reads packed evidence; its citations resolve into the store), link
   across rather than restate.
3. Read both existing Confluence pages first — they are the house style, and it
   is a specific one: `docs/confluence-subagent-analysts.md` (796 lines) and
   `docs/confluence-task-broker-architecture.md` (396 lines). Note how the first
   opens with a dated status callout that **corrects its own earlier framing**.
   That is not decoration; copy the habit.
4. **One page for both subsystems, not two.** The `Evidence.id` link contract
   spans them and would have to be duplicated across two pages to make either
   readable.
5. Re-confirm every number in *Verified facts* **by running it**, not by trusting
   this file. Commands are indicated. This codebase has a recorded history of
   inspection-based claims being wrong — see the 2026-08-24 audit, whose whole
   lesson was that "the tests pass" and "I read the code" are not evidence for a
   data-handling path.
6. **Do not mark the Asana cards closed** as part of this. The evidence for
   closure is in *Closure state*; the decision is Mohammed's, and the cards sit
   under the SubAgents epic rather than ours.

## What the page has to explain

Two subsystems, and the point of the page is that they are different things which
are easy to conflate:

- **The Findings Pipeline** moves *projected, typed rows* from a tool result to a
  domain analyst's judgement and out to the Analyst Agent. Nothing in it is
  model-authored except the judgement at the end.
- **The Evidence Store** holds the *raw tool output* those rows were projected
  from, on disk, addressable, so a judgement can be traced back to what produced
  it — or replayed offline at zero cost.

The pipeline never reads the store. That is the most important structural fact on
the page and the one a reader will get wrong by default: the analysts work off
`ResultSet.rows` inside `report.json`, and `evidence.json` is written alongside
for replay, audit, and citation resolution. Say it early, and say what follows
from it — when projection under-reports (it has, twice), the correct rows sitting
in `evidence.json` are unreachable by any code path.

### The pipeline path, in order

| Step | Code | What it does |
|---|---|---|
| 1 | `projection.project()` — `projection.py:307` | Raw tool output → typed `SiemFindings`/`VtFindings`. **Code only, never a model.** Dispatches to `project_siem` (`:183`) or `project_vt` (`:227`). |
| 2 | `SubtaskResult.findings` | The typed payload, carried on the result and into `BrokerReport`. A discriminated union, so it survives a JSON round trip as the right subclass. |
| 3 | `routing.route()` — `subagent_analysts/routing.py:95` | Splits the report into three `DomainSlice`s by CIM category and entity kind. **In code, not a model decision.** |
| 4 | `packing.pack_evidence()` — `packing.py:167` | Renders a slice to text under a 20k token budget, shrinking a row cap down a ladder rather than truncating mid-block. Returns the cap it settled on. |
| 5 | `packing.blocks()` — `packing.py:55` | **The single place block order and citation numbering are defined.** `_render`, `valid_citation_ids` (`:149`) and `exhibits_for` (`:119`) are all thin readings of it. |
| 6 | the analyst | Authors a `Disposition` + observations + citations. The only model-authored step. |
| 7 | `_finalize_finding()` — `analyze.py:390` | The grounding gate: drops citations that do not resolve, drops observations resting only on invented ids, downgrades an ungrounded decisive disposition, freezes `citation_evidence`. |
| 8 | `_as_judgement()` — `analyze.py:449` | Projects to the wire: audit fields off, `Exhibit`s on. |
| 9 | `gather()` — `analyze.py:508` | Assembles `HypothesisFindings`, plus `_retrieval_summary()` (`:564`). |

The two-layer split deserves a section of its own: **the model authors a small
`Assessment`, code supplies every row.** Neither half can forge the other — a
model that never sees the rows cannot invent them, and code that never reads the
prompt cannot be talked into re-categorising. `contracts/findings.py`'s module
docstring states this in two paragraphs worth quoting rather than paraphrasing.

### The store

| Piece | Code | Note |
|---|---|---|
| Write | `save_run_artifacts()` — `broker.py:1079` | `<base>/<task_id>/<stamp>/` holding `report.json` + `evidence.json`, plus a sibling `latest.txt`. Timestamped because keying on `task_id` alone meant every re-run silently overwrote the last — and the bench runs each case N times. |
| Read (report) | `load_run_artifacts()` — `broker.py:1132` | Typed round trip. Depends on the callable `Discriminator`s at `subtask.py:393` / `:415` to resolve payloads written before `tool_family` existed. |
| Read (evidence) | `load_evidence_from_file` / `_from_run` — `replay.py:57` / `:115` | Resolves a bare case id via `latest.txt`, else the highest stamp (zero-padded, so lexical sort is chronological). |
| Address one record | `evidence_by_id()` — `replay.py:147` | Keyed by `Evidence.id`. |
| The id | `evidence_id()` — `subtask.py:63` | `f"{task_id}:{index}"`. One formula, three minting sites. |
| Replay | `ReplayToolset` — `replay.py:213` | Serves recorded output offline. Exact → fuzzy → tool-only → honest cache miss. |

### The link contract — what makes the two subsystems one story

A citation the analyst writes (`auth_events#1`) is a *position in a rendering*.
On its own it resolves only against a recomputed routing, so if routing order
ever changed, every stored citation would silently re-target. Three fields close
that. Walk the chain end to end with one concrete id:

```
DomainJudgement.citations    "auth_events#1"             what the analyst wrote
  -> citation_evidence       {"auth_events#1": [...]}    frozen at finalisation
  -> ResultSet.evidence_id   "cli-...:siem:tooluse_...:2"  the record it came from
  -> Evidence.id             in evidence.json            the raw tool output
```

Plus `Exhibit` (`reasoning.py:231`), which carries the actual rows so a consumer
holding no store can still check a judgement. Worth stating why it exists at all:
on `cli-20260825T100434` each domain was routed 32–35 blocks and cited one, so
shipping only the cited blocks is ~2% of the pack. Note also that `Exhibit.query`
carries the SPL the analyst was *not* shown — the two consumers differ, and that
asymmetry is a design decision, not an oversight.

## Verified facts — re-run each before publishing

Confirmed by execution on 2026-08-25/26 against the 26 runs under
`.smartops/runs/`. Do not restate any of them without re-running.

| Fact | How to re-confirm |
|---|---|
| **26/26 saved reports load** (was 22 of 24 *failing* — the 2026-08-24 gap 2) | loop `load_run_artifacts` over `glob('.smartops/runs/*/*/report.json')` **and** `glob('.smartops/runs/*/report.json')` — one run sits at the shallower depth and a single glob misses it |
| **0 evidence headers name the hypothesis subject** (was 2 / 11 / 2 for identity / network / endpoint) | `route` → `pack_evidence` on `cli-20260825T100434/20260825T100741262`; count `# `-prefixed lines containing `coinhive`. Scope to headers — `query=` is also a legitimate DNS row field |
| **Every category's citation ids start at #1** (the network slice used to emit `connections#1..#9` then `dns_resolutions#10..`) | `valid_citation_ids` on the same run's network slice |
| **60 model-authored answer records on disk, across 22 of 26 evidence files** | scan `evidence.json` for `raw.tool` in `{SiemAnswer, VtAnswer, EdrAnswer, NdrAnswer}` |
| **All 60 carry only a validation ack** — 35 × `"Successfully validated SiemAnswer structured output"`, 25 × the VT equivalent, no answer content at all | print `raw.result.content[0].text` for each |
| **No answer-tool name is reachable in any replay index** | `ReplayToolset(load_evidence_from_run(d))` over every run; assert no recorded `tool` ends with `Answer` |
| **`report.trace_id` is populated on a fresh run** | any `--scripted` run, then read `report.json` |

## The honesty callouts the page must carry

The house style is unusually candid and the page is not credible without these.

1. **`hypothesis_id` is the constant `"cli-hypothesis"` on every artifact on
   disk.** The join key back to a hypothesis exists in the schema and is useless
   in practice, because no Analyst Agent produces one — `main._run` hardcodes it.
   Every `assessment.json` and the one `findings.json` carry it. Do not present
   hypothesis-level traceability as working.
2. **60 model-authored records are still in the store, filtered on read rather
   than deleted.** `contracts.Evidence` is raw tool output, never model-authored;
   `_EvidenceCollector` enforces that at capture, but 22 runs predate that skip.
   They are filtered at both read doors (`load_evidence_from_file` and
   `ReplayToolset`) as of `e3dcd99`, and `include_model_answers=True` still reads
   them. **Explain why they were not purged**: `evidence_id` is
   `f"{task_id}:{index}"`, so deleting a record renumbers every record after it
   and silently re-targets every stored citation — the exact failure the link
   contract exists to prevent. This is the clearest illustration on the page of
   why the id shape matters, so use it as one. Worth adding what those records
   did before the filter: `build_replay_tools` mints one replay tool per recorded
   tool name, so an unfiltered record became a tool literally called `VtAnswer`
   that handed a replayed subagent the model's own prior answer as though a tool
   had returned it.
3. **edr/ndr evidence would reach no analyst.** `project()` has projectors for
   siem and vt only, and `route()` skips a `None` findings payload. Latent while
   both families are always REJECTED for want of an MCP server; live the day a
   connector lands. `route()` now warns loudly instead of dropping silently, and
   a projector per family is the fix — it belongs with the connector that defines
   the row shape, not ahead of it.
4. **22 of 26 artifacts load through a shape fallback, not a tag.** The callable
   `Discriminator` resolves payloads written before `tool_family` existed. It
   works and is tested, but say plainly that the store's older half is read by
   inference rather than by declaration.
5. **The query is out of the analyst's evidence header, and the justification is
   structural, not empirical.** It measures as a channel that existed (11 of 35
   network headers named the hypothesis subject); it was **not** measured to have
   changed any verdict. Frame it exactly as `confluence-subagent-analysts.md`
   frames blindness itself, and read
   `handover_2026-08-25_blind-vs-shown-remeasured.md` before writing this
   paragraph — that session found the original anchoring demo was one draw from a
   distribution wider than the effect it claimed. **Do not cite the leak fix as
   evidence that anchoring was occurring.** One further line worth including:
   `blind_compare.py`'s existing numbers are stale for a subtle reason — they
   held evidence fixed across arms, so the leak was a constant in every arm
   *including the blind control*, which is precisely why that harness could not
   have detected it.
6. **`combine()` has no confidence floor** — a lone `supports` at 0.01 returns
   `('supports', 0.01)`. It is on the hypothesis-shown path that production no
   longer calls, so it is dead code. Mention it as dead code that would mislead
   if revived, not as a live defect.

## Closure state (for the page's status callout, and for Mohammed)

The 2026-08-24 audit recorded three gaps blocking closure of "Findings Pipeline",
"Evidence Store" and their parent "Data Connector". All three are now closed:

| Gap | State |
|---|---|
| 1 — findings 4–7 uncommitted | closed; committed, tree clean |
| 2 — 22 of 24 reports fail to load | closed; **26/26 load** |
| 3 — artifact linking unstarted | closed; `ResultSet.evidence_id`, `HypothesisAssessment.task_id`/`run_id`, `AnalystVerdict.citation_evidence`, `Exhibit.evidence_ids` all present |

Its "unscheduled Important tier" of five is four closed, one dead-code:
comma-only citation split (fixed), global citation numbering (fixed),
`_EvidenceCollector` recording structured output (fixed at capture, and now at
read), replay unable to read VT evidence (resolves), `combine()` floor (dead
path, open).

## Source material

Draw on these rather than re-deriving. The first two are the direct predecessors
and carry detail this file compresses.

- `docs/sessions/handover_2026-08-23_findings-pipeline-evidence-store.md`
- `docs/sessions/handover_2026-08-24_findings-pipeline-evidence-store-audit.md` — the seven-findings table
- `docs/sessions/2026-08-25-evidence-link-contract.md` — the id-shape decision and its three open questions
- `docs/sessions/handover_2026-08-25_blind-vs-shown-remeasured.md` — read before writing callout 5
- `docs/architecture.md` — the page is a stakeholder view of it; keep them consistent
- `contracts/findings.py` and `contracts/reasoning.py` module docstrings — the two-layer split and the wire boundary, already in prose worth quoting

## Definition of done

- `docs/confluence-findings-pipeline-evidence-store.md` exists, in the style of
  its two siblings: audience + source-of-truth header, a dated status callout,
  numbered design principles, an ASCII flow diagram, tables over prose, and a
  code-map appendix keyed to `file:line`.
- `docs/confluence-subagent-analysts.md` is **unmodified**.
- Every number on the page was re-run this session, not copied from here.
- All six honesty callouts appear.
- The three still-open items are visible on the page rather than buried:
  hardcoded `hypothesis_id`, no edr/ndr projector, `combine()`'s missing floor.
- `uv run pytest` from the repo root still passes. The page should need no code
  changes; if it does, that is a finding worth its own commit.
- **Do not hand-edit `docs/PROJECT_DOCS.md`.** Run `docs/compile_docs.py` so this
  file reaches it. Every `docs/sessions/*.md` needs `date` and `title`
  frontmatter or the compile raises.

## Open questions to leave visible rather than answer

- Should the `Evidence.id` trailing index become content-addressed? Open
  question A of `2026-08-25-evidence-link-contract.md`, and the reason purging
  records is unsafe today. Do not settle it on the page.
- One `reputation#1` header covers every VT verdict in a slice, so
  `citation_evidence` maps it to a list. Whether that should be per-verdict is
  open question C of the same doc.
- Does the store need a retention policy? 26 runs is fine; nothing bounds growth
  and `save_run_artifacts` never prunes. Not a defect, not yet decided.
