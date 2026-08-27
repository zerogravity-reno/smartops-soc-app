---
date: 2026-08-26
title: The Findings Pipeline / Evidence Store Confluence page written; one handover number re-measured and corrected
---

# Handover — 2026-08-26: the Confluence page is written

Continues `handover_2026-08-26_confluence-findings-pipeline-evidence-store.md`, whose
single remaining item was one document. That document exists.

Branch `task-broker-agent`, still at HEAD `6a4a9dd` — **nothing in this session is
committed.** `uv run pytest` from the repo root: **744 passed, 0 failed**, re-run after
each of the doc-only source edits.

The page is written, reviewed once, and `PROJECT_DOCS.md` is recompiled. The review
pass found five things wrong with the first draft; they are in *What the review pass
caught*, because that is the part worth reading.

## Pick this up here

1. **Commit in three pieces**, in this order — they are independent and two touch code:
   - `contracts/src/contracts/subtask.py` — docstring-only (`Evidence`, `SubtaskResult`)
   - `backend/src/smartops/replay.py` + `backend/tests/test_replay.py` — comment-only,
     the phantom `build_replay_tools` name
   - `docs/architecture.md`, `docs/confluence-findings-pipeline-evidence-store.md`,
     `docs/images/findings-pipeline-flow.{svg,png}`, this session file, and the
     recompiled `docs/PROJECT_DOCS.md`
2. **The `file:line` anchors are machine-checked, and the checker is worth keeping.**
   All **88** anchors on the page resolve to the symbol they name — verified by
   `check_anchors.py` in this session's scratchpad, which parses both the
   `` `foo.py:307` `` and bare `` `:183` `` forms and prints the actual source line.
   The `subtask.py` anchors moved once already when a docstring grew. **Re-run it after
   any edit to a file the page cites**, or accept that they rot.
3. **Read §10.5 with fresh eyes if you change anything near it.** It is written to
   *withhold* a claim — the leak channel was measured, the anchoring effect was not —
   and the failure mode is a well-meaning edit turning it back into proof.
4. **Do not close the Asana cards.** See *Deliberately not done*.

## What landed

| File | State |
| :--- | :--- |
| `docs/confluence-findings-pipeline-evidence-store.md` | **new** — the deliverable. 11 sections, all six honesty callouts, the three open items surfaced rather than buried, a `file:line` module map, and an appendix showing the on-disk artifact shape |
| `docs/images/findings-pipeline-flow.svg` + `.png` | **new** — the diagram the page's §4 callout names |
| `docs/architecture.md` | §5's Formatting bullet corrected: the evidence header no longer carries `query="…"` |
| `contracts/src/contracts/subtask.py` | docstring-only: `Evidence` and `SubtaskResult` no longer claim the aggregator writes the evidence store |
| `backend/src/smartops/replay.py`, `backend/tests/test_replay.py` | comment-only: three references to a `build_replay_tools` that never existed |
| `docs/PROJECT_DOCS.md` | recompiled by `docs/compile_docs.py` — 20 session docs |
| `docs/confluence-subagent-analysts.md` | **untouched**, as its own scope requires |

## THE HEADLINE: one handover number did not survive re-measurement

The handover's instruction was to re-confirm every figure by running it rather than
trusting the file, on the 2026-08-24 audit's lesson. Six of seven confirmed exactly.
**One did not**, and it is the one worth recording:

> **Claimed:** "22 of 26 artifacts load through a shape fallback, not a tag."
> **Measured:** **23 of 26**, and the real picture is sharper than either number.

Of the 26 saved reports, **2 carry no typed payload at all** (nothing was retrieved),
and of the 24 that do, **exactly one** — `cli-20260825T100434`, the only run written
after the discriminator landed — is fully tagged. By payload it is **123 untagged
against 14 tagged**.

So the store's "older half" is not a half. It is 23 of the 24 reports that carry data,
and the honest statement on the page is that **the store's history is read by inference
from shape rather than by declaration**, ageing out only as new runs accumulate. The
callable `Discriminator` is doing more work than the handover's phrasing implied.

The other six, all confirmed by execution against `.smartops/runs/`:

| Fact | Result |
| :--- | :--- |
| saved reports that load | **26 of 26**, 0 failing (25 at the deep path, 1 at the shallow one — a single glob misses it) |
| evidence **headers** naming the hypothesis subject | **0** of 32 / 35 / 34 across identity / network / endpoint. 19 network *row* lines mention it legitimately: `query=` is a real DNS row field |
| per-category citation numbering | **contiguous from `#1`** in all 9 category/slice pairs; network now emits `connections#1..#9` **and** `dns_resolutions#1..#8` |
| model-authored answer records on disk | **60**, across **22 of 26** evidence files |
| their content | exactly two distinct strings — 35 × `"Successfully validated SiemAnswer structured output"`, 25 × the `VtAnswer` equivalent. No answer content at all |
| answer tools reachable in a replay index | **0** across all 26 runs; the read door drops all 60 |
| `report.trace_id` on a fresh run | populated — `5c5dc4e16617d30965e23d1a1a71574c` |

The `--scripted` run for the last row wrote into a scratchpad via
`SMARTOPS_RUNS_DIR`. **Nothing was written under `.smartops/runs/`**, per the standing
landmine.

## The three doc-drift corrections

All found by reading the code for the page, all about the page's exact subject, none a
behaviour change:

1. **`docs/architecture.md` §5** documented the citable header as
   `# {category}#{index} · query="…" · rows=N`. The query left that header in the blind
   redesign; `formatting.format_result_set` emits `# {category}#{index} · rows=N` and
   its docstring records why at length. Corrected, with the reason named in one clause.
2. **`contracts/subtask.py`** — `Evidence` said *"the aggregator is what actually writes
   them into the case file's evidence store"* and `SubtaskResult` said *"consumed only
   by the aggregator"*. `broker.save_run_artifacts()` writes the store; the aggregator
   is the Analyst Agent, a separate epic with no code. **Flagged unfixed on 2026-08-23
   and again on 2026-08-25** — the third flag was enough. Both lines corrected together;
   they were one contradiction.
3. **`build_replay_tools` does not exist.** Two `replay.py` docstrings and one
   `test_replay.py` comment name it as the thing that "mints one replay tool per
   recorded tool name". The function is **`get_replay_tools_for_family`**
   (`replay.py:320`), via `make_replay_tool` (`:304`). The *mechanism* those comments
   describe is correct — which is why nobody noticed the symbol was fictional. All three
   corrected; the page had inherited the phantom name from them.

   **A fourth reference survived this sweep and was found in review on 2026-08-27**, in
   the sibling session file `handover_2026-08-26_confluence-findings-pipeline-evidence-store.md`
   — where it was stated as a fact about the code, not as a quotation of the bad
   docstring, and so compiled straight into `PROJECT_DOCS.md`. For a day the decision
   record both asserted the phantom name and explained that it never existed. The count
   above ("all three") was scoped to code files and was correct as far as it went; the
   sweep's mistake was not searching the docs it was about to compile.

## What the review pass caught

The first draft was written in one pass and then read back. Five things were wrong, and
the pattern in them is worth more than the fixes:

| # | Wrong | Right |
| :--- | :--- | :--- |
| 1 | "`evidence_id()` — **three** minting sites" (three places on the page, and the source docstring's own phrasing) | **four**: `_EvidenceCollector.evidence`, `project_siem`, `project_vt`, and the VT enricher at `broker.py:333`. The docstring dates from when the projectors were one prospective consumer; they became two |
| 2 | "Every `assessment.json` and the one `findings.json` carry `hypothesis_id: cli-hypothesis`" | the 9 assessments do; the one `findings.json` carries **no `hypothesis_id` at all** — it is a bare list of three pre-`HypothesisFindings` domain findings, no `task_id`, no `run_id`, no `disposition` |
| 3 | gap 3 "closed — all fields present" | closed **in the contracts**. Measured on disk: **0 of 10** analysis artifacts carry a top-level `task_id` and **0** carry any `citation_evidence`. Only **72 of 875** stored result sets carry an `evidence_id`, all in the one post-contract run |
| 4 | the page named `build_replay_tools` | see correction 3 above |
| 5 | the ASCII diagram's connectors | drifted across columns 50–55 and 64–66 from hand-editing. Rebuilt by placing every glyph at a computed column; now six columns, each used consistently, max width 80 |

**Four of the five are the same error**: a claim inherited from a document (a docstring,
a handover, an earlier draft) rather than derived from the thing itself. Number 3 is the
one that would have mattered most — the page would have told a reader the link contract
is proven on disk when nothing on disk exercises it.

Two of the checks are now mechanical and cheap to repeat: `check_anchors.py` resolves
all 88 `file:line` anchors against the real symbols, and the diagram is generated by
`build_ascii.py` rather than hand-aligned. Both are in this session's scratchpad.

## Deliberately not done

- **No Asana card was closed.** "Findings Pipeline", "Evidence Store" and their parent
  "Data Connector" all have their closure evidence on the page (§11: all three
  2026-08-24 blockers closed, the Important tier four-closed/one-dead-path). The cards
  sit under the SubAgents epic and the decision is Mohammed's.
- **None of the three open questions was settled.** `Evidence.id` content-addressing
  (question A), per-verdict VT citation (question C), and store retention are on the
  page as open, with the tradeoffs, and no code touched them. **A is still the one that
  gates any id-shape change.**
- **The three open defects were not fixed.** Naming them was the deliverable: the
  hardcoded `hypothesis_id` (`main.py:666`, still `"cli-hypothesis"` on a fresh run),
  the missing edr/ndr projector, and `combine()`'s absent confidence floor.

## Outstanding

| Item | Why it is not done |
| :--- | :--- |
| Nothing committed | The whole session's diff sits in the working tree on `task-broker-agent` at `6a4a9dd`. The three-commit split is at the top of this file |
| Page reviewed once, by its author | The review pass above found five real errors, which is a reason to expect a sixth. It has had no *other* reader |
| No PNG re-render pipeline | The `.png` is a headless-Chrome screenshot of the `.svg`, taken by hand. If the SVG changes, the PNG has to be retaken the same way (command in *Notes* below) |
| Nothing on disk proves the link contract | Not this session's to fix — it needs one blind analyst run to complete. See §11's caveat on the page; it is the single most useful next check |

## Notes for whoever picks this up

- **`docs/confluence-subagent-analysts.md` is untracked**, not just unmodified — it has
  never been committed. Worth committing alongside the new page so the two siblings are
  both in the repo; this session left it exactly as it found it rather than widening
  scope to stage someone else's file.
- The diagram PNG was rendered with **headless Chrome**. No
  `cairosvg`/`rsvg-convert`/ImageMagick on this machine — `cairo` is absent, and
  `/c/WINDOWS/system32/convert` is the Windows disk utility, not ImageMagick. The SVG is
  the source of truth; re-render with:

  ```sh
  "/c/Program Files/Google/Chrome/Application/chrome.exe" --headless --disable-gpu \
    --hide-scrollbars --force-device-scale-factor=2 --window-size=2180,980 \
    --default-background-color=ffffffff --screenshot=out.png in.svg
  ```

  Chrome will not screenshot straight out of the repo path reliably; copy the SVG to a
  scratch dir first, render there, then copy the PNG back.
- **The verification scripts are in the scratchpad, not the repo** —
  `verify_facts.py` (the six confirmed figures) and `verify_discriminator.py` (the
  corrected one) under this session's
  `…/claude/d--projects-Smartops-SOC-App/…/scratchpad/`. They reuse the production
  readers rather than reimplementing them (`load_run_artifacts`,
  `load_evidence_from_run`, `route`, `pack_evidence`, `valid_citation_ids`,
  `answer_tool_name`). If any §9 figure is ever challenged, rewriting them from the
  method column of §9 is a ten-minute job — they were deliberately not committed
  because nothing in production calls them.
- **Never stage `backend/src/smartops/bench.py`.** Still carries pre-existing
  out-of-scope work. Verified untouched throughout.

## Process note

Three sessions running have now made the same point, and this one narrows it twice.

The 2026-08-24 audit found that executing a data path disproves claims made by reading
it. This session executed the *handover's own summary of that audit* and found one
figure off by one report — small, but it was the figure describing how much of the store
is read by inference, which is exactly the kind of claim that gets quoted into a closure
decision. **A number re-derived from a document is not a measurement, even when the
document was written by the person who measured it.**

The review pass then made the sharper version of the same point against this session's
own output. Four of its five findings were claims inherited from a document rather than
derived from the thing described — a docstring that undercounted its own call sites, a
handover sentence about artifacts nobody had opened, a function name that never existed
and had been quoted three times. **The failure mode is not carelessness; it is that
prose about code reads as evidence about code.** The two checks that now run
mechanically — anchor resolution and diagram generation — were both added because the
hand-done version of each had already drifted.
