---
date: 2026-08-30
title: The re-ask template never asked for a disposition — and two PROJECT_DOCS entries this supersedes
---

Executed `handover_2026-08-30_splunk-back-answer-sheet-and-siem-trace.md` as five
tasks with per-task review, then a whole-branch review. Commits `24a4f81..bc3ddf5`
(12), **856 tests passing** (from 848), 31 doc anchors verified, 0 stale.

## ⚠️ Two PROJECT_DOCS entries are now false — read this one instead

`docs/PROJECT_DOCS.md` is compiled from `docs/sessions/` in date order, so earlier
entries stay as history. Two of them assert things this session falsified, and
CLAUDE.md tells a reader to consult the decision record before proposing changes:

- **"no expected dispositions anywhere in the repo"** — false. `bench.py` now has
  `EXPECTED_DISPOSITIONS` with three documented BOTSv3 answers, and
  `SYNTHETIC_INDICATOR_CASES` registering seven cases whose indicators the dataset
  does not contain.
- **"The prompt-token estimator runs ~26% low … so this is a note rather than a
  defect."** — false, twice over. It ran **59%** low on real Splunk evidence
  (20,000 budgeted vs 31,850 actual on a 32,768-token window, leaving a 918-token
  margin), and it **was** a defect. `_CHARS_PER_TOKEN` is now 2.5, and the budget
  is derived rather than hardcoded.

## THE HEADLINE: the re-ask manufactured `inconclusive`

The whole-branch review found what four per-task reviews structurally could not.

There were **two** copies of the analyst's required answer block:

```
prompts.py  _FINDING_FOOTER:  DISPOSITION → CONFIDENCE → RATIONALE → OBSERVATIONS → CITATIONS
analyze.py  _FINDING_REASK:   OBSERVATIONS → CONFIDENCE → RATIONALE → CITATIONS
                              ↑ no DISPOSITION line at all
```

`_FINDING_REASK` is appended to the user turn and says *"Reply again, ending with
exactly:"* — so it is the **last and most explicit** instruction the model reads.
The chain, every link confirmed in source and in the live log:

1. the network slice was over-packed (the estimator defect above) → first reply
   unparseable
2. `_invoke_with_one_reask` re-asked, appending `_FINDING_REASK`
3. the re-ask never asks for a disposition
4. the model complied → no `DISPOSITION` emitted
5. `parse_finding` defaulted the missing field to `inconclusive`, at `logger.info`,
   which the default `ERROR` level hides

**So a model obeying our own template verbatim could never answer with a
disposition.** The documented answer for that case was `malicious`.

**This session created the contradiction.** An earlier task made `DISPOSITION` the
load-bearing first field and reordered *one* of the two copies without looking for
the other. That is CLAUDE.md's duplication rule — "unjustified duplication gets
extracted now" — violated by the task decomposition itself. Nobody asked "where
else is this block specified?", and a review scoped to one diff cannot ask it.

Fixed by making `prompts._FINDING_ANSWER_BLOCK` the single definition, imported by
both consumers, with a test asserting field set **and** order. `shown.py`'s
equivalent pair was checked, found already in agreement, and is now pinned by a
regression test — though it still hand-writes two copies (see Open).

## The diagnosis this replaces

The live run's wrong verdict was first attributed to prompt wording (the
`suspicious`/`inconclusive` tie-break "not taking effect"), and a fix was
dispatched for that. **That diagnosis was wrong.** The tie-break work is
independently defensible and stays, but it was aimed at the wrong target. The
second theory — that 97% context pressure confounded it — was half right: context
pressure caused the re-ask, and the re-ask caused the verdict.

Two wrong diagnoses in sequence, both plausible, both from reading the prompt
rather than the whole path.

## Also landed

**Job 1 — the SIEM path is traced, and the planner works.** First live multi-step
siem plan ever to execute. `CompletionRule.categories` exercised for the first
time and correct: `siem-dns` declared `dns_resolutions` and closed on 46 rows in
that category; `siem-connections` closed on its own 124. Splunk MCP calls appear
as spans carrying `tool_family=siem`, nested under `smartops.investigation`, with
`run_id` on the root. `IndexScopeGuard` rejected a **hallucinated index**
(`index=botsv_v10`; the real one is `botsv3`) — the guard catching a fabrication
that would otherwise have read as an empty result.

**Job 2 — the answer sheet, and why it is inert.** `bench.py` imports
`broker_task` and **never the analyst tier**; `_execute_single_run` calls only the
Broker. So `disposition_correct` can only ever be `None` today, documented in three
places in code and deliberately absent from the human-readable report so no reader
can mistake it for a pass. `bench.py` has always been a *fetch-tier* benchmark.
Wiring `analyze()` in is a scope decision — it needs a model configured and spends
CMU-minutes per case per run.

Two cases repointed at real documented indicators: `botsv3_c2_ip` →
`botsv3_c2_beacon` (`45.77.53.176`, host **ABUNGST-L** — Q323 documents ABUNGST-L
and FYODOR-L as the C2 contactors, not BSTOLL-L), and `botsv3_powershell_hash` →
`botsv3_hdoor_tool` (`586EF56F4D8963DD546163AC31C865D7` = `hdoor.exe`, Q307).

**Job 3 — the README documented half the system.** No mention of
`subagent_analysts`, `findings.json`, `Disposition` or `HypothesisFindings`
anywhere; its "analyst" hits were all the upstream Analyst Agent. Corrected, plus
five stale figures across `architecture.md` and the two tracked confluence pages.

**Token accounting, twice.** `_PACK_TOKEN_BUDGET` is now derived:
`32,768 − system prompt − generation − scaffold − safety margin = 25,392`. The
system-prompt reserve is measured at import from the rendered prompt, so a future
prompt edit costs evidence budget rather than silently eating the margin. Two
rounds were needed: the first derivation landed exactly on the ceiling with a
scaffold reserve short at one entity, and the second measured the scaffold against
a 20-entity worst case (474 → 833). Per-domain margins now: identity 577, network
500, endpoint 590.

**`SMARTOPS_ANALYST_MAX_GEN_LEN` is clamped.** The budget is frozen at import from
the module default while `analyst_model_from_env` read the env var at runtime — so
`=8192` overflowed the window by ~4,600 tokens, silently, while the docstring
asserted it could not happen.

## Open

- **The answer sheet scores nothing** until `analyze()` is wired into the bench
  runner. Three documented answers sit ready.
- **No AWS cases.** BOTSv3's richest answers live in `aws:cloudtrail` /
  `aws:s3:accesslogs`, and `routing._CATEGORY_DOMAIN` maps no `aws:*` category.
  Settle that routing question before building them.
- **`shown.py` still hand-writes its `_REASK`/`_VERDICT_FOOTER` pair.** They agree
  and a test now pins it, but the structural risk the blind path just eliminated
  remains there.
- **The reporting floor's "at most 10 observations" is a chosen number**, validated
  against two data points (17 pre-floor, 82 post-floor). Re-measure on the next
  live run.
- **`docs/fix_anchors.py` silently skips** shorthand `` `:N` `` anchors whose symbol
  is ambiguous across modules. `check_anchors.py` still catches what it misses, but
  it should report what it declines to touch.
- **`BOTSV3_C2_IP_TASK`** keeps its old constant name while its `task_id` is
  `botsv3_c2_beacon`. A test now guards key/`task_id` drift, which is the better
  investment than the rename.
- **`docs/confluence-subagent-analysts.md`** was briefly tracked and then untracked
  again, restoring the decision recorded in `46ad14f`. Whether it belongs in git is
  still an open question for the team.

## Process note

Of the eleven defects found across today, **six came from running the thing and
reading its output** — not from tests, review, or reading code. The planner had
never worked in production; 848 tests passed anyway. The one defect that mattered
most was invisible to every per-task review by construction, because it lived in
the interaction between two tasks: one changed a template, the other owned its
duplicate.

The transferable rule is narrow: **when you change a string a model is instructed
by, grep for every other place that string is specified.** A per-task review sees
one diff. Duplication that spans modules needs the whole-branch pass, and this
session is the argument for keeping that pass.
