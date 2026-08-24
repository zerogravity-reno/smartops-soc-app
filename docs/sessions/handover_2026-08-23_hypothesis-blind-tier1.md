---
date: 2026-08-23
title: Hypothesis-blind Tier 1 lands, then a real run explains why the "fix" isn't proof yet
---

# Handover — 2026-08-23, Tier 1 redesign + a real-run deep dive + code review in flight

Branch `task-broker-agent`, no `origin/main` tracking ref configured locally (push
status unknown from here — check before assuming anything is or isn't upstream).
HEAD is `e131e74`. Tree has **one unrelated pre-existing modification**
(`backend/src/smartops/bench.py`, a benchmark-case addition from earlier this
session, deliberately left uncommitted — see "Loose ends" below) plus several
untracked docs/report artifacts. `uv run pytest` from root: **605 passed, 0
failed** as of the last full run (before this session's code-review pass — that
review did NOT re-run the suite, it read code).

The authoritative trail for the Tier-1 work is
`docs/superpowers/plans/2026-08-23-hypothesis-blind-analysts-tier1.md` +
`docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md` (both
now committed, `e131e74`). This document covers what happened after the plan
finished: a real run, a deep-dive into *why* it looked interesting, and a
still-in-progress code review.

---

## THE HEADLINE: the anchoring-bias demo is real, but its own root cause is a bug, not model insight

Tier 1 of the hypothesis-blind redesign (`gather_finding`/`facts_system_prompt`/
`parse_finding`/`DomainFinding`) is implemented, task-reviewed, whole-branch
reviewed (opus, APPROVE), and landed additively across 5 commits
(`5caf246`..`8512f28`) — the old hypothesis-shown path (`run_one`/`analyze`/
`combine`) is untouched and still what `main.py --hypothesis` actually runs.
Tier 1 is **not wired into production** on purpose; that's the Aggregator
cycle, still deferred.

To see it do something, I ran a fresh, live, non-scripted investigation
(`cli-20260823T112627`, same BSTOLL-L/coinhive.com BOTS v3 case, real VT+SIEM
fetch, ~$1.50) and, on the exact same evidence, ran the OLD path (production)
side by side with the NEW path (`gather_finding`, via a standalone comparison
script — nothing production calls it yet). Same record, `auth_events#6`:

- **Old (hypothesis-shown):** "legitimate local logins" → contributed to
  overall **REFUTES, confidence 0.85**.
- **New (hypothesis-blind):** "potential password spraying attempt" →
  **confidence 0.90**.

That's a real, reproducible anchoring-bias demonstration and it's why Tier 1
exists. Built a report on it: `docs/hard-test-new-run.html`.

**Then the user asked me to dig into why, and the answer is a code bug, not
proof either analyst reasoned better:**

`backend/src/smartops/subagent_analysts/formatting.py:48-56`
(`_format_auth_event`) only projects `time/user/src/dest/action/app` per row —
it silently drops `EventCode` and `Logon_Type`, even when the SIEM subagent's
own SPL explicitly fetched them (confirmed by re-running the *actual*
`pack_evidence()` call against this run's real report — see
`docs/hard-test-new-run.html`'s footnotes for the literal packed text). The
real raw row behind `auth_events#6` is `EventCode 4624, Logon_Type 11`
(CachedInteractive) followed by `EventCode 4624→4648, Logon_Type 7` (Unlock)
ten seconds later — the textbook signature of a laptop being unlocked by its
own user. Both analysts saw six near-blank rows with the one discriminating
field already stripped. The old analyst, finding nothing that matched its
checklist, called it clean. The new analyst pattern-matched "same account, six
times, ten seconds" onto "password spraying" — a label its *own prompt*
defines as "one source failing across many accounts" (verified: that
definition is in both `_IDENTITY_BODY` and `_IDENTITY_FACTS_BODY`,
`prompts.py:81,257`), which doesn't match one account with no visible
failures either. Neither verdict is trustworthy proof of anything; both are
downstream of the same missing fields.

**Two more things the deep-dive turned up, digging into `evidence.json`
directly:**

1. **Identity never gets reconciled across log sources.** Auth events use
   `bstoll@froth.ly` (WORKGROUP UPN); the process/network activity that
   actually matters (the coinhive-bound Chrome connection, the encoded
   PowerShell) is all under `AzureAD\BudStoll`. Several of the SIEM
   subagent's own higher-fidelity auth queries hard-filter on the literal
   string `bstoll@froth.ly`, which structurally excludes `BudStoll` — so
   identity's finding and network/endpoint's findings are, mechanically,
   about two different-looking identities nothing ties together.
2. **The test case's own hypothesis overstates a causal link the evidence
   doesn't show.** The raw `nvzFlow` record for the 217.182.164.14
   connection is `chrome.exe` (parent `explorer.exe`) talking to
   `ws001.coinhive.com` — real, documented BOTS v3 browser cryptomining. The
   encoded PowerShell (disabling its own `ScriptBlockLogging`) is a *separate*
   process spawned by `browser_broker.exe`. Nothing in the evidence ties the
   two into one "PowerShell payload → C2" chain, which tracks with the named
   file hash coming back completely unknown to VirusTotal, both times it was
   checked.

---

## What landed this session

| Item | Commits / files | Result |
|---|---|---|
| Tier 1 Task 1 — `DomainFinding` contract | `1305805` | reviewed clean |
| Tier 1 Task 2 — facts-only prompts | `4f389fa` | reviewed clean; 1 ruling (`_FACTS_SECURITY_BLOCK`, see below), 1 minor deferred |
| Tier 1 Task 3 — `parse_finding`/`FindingParseError` | `b86a0a8` | reviewed clean; 1 ruling (local observations regex, see below), 1 minor deferred |
| Tier 1 Task 4 — `gather_finding`/`_finalize_finding` | `8512f28` | reviewed clean, zero findings |
| Tier 1 Task 5 — full regression | (verification only) | 605/605, confirmed no plan-unrelated files touched |
| Final whole-branch review (opus) | range `5caf246..8512f28` | **APPROVE**, only Minor findings |
| Spec + plan committed | `e131e74` | were untracked despite being cited by docstrings |
| Real end-to-end run + comparison | `cli-20260823T112627` | old-vs-new side by side, real evidence |
| `docs/hard-test-new-run.html` | new | the auth_events#6 diptych report |
| Root-cause deep dive | (this session, no commit yet) | traced the flip to `formatting.py`'s dropped fields — **not yet fixed** |

**Two rulings made during the SDD process, both already re-confirmed by the
final whole-branch review, worth knowing before re-litigating them in
code review:**
- `_FACTS_SECURITY_BLOCK` deliberately duplicates `_SECURITY_BLOCK` (the
  original mentions "hypothesis," which Tier 1 must never say) — accepted,
  not a bug.
- `parse_finding`'s local observations regex deliberately doesn't reuse
  `_OBSERVATIONS_RE` (which assumes OBSERVATIONS immediately precedes
  CITATIONS; Tier 1's field order is different) — accepted, not a bug.

## Code review — in flight, not yet finalized

`/code-review` ran 8 finder angles in the background; all 8 reported. I was
mid-verification (checking the strongest candidates directly against code,
not just trusting the angle reports) when this handover was requested — **no
`ReportFindings` call has happened yet, nothing has been fixed.**

**Confirmed by direct code inspection (real bugs, not yet fixed):**
- `parse.py:24` `_CONFIDENCE_RE = re.compile(r"CONFIDENCE\D*([0-9]*\.?[0-9]+)")`
  — `\D*` crosses newlines and other fields. A reply with no numeric
  confidence (e.g. `CONFIDENCE: unclear`) can lock onto a digit anywhere
  later in the text, including inside a citation like `auth_events#1`,
  manufacturing `confidence=1.0` from a reply that gave none. Affects both
  `parse_verdict` and `parse_finding`.
- `model.py:129` `os.environ["AWS_BEARER_TOKEN_BEDROCK"] = self._api_key` —
  mutates process-global env with no cleanup. A second `AnalystModel` built
  later in the same process with no explicit key silently inherits the
  first one's stale bearer token instead of falling through to the default
  AWS credential chain.
- `subagents/__init__.py:465-480` + `:670-682` — `investigate()`'s
  `except BaseException: await budget.release(reservation)` releases the
  **full** reservation on any exception, but `_build_agent_and_invoke` can
  make a real, billable second ("recovery") model call *after* the first one
  already succeeded and spent tokens. If that second call throws, the whole
  reservation — including the first call's real spend — is refunded as if
  nothing happened. Two angles converged on this independently.
- `subagent_analysts/model.py` / `main.py:658` — analyst-model spend never
  goes through `Budget.reserve()`/`settle()` at all; `analyze()` takes no
  `Budget` argument. No admission control on analyst calls, and
  `budget.spend_by_role()` — the thing the whole Budget module exists to
  report — silently under-reports total investigation cost by the analyst
  share. Two angles (reuse, my own earlier report footnote) converged.
- `projection.py` `project_vt` — an unparseable VT payload now emits **no**
  verdict at all (silent `continue` + log line) instead of the old
  synthesized "unknown" verdict. Two angles converged independently. Real
  fix for a worse bug (was: "unknown" masqueraded as "clean"), but the new
  failure mode is invisible downstream — a `DomainSlice` just looks like
  "nothing was queried."

**Plausible, not yet fully chased down:**
- `broker.py:560` `outcome.confirmed_empty = confirmed_empty or outcome.confirmed_empty`
  is monotonic — checked the surrounding code; completion (`rows_or_confirmed_empty`)
  is likely unaffected in practice because `rows_retrieved` growing past
  `min_rows` satisfies completion independently of the stale flag. Whether
  anything else reads `confirmed_empty` as a standalone "we can assert zero
  data" claim (report rendering, gap analysis) is not yet checked.
- `subagents/__init__.py` `_estimated_input_tokens` caps `expected_turns` at
  8 while `main.py --subagent-turns` defaults to 25 — two angles converged;
  plausible under-reservation on long SIEM runs, not yet traced to an actual
  observed budget-negative incident.
- `formatting.py`'s dropped `EventCode`/`Logon_Type` fields (this session's
  own finding, above) — not raised by any of the 8 angles, since it's a
  semantic/data-quality gap rather than a diff-visible defect pattern. Worth
  folding into the same fix pass since it's the same file family.

**Already-settled, filtered out rather than re-flagged:** several angles
independently re-discovered the two SDD rulings above, the deliberate
`broker_flat.py` removal (documented in `docs/PROJECT_DOCS.md`), and the
deliberate "Tier 1 lands unwired" sequencing decision (explicit in the plan's
own "Sequencing Decision" section, and in the user's own direction to get
prompts/output right before building the Aggregator). None of those are
fresh defects — re-raising them would contradict CLAUDE.md's own governance
note about not re-litigating settled decisions.

**Not yet done:** dedup the ~35 raw candidate findings down to a final
verified list, decide fix-vs-park per item, and call `ReportFindings`
(or hand a fix list to the next session).

## Loose ends worth knowing about

- `backend/src/smartops/bench.py` has an uncommitted, pre-existing
  modification (`BOTSV3_HARD_MULTI_VECTOR_TASK`) from earlier this session's
  Splunk test-case exploration — deliberately left uncommitted, out of scope
  for the Tier-1 plan. Several untracked `docs/*.html` report artifacts and
  `graphify-out/` are similarly pre-existing and unrelated.
- Reloading a persisted `report.json` from disk via a plain
  `BrokerReport.model_validate_json()` silently loses every typed SIEM/VT
  field (`SubtaskResult.findings` has no discriminator between `Findings`
  subtypes) — found while building the comparison script, worked around
  there, **not fixed in production** (nothing in the live pipeline reloads a
  persisted report today, so it's latent, not active).
- CLAUDE.md's Tests section claims "no `filterwarnings` is configured
  anywhere" — the CLAUDE.md conventions review angle found the root
  `pyproject.toml` already contradicts this
  (`filterwarnings = ["error::DeprecationWarning", ...]`), and a new
  `README.md` line in this diff documents the true (opposite) state. Worth a
  CLAUDE.md correction — its own governing clause says to raise this again
  once its stated premise is no longer true.

## Ranked queue for the next session

1. **Finish the code review**: dedup the confirmed findings above, verify
   the two "plausible" items, call `ReportFindings` or write the fix list.
2. **Fix `_format_auth_event`** (`formatting.py:48-56`) — add `EventCode`/
   `Logon_Type` to the projection. Small, surgical, in the existing
   field-alias pattern. This is the actual root cause behind the whole
   auth_events#6 story — worth doing before treating any future
   old-vs-new comparison as meaningful.
3. **Fix `_CONFIDENCE_RE`** — anchor it so it can't cross into a citation's
   digits. Affects both the live production path and Tier 1.
4. **Fix the `AWS_BEARER_TOKEN_BEDROCK` env leak** and the **budget
   over-refund on recovery-call exception** — both are real correctness
   bugs in already-shipped code, independent of Tier 1.
5. **Decide what to do about analyst spend never entering `Budget`** — this
   is a design question (does `analyze()`/`gather_finding` need a `Budget`
   argument?), not a one-line fix; flag for Mohamed rather than just doing
   it.
6. Once the above is settled: the Aggregator (Tier 2), the condensed-finding
   contract/pipeline docs, and formalizing a clean `bench.py` test case —
   all still explicitly deferred, per the user's own direction this session.

## Process lessons worth keeping

- **"What do you think of this run?" and "dig into why" are different
  questions, and the second one is where the real bug was.** The narrative
  critique (old path overconfident on absence-of-evidence, new path
  suspiciously uniform-high-confidence) was directionally right but the
  actual root cause only showed up from re-running the real `pack_evidence()`
  call and reading the raw Splunk rows directly — inference from the verdict
  text alone would have missed it.
- **Two independent angles converging on the same bug is a strong signal** —
  used it here (`project_vt` silent-drop, the 8-turn budget cap, the
  analyst-spend-not-in-Budget gap) to prioritize verification effort instead
  of chasing all ~35 raw candidates equally.
- **Check the SDD ledger before treating a code-review finding as new.**
  Several of the 8 angles re-discovered decisions already ruled on during
  Tier 1's own implementation — re-flagging those would have been noise, not
  signal.
