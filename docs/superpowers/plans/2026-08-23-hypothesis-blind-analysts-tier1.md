# Hypothesis-Blind Domain Analysts — Tier 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each domain analyst (identity/network/endpoint) a hypothesis-free prompt path that reports grounded findings instead of a supports/refutes stance, without touching or breaking the currently-working hypothesis-shown path.

**Architecture:** Add a second, parallel set of prompt bodies, a parser, and an orchestration function (`facts_system_prompt`/`build_facts_user_turn`, `parse_finding`, `gather_finding`) alongside the existing `system_prompt`/`build_user_turn`, `parse_verdict`, `run_one` — purely additive, not wired into `analyze()` yet. The Aggregator that consumes this new path is a later cycle.

**Tech Stack:** Python 3.13, pydantic (contracts), pytest (`asyncio_mode = "auto"` at the workspace root).

**Spec:** `docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md`

## Global Constraints

- Every existing test must keep passing unchanged. `run_one`, `parse_verdict`, `combine`, `analyze`, `system_prompt`, `build_user_turn`, `_VERDICT_FOOTER`, and every currently-hypothesis-framed body constant are **not modified or deleted** in this plan — see "Sequencing Decision" below.
- No new third-party dependencies.
- Run the full suite from the workspace root: `uv run pytest` (root `pyproject.toml` already sets `asyncio_mode = "auto"` and `testpaths` covering both packages — do not `cd` into `backend/` first).
- The new code is not called from `analyze()`, `main.py`, or anywhere else yet. It exists, is tested, and sits unused until the Aggregator cycle swaps `analyze()` over to it.

## Sequencing Decision

The spec describes the end state as if `system_prompt()`/`build_user_turn()`/`_VERDICT_FOOTER` and the hypothesis-framed bodies get deleted as dead code. They can't be deleted *yet*: `run_one()` and `analyze()` still use them, and `main.py`'s `--hypothesis` CLI path depends on that whole chain working today. The Aggregator — the thing that would replace `run_one()`'s stance-producing role — is explicitly out of scope for this plan.

So this plan adds a second, distinctly-named set of symbols instead of overwriting the existing ones:

| Existing (untouched) | New (this plan) |
|---|---|
| `_IDENTITY_BODY`, `_NETWORK_BODY`, `_ENDPOINT_BODY` | `_IDENTITY_FACTS_BODY`, `_NETWORK_FACTS_BODY`, `_ENDPOINT_FACTS_BODY` |
| `_VERDICT_FOOTER` | `_FINDING_FOOTER` |
| `system_prompt()` | `facts_system_prompt()` |
| `build_user_turn()` | `build_facts_user_turn()` |
| `parse_verdict()`, `VerdictParseError` | `parse_finding()`, `FindingParseError` |
| `run_one()`, `_REASK` | `gather_finding()`, `_FINDING_REASK` |
| `AnalystVerdict` | `DomainFinding` (new contract type) |

This is a purely additive diff: zero lines of existing, working code change. When the Aggregator cycle lands and swaps `analyze()` over to `gather_finding()`, that cycle deletes the left column and — if desired — renames the right column down to the plain names. That cleanup is not this plan's job.

## File Structure

- `contracts/src/contracts/reasoning.py` — add `DomainFinding` (new pydantic model).
- `contracts/src/contracts/__init__.py` — export `DomainFinding`.
- `backend/src/smartops/subagent_analysts/prompts.py` — append the three new facts-only bodies, `_FINDING_FOOTER`, `facts_system_prompt()`, `build_facts_user_turn()`.
- `backend/src/smartops/subagent_analysts/parse.py` — append `FindingParseError`, `parse_finding()`.
- `backend/src/smartops/subagent_analysts/analyze.py` — append `_FINDING_REASK`, `gather_finding()`, `_finalize_finding()`.
- `backend/tests/test_analyst_prompts.py` — add `TestFactsSystemPrompt`, `TestFactsUserTurn`.
- `backend/tests/test_analyst_parse.py` — add `TestParseFinding`.
- `backend/tests/test_analyst_analyze.py` — add `TestGatherFinding`.

---

### Task 1: `DomainFinding` contract type

**Files:**
- Modify: `contracts/src/contracts/reasoning.py` (append after `AnalystVerdict`, before `HypothesisAssessment`)
- Modify: `contracts/src/contracts/__init__.py`
- Test: `backend/tests/test_analyst_parse.py` (verified indirectly in Task 3 — this task's own check is a quick construction smoke test, since a bare pydantic model has no behaviour of its own to unit-test yet)

**Interfaces:**
- Produces: `contracts.DomainFinding(domain: AnalystDomain, observations: list[str] = [], citations: list[str] = [], confidence: float = 0.0, rationale: str = "", reasoning_trace: str | None = None, prompt_tokens: int = 0, generation_tokens: int = 0)`

- [ ] **Step 1: Add `DomainFinding` to `contracts/src/contracts/reasoning.py`**

Insert directly after the `AnalystVerdict` class (after its closing `prompt_tokens`/`generation_tokens` fields, before `class HypothesisAssessment`):

```python
class DomainFinding(BaseModel):
    """One domain analyst's evidence-grounded findings, with no hypothesis in view.

    Tier 1 of the hypothesis-blind pipeline (see
    docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md): the
    domain analyst never sees the hypothesis, so there is no `stance` here --
    only what the evidence itself shows. A later Aggregator cycle turns a list
    of these plus a hypothesis into an `AnalystVerdict` per domain.
    """

    domain: AnalystDomain
    observations: list[str] = Field(default_factory=list)
    citations: list[str] = Field(
        default_factory=list,
        description="Evidence header ids the finding rests on, e.g. 'auth_events#1'.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence that these observations are real and correctly grounded -- "
            "not confidence in any stance; there is no stance at this layer."
        ),
    )
    rationale: str = ""
    reasoning_trace: str | None = Field(
        default=None,
        description="The model's <think> chain. Persisted for audit, never re-fed.",
    )
    prompt_tokens: int = Field(default=0, ge=0)
    generation_tokens: int = Field(default=0, ge=0)
```

- [ ] **Step 2: Export it from `contracts/src/contracts/__init__.py`**

Find the existing import block (it lists `AnalystVerdict,` then `HypothesisAssessment,` then `InvestigationContext,` — from the `reasoning` submodule). Add `DomainFinding,` alphabetically before `HypothesisAssessment,`:

```python
    DomainFinding,
    HypothesisAssessment,
```

Then find the `__all__` list, which has `"AnalystVerdict",` and, a few lines later, `"HypothesisAssessment",` / `"InvestigationContext",`. Add `"DomainFinding",` alphabetically:

```python
    "DomainFinding",
```

- [ ] **Step 3: Smoke-test the import**

Run: `uv run python -c "from contracts import DomainFinding; f = DomainFinding(domain='identity'); print(f.confidence, f.citations)"`
Expected: prints `0.0 []` with no error.

- [ ] **Step 4: Commit**

```bash
git add contracts/src/contracts/reasoning.py contracts/src/contracts/__init__.py
git commit -m "contracts: add DomainFinding for the hypothesis-blind analyst pipeline"
```

---

### Task 2: Facts-only prompts (`prompts.py`)

**Files:**
- Modify: `backend/src/smartops/subagent_analysts/prompts.py` (append at end of file, after `build_user_turn`)
- Test: `backend/tests/test_analyst_prompts.py`

**Interfaces:**
- Consumes: `METIS_PREAMBLE`, `_SECURITY_BLOCK`, `_render_scope()` (all already in this file, unchanged); `contracts.AnalystDomain`, `contracts.Scope`; `smartops.guards.fenced`
- Produces: `facts_system_prompt(domain: AnalystDomain) -> str`, `build_facts_user_turn(scope: Scope, evidence_text: str) -> str`

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_analyst_prompts.py`, after the existing `TestUserTurn` class and before `TestPacking`:

```python
class TestFactsSystemPrompt:
    def test_domain_focus_is_embedded(self):
        assert "authentication" in facts_system_prompt("identity").lower()
        assert "dns" in facts_system_prompt("network").lower()
        assert "process" in facts_system_prompt("endpoint").lower()

    def test_no_hypothesis_or_verdict_framing(self):
        for domain in ("identity", "network", "endpoint"):
            p = facts_system_prompt(domain)
            assert "HYPOTHESIS" not in p
            assert "VERDICT" not in p
            assert "hypothesis" not in p.lower()

    def test_states_finding_format_and_untrusted_regions(self):
        p = facts_system_prompt("identity")
        assert "OBSERVATIONS:" in p and "CONFIDENCE:" in p and "CITATIONS:" in p
        assert "UNTRUSTED" in p

    def test_augments_metis_persona_not_replaces_it(self):
        p = facts_system_prompt("network")
        assert "You are Metis" in p
        assert p.index("You are Metis") < p.index("network detection")


class TestFactsUserTurn:
    def test_no_hypothesis_anywhere(self):
        turn = build_facts_user_turn(_scope(), "# auth_events#1 · rows=1")
        assert "hypothesis" not in turn.lower()

    def test_scope_and_evidence_are_fenced(self):
        turn = build_facts_user_turn(_scope(), "# auth_events#1 · rows=1")
        assert "<scope>" in turn and "host: BSTOLL-L" in turn
        assert "<evidence>" in turn and "auth_events#1" in turn
```

Update this test file's import line (currently `from smartops.subagent_analysts.prompts import build_user_turn, system_prompt`) to also import the two new names:

```python
from smartops.subagent_analysts.prompts import (
    build_facts_user_turn,
    build_user_turn,
    facts_system_prompt,
    system_prompt,
)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest backend/tests/test_analyst_prompts.py -v`
Expected: `ImportError: cannot import name 'facts_system_prompt'` (or `build_facts_user_turn`) — the new names don't exist yet.

- [ ] **Step 3: Append the new prompt content to `prompts.py`**

Add at the end of the file (after the existing `build_user_turn` function), with a section comment marking it as the new, not-yet-wired-in path:

```python
# ---------------------------------------------------------------------------
# Tier 1 of the hypothesis-blind redesign (see
# docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md).
#
# These bodies never mention a hypothesis. The opening deliberately avoids
# even saying "you are not told the hypothesis" -- that phrasing tips the
# model off that one exists and invites it to guess at it, which defeats the
# point. Evidence format, threat catalog, and grounding rules are otherwise
# unchanged from the hypothesis-framed bodies above; only the framing and the
# final grounding rule (a clean read must be reported, not left blank) differ.
#
# Not yet called from analyze() -- see the plan's "Sequencing Decision".
# ---------------------------------------------------------------------------

_IDENTITY_FACTS_BODY = f"""\
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

{_FINDING_FOOTER}"""

_NETWORK_FACTS_BODY = f"""\
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

{_FINDING_FOOTER}"""

_ENDPOINT_FACTS_BODY = f"""\
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

{_FINDING_FOOTER}"""

_FACTS_BODY_BY_DOMAIN: dict[AnalystDomain, str] = {
    "identity": _IDENTITY_FACTS_BODY,
    "network": _NETWORK_FACTS_BODY,
    "endpoint": _ENDPOINT_FACTS_BODY,
}


def facts_system_prompt(domain: AnalystDomain) -> str:
    """The hypothesis-blind system prompt: Metis preamble + the facts-only body.

    Unlike `system_prompt()`, the domain never sees the hypothesis in this call
    or anywhere else in the Tier-1 pipeline.
    """
    return f"{METIS_PREAMBLE}\n\n{_FACTS_BODY_BY_DOMAIN[domain]}"


def build_facts_user_turn(scope: Scope, evidence_text: str) -> str:
    """Assemble the hypothesis-blind user turn: fenced scope and evidence only.

    No hypothesis is included anywhere in this turn -- that is the entire point
    of the Tier-1 path. Reuses `_render_scope()` and `guards.fenced()`, same as
    `build_user_turn()`.
    """
    return (
        fenced("scope", _render_scope(scope))
        + "\n\n"
        + fenced("evidence", evidence_text)
        + "\n\nList every security-relevant finding you can support from the evidence "
        "above. Give your reasoning, then the required block."
    )
```

Add `_FINDING_FOOTER` immediately before this new block (it must exist before `_IDENTITY_FACTS_BODY` references it in an f-string):

```python
# Shared by the three facts-only bodies above, mirroring `_VERDICT_FOOTER`'s
# citation discipline but with no VERDICT line -- there is no stance at this
# layer, only observations.
_FINDING_FOOTER = """\
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
CITATIONS: <comma-separated full header ids you actually used, e.g. auth_events#1, auth_events#2>"""
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest backend/tests/test_analyst_prompts.py -v`
Expected: all tests PASS, including the four pre-existing classes (`TestSystemPrompt`, `TestUserTurn`, `TestPacking`) unchanged.

- [ ] **Step 5: Commit**

```bash
git add backend/src/smartops/subagent_analysts/prompts.py backend/tests/test_analyst_prompts.py
git commit -m "subagent_analysts: add hypothesis-blind facts prompts alongside the existing ones"
```

---

### Task 3: `parse_finding()` (`parse.py`)

**Files:**
- Modify: `backend/src/smartops/subagent_analysts/parse.py` (append at end of file)
- Test: `backend/tests/test_analyst_parse.py`

**Interfaces:**
- Consumes: `_CONFIDENCE_RE`, `_RATIONALE_RE`, `_CITATIONS_RE`, `_OBSERVATIONS_RE`, `_strip_md()`, `split_reasoning()` (all already in this file, unchanged); `contracts.AnalystDomain`, `contracts.DomainFinding` (from Task 1)
- Produces: `FindingParseError(ValueError)`, `parse_finding(generation: str, *, domain: AnalystDomain) -> DomainFinding`

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_analyst_parse.py`, at the end of the file:

```python
_GOOD_FINDING = """the logons cluster around one account with no failures preceding \
success, and no process or network rows are present in this slice.
</think>
OBSERVATIONS:
- one clean logon for bostoll from 10.0.1.50, no prior failures [auth_events#1]
CONFIDENCE: 0.65
RATIONALE: A single successful logon with no surrounding anomaly pattern.
CITATIONS: auth_events#1"""


class TestParseFinding:
    def test_parses_rich_finding(self):
        f = parse_finding(_GOOD_FINDING, domain="identity")
        assert f.domain == "identity"
        assert f.confidence == 0.65
        assert "logon" in f.rationale
        assert len(f.observations) == 1
        assert f.citations == ["auth_events#1"]
        assert f.reasoning_trace and "cluster" in f.reasoning_trace

    def test_confidence_is_clamped(self):
        out = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCONFIDENCE: 3.0\nCITATIONS: auth_events#1"
        assert parse_finding(out, domain="network").confidence == 1.0

    def test_missing_observations_and_citations_raises(self):
        with pytest.raises(FindingParseError):
            parse_finding("</think>I looked at the evidence and it seems fine.", domain="endpoint")

    def test_citations_alone_are_enough_to_parse(self):
        # No OBSERVATIONS block, but a CITATIONS line is still a recognisable finding.
        out = "</think>RATIONALE: nothing notable.\nCITATIONS: auth_events#1"
        f = parse_finding(out, domain="identity")
        assert f.citations == ["auth_events#1"]
        assert f.observations == []

    def test_defaults_when_optional_fields_absent(self):
        out = "</think>OBSERVATIONS:\n- x [auth_events#1]"
        f = parse_finding(out, domain="endpoint")
        assert f.confidence == 0.0
        assert f.rationale == ""
        assert f.citations == []

    def test_markdown_bolded_block_parses(self):
        out = (
            "prose...\n</think>\n"
            "**OBSERVATIONS:**  \n"
            "- BSTOLL-L ran chrome.exe [processes#1]  \n"
            "**CONFIDENCE:** 0.7  \n"
            "**RATIONALE:** Evidence shows chrome.exe referencing the CoinHive library.  \n"
            "**CITATIONS:** processes#1"
        )
        f = parse_finding(out, domain="endpoint")
        assert f.confidence == 0.7
        assert f.citations == ["processes#1"]
        assert "CoinHive" in f.rationale
        assert f.observations == ["BSTOLL-L ran chrome.exe [processes#1]"]
```

Update this test file's import block (currently `from smartops.subagent_analysts.parse import (VerdictParseError, parse_verdict, split_reasoning,)`) to also import the two new names:

```python
from smartops.subagent_analysts.parse import (
    FindingParseError,
    VerdictParseError,
    parse_finding,
    parse_verdict,
    split_reasoning,
)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest backend/tests/test_analyst_parse.py -v`
Expected: `ImportError: cannot import name 'parse_finding'`.

- [ ] **Step 3: Append `parse_finding()` and `FindingParseError` to `parse.py`**

Add at the end of the file:

```python
class FindingParseError(ValueError):
    """The generation carried no recognisable OBSERVATIONS or CITATIONS block."""


def parse_finding(generation: str, *, domain: AnalystDomain) -> DomainFinding:
    """Parse a hypothesis-blind generation into a `DomainFinding`.

    Unlike `parse_verdict`, there is no stance to recover here: "parseable"
    means an OBSERVATIONS or CITATIONS block was found at all. Reuses the same
    generic label regexes as `parse_verdict`; only the stance-specific
    `_STANCE_RE`/`_normalise_stance` are skipped, because there is no stance at
    this layer.
    """
    reasoning, raw_answer = split_reasoning(generation)
    answer = _strip_md(raw_answer)

    observations = _parse_observations(answer)
    citations = _parse_citations(answer)
    if not observations and not citations:
        raise FindingParseError(
            f"no OBSERVATIONS or CITATIONS block found in {domain} analyst output"
        )

    confidence_match = _CONFIDENCE_RE.search(answer)
    confidence = float(confidence_match.group(1)) if confidence_match else 0.0
    confidence = max(0.0, min(1.0, confidence))

    rationale_match = _RATIONALE_RE.search(answer)
    rationale = rationale_match.group(1).strip() if rationale_match else ""

    return DomainFinding(
        domain=domain,
        observations=observations,
        citations=citations,
        confidence=confidence,
        rationale=rationale,
        reasoning_trace=reasoning,
    )
```

Update this module's import line (currently `from contracts import AnalystDomain, AnalystVerdict, Stance`) to also import `DomainFinding`:

```python
from contracts import AnalystDomain, AnalystVerdict, DomainFinding, Stance
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest backend/tests/test_analyst_parse.py -v`
Expected: all tests PASS, including the pre-existing `TestSplitReasoning` and `TestParseVerdict` classes unchanged.

- [ ] **Step 5: Commit**

```bash
git add backend/src/smartops/subagent_analysts/parse.py backend/tests/test_analyst_parse.py
git commit -m "subagent_analysts: add parse_finding for the hypothesis-blind path"
```

---

### Task 4: `gather_finding()` (`analyze.py`)

**Files:**
- Modify: `backend/src/smartops/subagent_analysts/analyze.py` (append at end of file)
- Test: `backend/tests/test_analyst_analyze.py`

**Interfaces:**
- Consumes: `AnalystModel` (`.model`), `DomainSlice` (`.routing`), `pack_evidence()` (`.packing`), `facts_system_prompt()`/`build_facts_user_turn()` (Task 2), `parse_finding()`/`FindingParseError` (Task 3), `contracts.DomainFinding` (Task 1), `contracts.Scope`
- Produces: `gather_finding(model: AnalystModel, scope: Scope, slice_: DomainSlice) -> DomainFinding`

Note the signature has no `context`/`InvestigationContext` parameter at all — Tier 1 never receives the hypothesis, so there is nothing to pass.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_analyst_analyze.py`, after the existing `TestRunOne` class:

```python
class TestGatherFinding:
    def test_good_finding_first_try(self):
        gen = (
            "</think>OBSERVATIONS:\n- clean logon for bostoll [auth_events#1]\n"
            "CONFIDENCE: 0.6\nRATIONALE: nothing unusual.\nCITATIONS: auth_events#1"
        )
        model = _SequenceModel([gen])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.domain == "identity"
        assert finding.confidence == 0.6
        assert finding.citations == ["auth_events#1"]
        assert model.calls == 1

    def test_reask_recovers_a_malformed_first_reply(self):
        good = "</think>OBSERVATIONS:\n- x [auth_events#1]\nCITATIONS: auth_events#1"
        model = _SequenceModel(["no recognisable block here", good])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.citations == ["auth_events#1"]
        assert model.calls == 2

    def test_both_attempts_unparseable_yields_empty_finding(self):
        model = _SequenceModel(["prose one", "prose two"])
        slice_ = DomainSlice(
            domain="network",
            siem_sets=[("connections", ResultSet(query="q", row_count=1, rows=[{"dest": "1.2.3.4"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.confidence == 0.0
        assert "no parseable finding" in finding.rationale
        assert model.calls == 2

    def test_invented_citation_is_dropped(self):
        gen = (
            "</think>OBSERVATIONS:\n- x [auth_events#1]\n- y [auth_events#99]\n"
            "CITATIONS: auth_events#1, auth_events#99"
        )
        model = _SequenceModel([gen])
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(model, _scope(), slice_)
        assert finding.citations == ["auth_events#1"]

    def test_empty_slice_short_circuits_without_a_model_call(self):
        model = _SequenceModel([])  # would IndexError if invoked
        finding = gather_finding(model, _scope(), DomainSlice(domain="endpoint"))
        assert finding.confidence == 0.0
        assert "no endpoint evidence" in finding.rationale
        assert model.calls == 0

    def test_model_exception_is_contained(self):
        slice_ = DomainSlice(
            domain="identity",
            siem_sets=[("auth_events", ResultSet(query="q", row_count=1, rows=[{"user": "bostoll"}]))],
        )
        finding = gather_finding(_RaisingModel(), _scope(), slice_)
        assert finding.confidence == 0.0
        assert "could not run" in finding.rationale
```

Update this test file's import line (currently `from smartops.subagent_analysts.analyze import analyze, combine, run_one`) to also import `gather_finding`:

```python
from smartops.subagent_analysts.analyze import analyze, combine, gather_finding, run_one
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest backend/tests/test_analyst_analyze.py -v`
Expected: `ImportError: cannot import name 'gather_finding'`.

- [ ] **Step 3: Append `gather_finding()`, `_finalize_finding()`, and `_FINDING_REASK` to `analyze.py`**

Add at the end of the file:

```python
# ---------------------------------------------------------------------------
# Tier 1 of the hypothesis-blind redesign (see
# docs/superpowers/specs/2026-08-23-hypothesis-blind-analysts-design.md).
# Mirrors run_one()'s shape but never receives the hypothesis. Not yet called
# from analyze() -- that wiring is the Aggregator cycle, a later plan.
# ---------------------------------------------------------------------------

_FINDING_REASK = (
    "\n\nYour previous reply did not end with the required block. "
    "Reply again, ending with exactly:\n"
    "OBSERVATIONS:\n- <observation> [header_id]\n"
    "CONFIDENCE: <0.0-1.0>\n"
    "RATIONALE: <one or two sentences>\n"
    "CITATIONS: <comma-separated header ids>"
)


def gather_finding(
    model: AnalystModel,
    scope: Scope,
    slice_: DomainSlice,
) -> DomainFinding:
    """One hypothesis-blind domain analyst, invoked synchronously.

    Same empty-slice short-circuit, one-bounded-re-ask, and citation-validation
    discipline as `run_one`, but this call never receives the hypothesis: its
    system/user prompts come from `facts_system_prompt`/`build_facts_user_turn`,
    which have no hypothesis parameter at all.
    """
    domain = slice_.domain

    if not slice_.has_evidence():
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"no {domain} evidence was retrieved",
        )

    system = facts_system_prompt(domain)
    evidence_text, valid_ids, _ = pack_evidence(slice_)
    user = build_facts_user_turn(scope, evidence_text)

    try:
        response = model.invoke(system, user)
    except Exception as exc:
        logger.warning("domain=%s | facts model call failed", domain, exc_info=True)
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"{domain} analyst could not run: {type(exc).__name__}: {exc}",
        )

    prompt_tokens, generation_tokens = response.prompt_tokens, response.generation_tokens
    try:
        finding = parse_finding(response.generation, domain=domain)
        return _finalize_finding(finding, valid_ids, prompt_tokens, generation_tokens)
    except FindingParseError:
        logger.info("domain=%s | first reply had no parseable finding, re-asking once", domain)

    try:
        retry = model.invoke(system, user + _FINDING_REASK)
        prompt_tokens += retry.prompt_tokens
        generation_tokens += retry.generation_tokens
        finding = parse_finding(retry.generation, domain=domain)
        return _finalize_finding(finding, valid_ids, prompt_tokens, generation_tokens)
    except FindingParseError:
        logger.warning("domain=%s | re-ask still produced no parseable finding", domain)
        reasoning, _ = split_reasoning(response.generation)
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"{domain} analyst produced no parseable finding after a re-ask",
            reasoning_trace=reasoning,
            prompt_tokens=prompt_tokens,
            generation_tokens=generation_tokens,
        )
    except Exception as exc:
        logger.warning("domain=%s | re-ask call failed", domain, exc_info=True)
        return DomainFinding(
            domain=domain,
            confidence=0.0,
            rationale=f"{domain} analyst re-ask failed: {type(exc).__name__}: {exc}",
            prompt_tokens=prompt_tokens,
            generation_tokens=generation_tokens,
        )


def _finalize_finding(
    finding: DomainFinding, valid_ids: set[str], prompt_tokens: int, generation_tokens: int
) -> DomainFinding:
    """Drop any citation that does not resolve to a real evidence header id.

    No stance to downgrade here -- that concept doesn't exist at this layer, so
    this is deliberately simpler than `_finalize`. The equivalent grounding gate
    for a decided stance reappears at the Aggregator, in a later cycle.
    """
    kept = [c for c in finding.citations if c in valid_ids]
    dropped = [c for c in finding.citations if c not in valid_ids]
    if dropped:
        logger.warning(
            "domain=%s | dropped %d invented citation(s) from a finding: %s",
            finding.domain,
            len(dropped),
            ", ".join(dropped),
        )
    return finding.model_copy(
        update={
            "citations": kept,
            "prompt_tokens": prompt_tokens,
            "generation_tokens": generation_tokens,
        }
    )
```

Update this module's import block (the `from .prompts import build_user_turn, system_prompt` line and the `from .parse import VerdictParseError, parse_verdict, split_reasoning` line, and the `from contracts import (...)` block) to add the new names:

```python
from contracts import (
    AnalystVerdict,
    BrokerReport,
    DomainFinding,
    HypothesisAssessment,
    InvestigationContext,
    Scope,
    Stance,
)

from .model import AnalystModel
from .packing import pack_evidence
from .parse import FindingParseError, VerdictParseError, parse_finding, parse_verdict, split_reasoning
from .prompts import build_facts_user_turn, build_user_turn, facts_system_prompt, system_prompt
from .routing import DomainSlice, route
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest backend/tests/test_analyst_analyze.py -v`
Expected: all tests PASS, including the pre-existing `TestCombine`, `TestRunOne`, and the `test_full_pipeline_produces_assessment` async test unchanged.

- [ ] **Step 5: Commit**

```bash
git add backend/src/smartops/subagent_analysts/analyze.py backend/tests/test_analyst_analyze.py
git commit -m "subagent_analysts: add gather_finding, the hypothesis-blind orchestration path"
```

---

### Task 5: Full regression pass

**Files:** none (verification only)

**Interfaces:** none

- [ ] **Step 1: Run the entire workspace test suite from the root**

Run: `uv run pytest`

Expected: every test passes — the pre-existing suite (including `test_full_pipeline_produces_assessment`, which exercises today's hypothesis-shown `analyze()` end to end) plus every test added in Tasks 1-4. No test was modified or deleted; this is a pure addition.

- [ ] **Step 2: Confirm nothing outside the planned files changed**

Run: `git status --short`
Expected: only the files listed in "File Structure" above appear as modified, plus the plan/spec docs. If anything else shows up, investigate before committing further.

- [ ] **Step 3: Final commit (if Step 2 turned up anything worth recording separately)**

```bash
git add -A
git commit -m "subagent_analysts: Tier 1 of the hypothesis-blind redesign is additive-only and green"
```
