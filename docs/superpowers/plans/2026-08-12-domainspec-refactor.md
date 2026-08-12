# DomainSpec Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the ten scattered per-family registration sites into one `DomainSpec` object, so adding a security domain becomes three declarative edits instead of ten easily-missed ones.

**Architecture:** A new `backend/src/smartops/domains.py` holds a frozen `DomainSpec` dataclass and a `DOMAINS` registry keyed by `ToolFamily`. It imports only `contracts` and the VirusTotal native tools, so nothing can create an import cycle with it. `broker.py` grows a `make_investigate_tool()` factory that generates the four `@tool` wrappers from the registry; `registry.py`, `subagents/__init__.py` and `main.py` then read their per-family data from `DOMAINS` instead of holding parallel dicts. The old names survive as *derived* aliases until the final task, so every commit is green and bisectable.

**Tech Stack:** Python 3.13, uv workspace, pydantic 2.9+, `strands-agents==1.50.2` (pinned exactly), pytest with `asyncio_mode = "auto"`.

## Global Constraints

- **This is a pure refactor. No behaviour changes.** Through Tasks 1–5 the existing 209 tests must pass **completely unmodified**. Task 6 is the only task permitted to touch an existing test file, and only to change *import statements and symbol references* — **no assertion may change**. If an assertion needs editing to go green, the refactor is wrong: revert and rethink.
- **Every commit must leave `uv run pytest -q` green.** No "red in between" — a red commit destroys bisectability, which is the main reason to commit often.
- **Tool descriptions must be copied verbatim** from the current docstrings. They are model-facing text; the Broker's choice of which tool to call *is* the classification decision, so changing a word is a behaviour change nobody sees.
- `strands-agents` is pinned to `==1.50.2`. Treat the installed source at `.venv/Lib/site-packages/strands/` as the spec and the tests as the contract. Do not upgrade it.
- Run all commands from the repo root, `D:\projects\Smartops SOC App`.
- Do **not** add `assessment_model`, `findings_model`, or `index_allowlist` to `DomainSpec`. Those belong to Plan B and would be dead fields here — a dead field is worse than a missing one, because it reads as supported.
- Branch is `task-broker-agent`. Commit after every task. Do not push.

## Verified SDK facts

Established against the installed 1.50.2 source; do not re-derive:

- `@tool(description=..., name=..., context: bool | str = False)` — `decorator.py:728-741`. `context=True` requires the parameter to be named exactly `tool_context`.
- An explicit `description=` overrides the docstring, but **parameter** descriptions still come from the docstring's `Args:` section (`decorator.py:112`), so a generated tool still needs one.
- `tool_spec` shape is `{"name": ..., "description": ..., "inputSchema": {"json": <schema>}}` (`decorator.py:310`). Existing tests already index it as `tool_spec["inputSchema"]["json"]["properties"]`.
- A `DecoratedFunctionTool` is **directly awaitable-callable** with keyword arguments — `await investigate_siem(question=..., tool_context=...)`. There is no `original_function` attribute.
- `tool.tool_name` is the public accessor for the registered name (`decorator.py:534`).

---

## File Structure

| File | Responsibility |
|---|---|
| `backend/src/smartops/domains.py` *(create)* | The `DomainSpec` dataclass and the `DOMAINS` registry. Pure data. Imports only `contracts`, stdlib, and `smartops.tools.native.virustotal`. |
| `backend/tests/test_domains.py` *(create)* | Parity tests asserting each spec carries exactly what today's scattered constants carry, plus the generated-tool tests. |
| `backend/src/smartops/broker.py` *(modify)* | Gains `make_investigate_tool()`, `TOOL_BY_FAMILY`, generated `FAMILY_TOOLS`. Loses `FAMILY_REQUIRED_KINDS` and the four hand-written wrappers (Task 6). |
| `backend/src/smartops/tools/registry.py` *(modify)* | Loses `MCP_SERVERS_BY_FAMILY`, `NATIVE_TOOLS_BY_FAMILY`, `ENRICHERS_BY_FAMILY`; reads `DOMAINS`. |
| `backend/src/smartops/subagents/__init__.py` *(modify)* | Loses `_TIME_SCOPED_FAMILIES`; reads `spec.time_scoped`. |
| `backend/src/smartops/main.py` *(modify)* | Loses `_TOOL_BY_FAMILY` and `_ALL_FAMILIES`; reads `DOMAINS` and `broker.TOOL_BY_FAMILY`. |
| `backend/tests/test_broker.py` *(modify, Task 6 only)* | Import sites and symbol references updated. Assertions untouched. |

**Why `make_investigate_tool()` lives in `broker.py`, not `domains.py`** (a deliberate deviation from the spec sketch): the generated tool body must call `broker._dispatch`. Putting the factory in `domains.py` would make `domains` import `broker` while `broker` imports `domains` — a circular import. Keeping `domains.py` as pure data with no Strands import avoids the cycle entirely.

---

### Task 1: The `DomainSpec` dataclass and `DOMAINS` registry

**Files:**
- Create: `backend/src/smartops/domains.py`
- Test: `backend/tests/test_domains.py`

**Interfaces:**
- Consumes: `contracts.EntityKind`, `contracts.ToolFamily`, `virustotal.TOOLS`, `virustotal.enrich_scope`
- Produces:
  - `DomainSpec` — frozen dataclass: `family: ToolFamily`, `description: str`, `required_kinds: frozenset[EntityKind] | None`, `time_scoped: bool`, `mcp_servers: tuple[str, ...]`, `native_tools: tuple[Callable, ...]`, `enricher: Callable[..., Any] | None`, `turns: int`, `max_output_tokens: int`
  - `DOMAINS: dict[ToolFamily, DomainSpec]`
  - `ALL_FAMILIES: tuple[ToolFamily, ...]`
  - `spec_for(family: ToolFamily) -> DomainSpec`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_domains.py`:

```python
"""The domain registry is the single place a security domain is declared.

These are parity tests: every assertion mirrors a constant that used to live
somewhere else in the package. They exist so the refactor that deletes those
constants cannot silently drop one.
"""

import dataclasses
from typing import get_args

import pytest
from contracts import ToolFamily
from smartops.domains import ALL_FAMILIES, DOMAINS, DomainSpec, spec_for
from smartops.tools.native import virustotal


class TestRegistryCoverage:
    def test_every_tool_family_has_exactly_one_spec(self):
        assert set(DOMAINS) == set(get_args(ToolFamily))

    def test_each_spec_is_keyed_by_its_own_family(self):
        for family, spec in DOMAINS.items():
            assert spec.family == family

    def test_spec_for_returns_the_registered_spec(self):
        assert spec_for("siem") is DOMAINS["siem"]

    def test_all_families_matches_the_registry(self):
        assert set(ALL_FAMILIES) == set(DOMAINS)


class TestEntityGateParity:
    """Mirrors the old broker.FAMILY_REQUIRED_KINDS."""

    def test_siem_requires_nothing_because_a_siem_indexes_everything(self):
        assert DOMAINS["siem"].required_kinds is None

    def test_edr_requires_a_host_process_or_user(self):
        assert DOMAINS["edr"].required_kinds == frozenset({"host", "process", "user"})

    def test_ndr_requires_an_ip_domain_or_url(self):
        assert DOMAINS["ndr"].required_kinds == frozenset({"ip", "domain", "url"})

    def test_vt_requires_a_hash_ip_domain_or_url(self):
        assert DOMAINS["vt"].required_kinds == frozenset({"file_hash", "ip", "domain", "url"})


class TestTimeScopingParity:
    """Mirrors the old subagents._TIME_SCOPED_FAMILIES."""

    def test_log_indexed_domains_are_time_scoped(self):
        assert DOMAINS["siem"].time_scoped
        assert DOMAINS["edr"].time_scoped
        assert DOMAINS["ndr"].time_scoped

    def test_reputation_lookup_has_no_time_dimension(self):
        assert not DOMAINS["vt"].time_scoped


class TestToolWiringParity:
    """Mirrors the old registry.MCP_SERVERS_BY_FAMILY / NATIVE_TOOLS_BY_FAMILY."""

    def test_siem_is_served_by_the_splunk_mcp_server(self):
        assert DOMAINS["siem"].mcp_servers == ("splunk",)

    def test_vt_is_a_rest_api_reached_by_native_tools_not_mcp(self):
        assert DOMAINS["vt"].mcp_servers == ()
        assert list(DOMAINS["vt"].native_tools) == list(virustotal.TOOLS)

    def test_only_vt_has_native_tools(self):
        for family in ("siem", "edr", "ndr"):
            assert DOMAINS[family].native_tools == ()

    def test_no_mcp_server_serves_two_families(self):
        seen: set[str] = set()
        for spec in DOMAINS.values():
            for name in spec.mcp_servers:
                assert name not in seen, f"{name} is mapped to two families"
                seen.add(name)


class TestEnricherParity:
    """Mirrors the old registry.ENRICHERS_BY_FAMILY."""

    def test_vt_has_a_model_free_enricher(self):
        assert DOMAINS["vt"].enricher is virustotal.enrich_scope

    def test_domains_needing_a_decision_have_no_enricher(self):
        for family in ("siem", "edr", "ndr"):
            assert DOMAINS[family].enricher is None


class TestDescriptions:
    def test_every_domain_describes_itself_for_the_model(self):
        for spec in DOMAINS.values():
            assert spec.description.strip()

    def test_a_description_says_what_the_domain_is_not_for(self):
        # Each carries a "Do NOT use" clause; that negative guidance is what
        # stops the Broker calling the wrong specialist.
        for spec in DOMAINS.values():
            assert "Do NOT use" in spec.description


class TestImmutability:
    def test_a_spec_cannot_be_mutated_after_construction(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            DOMAINS["siem"].time_scoped = False  # type: ignore[misc]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest backend/tests/test_domains.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'smartops.domains'`

- [ ] **Step 3: Write the implementation**

Create `backend/src/smartops/domains.py`:

```python
"""The registry of security domains, and everything that makes one distinct.

One `DomainSpec` per `ToolFamily`, holding what used to be scattered across ten
sites in five files: the entity gate, whether the domain is time-scoped, which
MCP servers serve it, its native tools, its model-free enricher, and the
description the Broker's model reads when deciding whether to engage it.

Adding a domain is now three declarative edits: a `DomainSpec` here, a member on
`contracts.ToolFamily`, and an entry in `mcp_servers.json`.

**Deliberately pure data.** This module imports `contracts` and the VirusTotal
native tools and nothing else -- no Strands, no `broker`, no `registry`. The tool
wrappers are generated in `smartops.broker`, because their body calls
`broker._dispatch()` and generating them here would make `domains` and `broker`
import each other.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from contracts import EntityKind, ToolFamily

from smartops.tools.native import virustotal


@dataclass(frozen=True)
class DomainSpec:
    """Everything that distinguishes one security domain from another.

    Frozen because a spec is configuration read at import time by four separate
    modules. A mutable one would let any consumer silently change the entity
    gate or the toolset for every other consumer.
    """

    family: ToolFamily

    description: str
    """What the Broker's model reads when deciding whether to engage this domain.

    Model-facing and load-bearing: calling a specialist's tool IS the decision
    that its domain is relevant, so this text is the entire basis for routing.
    Each states what the domain is for, what observable it needs, and -- crucially
    -- what it is NOT for.
    """

    required_kinds: frozenset[EntityKind] | None
    """Which observable kinds this domain can be queried with. `None` means any.

    A *precondition*, not a judgement: VirusTotal cannot be queried without a
    hash, IP, domain, or URL regardless of what any model decides. A SIEM indexes
    logs about everything, so no observable makes it unusable.
    """

    time_scoped: bool
    """Whether this domain's data is indexed over time.

    Reputation lookups are not: "is this indicator known-bad" has no time
    dimension, so handing a `vt` subagent a 2018 window is an instruction it
    cannot follow and would have to invent a way to obey.
    """

    mcp_servers: tuple[str, ...] = ()
    """Names of MCP servers in `mcp_servers.json` that serve this domain.

    One server must not serve two families -- clients are built per family, so a
    name listed twice opens two connections to the same server.
    """

    native_tools: tuple[Callable, ...] = ()
    """Model-callable `@tool` functions for domains reached directly rather than
    through an MCP server."""

    enricher: Callable[..., Any] | None = None
    """A model-free lookup, for domains whose work is a *lookup* rather than an
    investigation: the entity's kind selects the query and its value is the
    argument, so there is no judgement to delegate. `None` for any domain that
    needs a decision about what to ask."""

    turns: int = 14
    max_output_tokens: int = 12_000


SIEM = DomainSpec(
    family="siem",
    description=(
        "Search SIEM logs for historical evidence across the whole estate:\n"
        "authentication events, process and network log records, index metadata.\n"
        "\n"
        "Use for anything needing log history or correlation over time, and as the\n"
        "starting point when you do not yet know which host or address matters.\n"
        "Works with any observable. Do NOT use for file or domain reputation (use\n"
        "investigate_vt) or for live host process detail (use investigate_edr)."
    ),
    required_kinds=None,
    time_scoped=True,
    mcp_servers=("splunk",),
)

EDR = DomainSpec(
    family="edr",
    description=(
        "Query endpoint detection and response for host-level detail: running and\n"
        "historical processes, persistence mechanisms, file activity, local accounts.\n"
        "\n"
        "Use when the question is about what happened *on a machine*. Needs a host,\n"
        "process, or user observable in scope. Do NOT use for network flow analysis\n"
        "(use investigate_ndr) or reputation lookups (use investigate_vt)."
    ),
    required_kinds=frozenset({"host", "process", "user"}),
    time_scoped=True,
    mcp_servers=("edr",),
)

VT = DomainSpec(
    family="vt",
    description=(
        "Look up third-party reputation and threat intelligence for an indicator:\n"
        "whether a file hash, IP, domain, or URL is known-malicious externally.\n"
        "\n"
        "Use to establish whether an indicator is known-bad. Needs a file_hash, ip,\n"
        "domain, or url observable in scope. Do NOT use to find out what happened in\n"
        "our own environment -- it knows nothing about our estate."
    ),
    required_kinds=frozenset({"file_hash", "ip", "domain", "url"}),
    time_scoped=False,
    mcp_servers=(),
    native_tools=tuple(virustotal.TOOLS),
    enricher=virustotal.enrich_scope,
)

NDR = DomainSpec(
    family="ndr",
    description=(
        "Analyse network detection and response telemetry: connections, flows,\n"
        "protocol anomalies, and traffic to or from an address.\n"
        "\n"
        "Use when the question is about traffic and communication patterns. Needs an\n"
        "ip, domain, or url observable in scope. Do NOT use for host-local process\n"
        "detail (use investigate_edr)."
    ),
    required_kinds=frozenset({"ip", "domain", "url"}),
    time_scoped=True,
    mcp_servers=("ndr",),
)

# Order matters: it is the order the Broker sees the tools in, and the default
# order of `--families`. Kept as siem, edr, vt, ndr to match what shipped.
DOMAINS: dict[ToolFamily, DomainSpec] = {s.family: s for s in (SIEM, EDR, VT, NDR)}

ALL_FAMILIES: tuple[ToolFamily, ...] = tuple(DOMAINS)


def spec_for(family: ToolFamily) -> DomainSpec:
    """The spec for `family`. Raises `KeyError` for an unregistered family --
    which is a programming error, not a runtime condition."""
    return DOMAINS[family]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest backend/tests/test_domains.py -v`
Expected: PASS.

- [ ] **Step 5: Verify the whole suite is still green**

Run: `uv run pytest -q`
Expected: 209 existing tests plus the new ones, all passing. Nothing reads the registry yet.

- [ ] **Step 6: Commit**

```bash
git add backend/src/smartops/domains.py backend/tests/test_domains.py
git commit -m "domains: one spec per security domain, replacing ten scattered sites

Adding a domain currently means editing ten places across five files, and
nothing fails loudly if one is missed -- a forgotten _TIME_SCOPED_FAMILIES
entry just silently gives the domain the wrong prompt.

This is the registry. Nothing reads it yet; the consumers are wired up one
at a time in the commits that follow, so each can be checked against the
existing suite on its own.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Generate the `investigate_*` tools, keeping the old names as derived aliases

**Files:**
- Modify: `backend/src/smartops/broker.py:101-106`, `:491-552`
- Test: `backend/tests/test_domains.py` (append)

**Interfaces:**
- Consumes: `smartops.domains.DOMAINS`, `smartops.domains.DomainSpec`, `broker._dispatch`
- Produces:
  - `broker.make_investigate_tool(spec: DomainSpec) -> DecoratedFunctionTool`
  - `broker.TOOL_BY_FAMILY: dict[ToolFamily, DecoratedFunctionTool]`
  - `broker.FAMILY_TOOLS: list[DecoratedFunctionTool]` — same name and type as today
  - `broker.FAMILY_REQUIRED_KINDS` and `broker.investigate_{siem,edr,vt,ndr}` survive as **derived** aliases so the existing suite stays green. Task 6 deletes them.

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_domains.py`:

```python
class TestGeneratedTools:
    """The four investigate_* wrappers are generated from DOMAINS.

    They used to be hand-written and identical apart from one string, which is
    exactly the kind of duplication that drifts -- and since the description
    drives routing, drift there is a silent behaviour change.
    """

    def test_one_tool_is_generated_per_domain(self):
        from smartops.broker import FAMILY_TOOLS

        assert len(FAMILY_TOOLS) == len(DOMAINS)

    def test_each_tool_is_named_for_its_family(self):
        from smartops.broker import TOOL_BY_FAMILY

        for family, tool in TOOL_BY_FAMILY.items():
            assert tool.tool_name == f"investigate_{family}"

    def test_the_model_facing_description_comes_from_the_spec(self):
        from smartops.broker import TOOL_BY_FAMILY

        for family, tool in TOOL_BY_FAMILY.items():
            described = tool.tool_spec["description"]
            assert "Do NOT use" in described
            assert described.splitlines()[0] in DOMAINS[family].description

    def test_question_is_the_models_only_parameter(self):
        from smartops.broker import TOOL_BY_FAMILY

        for tool in TOOL_BY_FAMILY.values():
            # tool_context is injected by the framework, never by the model.
            properties = tool.tool_spec["inputSchema"]["json"]["properties"]
            assert set(properties) == {"question"}

    def test_the_question_parameter_is_described_for_the_model(self):
        from smartops.broker import TOOL_BY_FAMILY

        for tool in TOOL_BY_FAMILY.values():
            question = tool.tool_spec["inputSchema"]["json"]["properties"]["question"]
            assert question["description"].strip()

    async def test_a_generated_tool_dispatches_its_own_family(self, monkeypatch):
        """Each closure carries its own family. Closing over a loop variable
        would make every generated tool dispatch the last one."""
        import smartops.broker as broker

        seen: list[str] = []

        async def fake_dispatch(family, question, ctx):
            seen.append(family)
            return "ok"

        monkeypatch.setattr(broker, "_dispatch", fake_dispatch)

        for tool in broker.TOOL_BY_FAMILY.values():
            await tool(question="q", tool_context=object())

        assert seen == list(broker.TOOL_BY_FAMILY)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest backend/tests/test_domains.py::TestGeneratedTools -v`
Expected: FAIL — `ImportError: cannot import name 'TOOL_BY_FAMILY' from 'smartops.broker'`

- [ ] **Step 3: Derive `FAMILY_REQUIRED_KINDS` from the registry**

In `backend/src/smartops/broker.py`, add to the imports:

```python
from smartops.domains import DOMAINS, DomainSpec
```

Replace the `FAMILY_REQUIRED_KINDS` block at lines 96–106 (comment included) with:

```python
# Kept as a derived view during the DomainSpec migration so existing callers and
# tests keep working. It cannot drift from the registry because it is computed
# from it. Deleted once every consumer reads `DOMAINS` directly.
FAMILY_REQUIRED_KINDS: dict[ToolFamily, frozenset[EntityKind] | None] = {
    family: spec.required_kinds for family, spec in DOMAINS.items()
}
```

- [ ] **Step 4: Replace the four wrappers with a factory**

Delete `investigate_siem`, `investigate_edr`, `investigate_vt`, `investigate_ndr` and the `FAMILY_TOOLS` list (lines 491–552), and put this in their place:

```python
def make_investigate_tool(spec: DomainSpec):
    """Build the `@tool` wrapper the Broker calls to engage one domain.

    The four wrappers were hand-written and identical apart from a single
    string. That string is model-facing text driving the routing decision, so
    duplicated copies drifting apart is a behaviour change nobody sees.

    `description=` overrides the docstring, but the *parameter* description
    still comes from the docstring's `Args:` section, which is why the inner
    function keeps one. `context=True` requires the parameter to be named
    exactly `tool_context` (`strands/tools/decorator.py:767`).

    `spec` is a function parameter rather than a loop variable on purpose: each
    call gets its own closure, so the four tools dispatch four different
    families. Closing over a loop variable would make all of them dispatch the
    last one.
    """

    @tool(name=f"investigate_{spec.family}", description=spec.description, context=True)
    async def investigate(question: str, tool_context: ToolContext) -> str:
        """Engage this domain specialist.

        Args:
            question: What this domain should find out, in plain language.
        """
        return await _dispatch(spec.family, question, tool_context)

    return investigate


TOOL_BY_FAMILY = {spec.family: make_investigate_tool(spec) for spec in DOMAINS.values()}

# A list, because that is what `Agent(tools=...)` takes.
FAMILY_TOOLS = list(TOOL_BY_FAMILY.values())

# Module-level aliases, so existing importers keep working during the migration.
# Deleted in the final task of this refactor.
investigate_siem = TOOL_BY_FAMILY["siem"]
investigate_edr = TOOL_BY_FAMILY["edr"]
investigate_vt = TOOL_BY_FAMILY["vt"]
investigate_ndr = TOOL_BY_FAMILY["ndr"]
```

- [ ] **Step 5: Run the full suite — it must be green**

Run: `uv run pytest -q`
Expected: **all** tests pass, including the 209 existing ones unmodified. The aliases are what make that true. If `test_broker.py` fails here, the aliases are wrong — fix them rather than editing the test.

- [ ] **Step 6: Commit**

```bash
git add backend/src/smartops/broker.py backend/tests/test_domains.py
git commit -m "broker: generate the family tools from the domain registry

Four wrappers identical apart from one string become one factory. The
description drives the Broker's routing decision, so duplicated copies
drifting apart is a silent behaviour change -- now there is one copy, on
the spec.

FAMILY_REQUIRED_KINDS and the investigate_* names survive as derived
aliases so the existing suite passes unmodified; they are deleted once
every consumer reads DOMAINS directly.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Point the tool registry at `DOMAINS`

**Files:**
- Modify: `backend/src/smartops/tools/registry.py:72-107`, `:184`, `:230-245`, `:364-370`, `:413`
- Test: `backend/tests/test_registry.py` (must pass unmodified)

**Interfaces:**
- Consumes: `smartops.domains.DOMAINS`
- Produces: `enricher_for()`, `server_count()`, `tools_for()` — signatures unchanged. `MCP_SERVERS_BY_FAMILY`, `NATIVE_TOOLS_BY_FAMILY`, `ENRICHERS_BY_FAMILY` are **deleted**.

- [ ] **Step 1: Confirm the safety net passes first**

Run: `uv run pytest backend/tests/test_registry.py -q`
Expected: PASS. These tests are what prove this task changed nothing.

- [ ] **Step 1b: Break the import cycle at its actual source**

`backend/src/smartops/tools/__init__.py` eagerly re-exports `tools_for`, so
`registry → domains → smartops.tools.native.virustotal` re-enters
`smartops.tools.__init__` → `registry` while that module is still initialising.
Nothing in the repo imports `from smartops.tools import ...` (verified with
`grep -rn "from smartops.tools import" backend/ contracts/`), so the re-export is
dead weight. Replace the file's contents with a docstring only:

```python
"""Tool resolution. Import from `smartops.tools.registry` directly.

Deliberately re-exports nothing: an eager `from .registry import tools_for` here
made `registry -> domains -> tools.native.virustotal` re-enter this module while
`registry` was still initialising, which is a circular import.
"""
```

With the cycle gone, `registry.py` can import `DOMAINS` normally at module level.
Do **not** use a lazy or function-local import to paper over the cycle.

- [ ] **Step 2: Replace the three parallel dicts with derived views**

`test_registry.py:7,8,47,49,65,70,153,348` imports and monkeypatches these dicts,
and `test_broker.py:408,430,466` monkeypatches `ENRICHERS_BY_FAMILY`. They
therefore cannot be deleted while tests must stay unmodified. Keep them as
**eagerly-derived module-level views**, exactly as Task 2 did for
`FAMILY_REQUIRED_KINDS`, and let Task 6 delete them with the other aliases.

In `backend/src/smartops/tools/registry.py`, replace `MCP_SERVERS_BY_FAMILY`
(lines 72–84), `NATIVE_TOOLS_BY_FAMILY` (86–93) and `ENRICHERS_BY_FAMILY`
(95–107), comment blocks included, with:

```python
# Derived views over the domain registry, kept during the DomainSpec migration
# because the tests monkeypatch them. They cannot drift from `DOMAINS` because
# they are computed from it. Deleted in the final task of this refactor.
MCP_SERVERS_BY_FAMILY: dict[ToolFamily, tuple[str, ...]] = {
    family: spec.mcp_servers for family, spec in DOMAINS.items()
}
NATIVE_TOOLS_BY_FAMILY: dict[ToolFamily, list[Callable]] = {
    family: list(spec.native_tools) for family, spec in DOMAINS.items()
}
ENRICHERS_BY_FAMILY: dict[ToolFamily, Callable[..., Any] | None] = {
    family: spec.enricher for family, spec in DOMAINS.items()
}
```

Built once at import. No lazy initialisation, no `global`, no
`_ensure_dicts_initialized()` — a mutable module global re-initialised on a
"looks empty" check breaks the moment a dict is legitimately empty, and defeats
the monkeypatching the tests rely on.

Readers keep using these dicts so monkeypatching still works; the single source
of truth is `DOMAINS`, which they are derived from. Replace the import:

```python
from smartops.tools.native import virustotal
```

with:

```python
from smartops.domains import DOMAINS
```

- [ ] **Step 3: Update the four readers**

In `load_mcp_servers()`, around line 184:

```python
    for family, spec in DOMAINS.items():
        subset = {name: servers[name] for name in spec.mcp_servers if name in servers}
```

In `_assert_no_shared_servers()`, around line 237:

```python
    seen: dict[str, ToolFamily] = {}
    for family, spec in DOMAINS.items():
        for name in spec.mcp_servers:
            if name in seen:
                raise ValueError(
                    f"MCP server {name!r} is mapped to both {seen[name]!r} and {family!r}; "
                    "one server per family, or it opens a connection per family"
                )
            seen[name] = family
```

In `enricher_for()`, around line 364:

```python
def enricher_for(family: ToolFamily) -> Callable[..., Any] | None:
    """The model-free lookup for `family`, if it has one.

    Returns None for every family whose work needs a decision about what to ask
    -- those wait for a real subagent.
    """
    return DOMAINS[family].enricher
```

In `tools_for()`, around line 413:

```python
    tools: list = list(DOMAINS[family].native_tools)
```

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -q`
Expected: all green, `test_registry.py` **unmodified**. If it needs editing, stop — behaviour changed.

- [ ] **Step 5: Commit**

```bash
git add backend/src/smartops/tools/registry.py
git commit -m "registry: read the family mapping from the domain registry

Three parallel dicts keyed by ToolFamily become three fields on one spec.
Same behaviour, same public functions, and test_registry.py passes
unmodified -- which is the point.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Point the subagent runner at `DOMAINS`

**Files:**
- Modify: `backend/src/smartops/subagents/__init__.py:41`, `:76-78`, `:195-209`, `:224`, `:404`, `:449`
- Test: `backend/tests/test_subagents.py` (must pass unmodified)

**Interfaces:**
- Consumes: `smartops.domains.DOMAINS`
- Produces: `_system_prompt_for(family: str, *, turns: int, time_scoped: bool) -> str` — gains the `time_scoped` keyword. `domain_runner()` and `investigate()` unchanged.

- [ ] **Step 1: Replace the import**

In `backend/src/smartops/subagents/__init__.py`, change:

```python
from smartops.broker import FAMILY_REQUIRED_KINDS, SubagentRunner, enrich_mission
```

to:

```python
from smartops.broker import SubagentRunner, enrich_mission
from smartops.domains import DOMAINS
```

- [ ] **Step 2: Delete `_TIME_SCOPED_FAMILIES` and thread the flag through**

Delete the `_TIME_SCOPED_FAMILIES` block at lines 76–78.

Rewrite `_system_prompt_for()` (line 195) to take the flag rather than look it up:

```python
def _system_prompt_for(family: str, *, turns: int, time_scoped: bool) -> str:
    """The system prompt for one family.

    One prompt with a conditional clause rather than a prompt per family: the
    instructions are the same job, and a registry of near-identical prompts drifts
    apart. Only the time-window rule genuinely does not apply to every domain.
    """
    return _SYSTEM_PROMPT.format(
        family=family,
        turns=turns,
        last_query_turn=max(1, turns - 1),
        time_guidance=_TIME_GUIDANCE if time_scoped else _LOOKUP_GUIDANCE,
    )
```

In `_prompt_for()` at line 224, replace the membership test:

```python
    if DOMAINS[mission.tool_family].time_scoped:
```

In `_build_agent_and_invoke()` at line 404:

```python
        system_prompt=_system_prompt_for(
            mission.tool_family,
            turns=turns,
            time_scoped=DOMAINS[mission.tool_family].time_scoped,
        ),
```

In `domain_runner()`'s inner `run()` at line 449:

```python
        required = DOMAINS[family].required_kinds
```

- [ ] **Step 3: Run the full suite**

Run: `uv run pytest -q`
Expected: all green, `test_subagents.py` unmodified. `TestPrompt` is the real check — it asserts time-scoped domains get epoch windows and `vt` does not.

- [ ] **Step 4: Commit**

```bash
git add backend/src/smartops/subagents/__init__.py
git commit -m "subagents: take time-scoping from the domain spec

_TIME_SCOPED_FAMILIES was a frozenset a hundred lines from the entity gate
it has to agree with, and forgetting a domain there silently gives it the
wrong prompt rather than failing. It is now a field on the spec, and
_system_prompt_for takes the flag rather than looking it up -- so the
prompt builder no longer needs the registry at all.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Point the CLI at `DOMAINS`

**Files:**
- Modify: `backend/src/smartops/main.py:29-52`, `:91`, and the three `_ALL_FAMILIES` uses
- Test: `backend/tests/test_main.py` (must pass unmodified)

**Interfaces:**
- Consumes: `smartops.domains.ALL_FAMILIES`, `smartops.broker.TOOL_BY_FAMILY`
- Produces: nothing new. `_TOOL_BY_FAMILY` and `_ALL_FAMILIES` are deleted.

- [ ] **Step 1: Replace the imports and the two maps**

In `backend/src/smartops/main.py`, replace the broker import block (lines 32–39) with:

```python
from smartops.broker import TOOL_BY_FAMILY, BrokerRequest, broker_task
```

Add:

```python
from smartops.domains import ALL_FAMILIES
```

Delete `_TOOL_BY_FAMILY` (lines 45–50) and `_ALL_FAMILIES` (line 52).

- [ ] **Step 2: Update the four references**

Replace every `_ALL_FAMILIES` with `ALL_FAMILIES` — there are three: the `_parse_families` unknown-family guard, the `--families` default, and its help string. Then in `_scripted_invoker()` at line 91:

```python
            await TOOL_BY_FAMILY[family](question=request.task.goal, tool_context=context)
```

- [ ] **Step 3: Run the full suite**

Run: `uv run pytest -q`
Expected: all green, `test_main.py` unmodified.

- [ ] **Step 4: Prove the CLI still runs end to end with no credentials**

```bash
uv run smartops-broker --goal "reputation of coinhive.com" \
  --entity domain:coinhive.com --families vt --scripted
```

Expected: exit 0. With no `VT_API_KEY`, `vt` is REJECTED with "lookup unavailable"; with one set it makes a real VirusTotal request. Either is a pass — what is being checked is that dispatch, the entity gate, tool resolution and printing all still work.

- [ ] **Step 5: Commit**

```bash
git add backend/src/smartops/main.py
git commit -m "main: take the family list and tool map from the registry

The CLI kept its own copy of both, which is two more places to forget when
a domain is added.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Delete the migration aliases

This is the **only** task permitted to modify an existing test file, and only its import statements and symbol references. No assertion changes.

**Files:**
- Modify: `backend/src/smartops/broker.py` (delete `FAMILY_REQUIRED_KINDS` and the four aliases)
- Modify: `backend/src/smartops/tools/registry.py` (delete the three derived dicts from Task 3)
- Modify: `backend/tests/test_broker.py:19`, `:27-29`, `:79`, `:207-208`, `:408`, `:430`, `:466`, `:718`, `:735`, `:846`, `:852`, `:964`
- Modify: `backend/tests/test_registry.py:7-8`, `:47`, `:49`, `:65`, `:70`, `:153`, `:348`

**Interfaces:**
- Consumes: `smartops.broker.TOOL_BY_FAMILY`, `smartops.domains.DOMAINS`
- Produces: `broker.FAMILY_REQUIRED_KINDS`, `broker.investigate_*`, `registry.MCP_SERVERS_BY_FAMILY`, `registry.NATIVE_TOOLS_BY_FAMILY` and `registry.ENRICHERS_BY_FAMILY` no longer exist.

- [ ] **Step 1: Delete the aliases from `broker.py` and `registry.py`**

In `broker.py`, delete the `FAMILY_REQUIRED_KINDS` derived dict and the four `investigate_* = TOOL_BY_FAMILY[...]` lines added in Task 2. Then update `_stub_subagent()` (around line 318), which was the last reader:

```python
    family = mission.tool_family
    required = DOMAINS[family].required_kinds
    in_scope = mission.scope.kinds()
```

In `registry.py`, delete the three derived dicts added in Task 3 and point their readers straight at `DOMAINS`:

```python
    for family, spec in DOMAINS.items():                      # load_mcp_servers
        subset = {name: servers[name] for name in spec.mcp_servers if name in servers}

    for family, spec in DOMAINS.items():                      # _assert_no_shared_servers
        for name in spec.mcp_servers:
            ...

    return DOMAINS[family].enricher                           # enricher_for

    tools: list = list(DOMAINS[family].native_tools)          # tools_for
```

Tests monkeypatch `registry.MCP_SERVERS_BY_FAMILY`, `registry.NATIVE_TOOLS_BY_FAMILY` and `registry.ENRICHERS_BY_FAMILY` to control the family mapping. With the dicts gone they must monkeypatch `smartops.domains.DOMAINS` instead — replacing a spec with `dataclasses.replace(spec, mcp_servers=...)`, since `DomainSpec` is frozen. Adjusting a monkeypatch target is a reference change, not an assertion change.

- [ ] **Step 2: Run the suite to see exactly what breaks**

Run: `uv run pytest -q`
Expected: FAIL, only in `test_broker.py`, only on import and name resolution. Note every failure — that list is the work for Step 3, and nothing outside `test_broker.py` should appear.

- [ ] **Step 3: Update `test_broker.py`'s references — mechanically**

Change the import block (lines 19, 27–29): drop `FAMILY_REQUIRED_KINDS`, `investigate_edr`, `investigate_siem`, `investigate_vt`; add `TOOL_BY_FAMILY`. Add `from smartops.domains import DOMAINS`.

Line 79:

```python
_TOOL_BY_FAMILY = {family: TOOL_BY_FAMILY[family] for family in ("siem", "edr", "vt")}
```

Lines 207–208 — same assertions, different subject:

```python
        assert "question" in TOOL_BY_FAMILY["siem"].tool_spec["inputSchema"]["json"]["properties"]
        assert set(TOOL_BY_FAMILY["siem"].tool_spec["inputSchema"]["json"]["properties"]) == {"question"}
```

Lines 718, 735 — `await investigate_siem(` becomes `await TOOL_BY_FAMILY["siem"](`.
Lines 846, 852 — `await investigate_vt(` becomes `await TOOL_BY_FAMILY["vt"](`.

Line 964:

```python
        families = len(DOMAINS)
```

Lines 654–657 are string literals naming the tools; leave them exactly as they are — they assert the generated tool names, which is now a stronger test than before.

- [ ] **Step 4: Verify the test diff is mechanical**

Run: `git diff backend/tests/test_broker.py`
Expected: only import lines and symbol references. **No assertion text changed, no test added, none removed.** If the diff shows anything else, revert it.

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -q`
Expected: all green — 209 original tests (with mechanically-updated references) plus the new domain tests.

- [ ] **Step 6: Confirm the old names are gone**

Run: `git grep -n "FAMILY_REQUIRED_KINDS\|MCP_SERVERS_BY_FAMILY\|NATIVE_TOOLS_BY_FAMILY\|ENRICHERS_BY_FAMILY\|_TIME_SCOPED_FAMILIES\|_ALL_FAMILIES" -- backend/ contracts/`
Expected: no matches outside `docs/`.

- [ ] **Step 7: Lint**

Run: `uv run ruff check backend/`
Expected: clean. Watch for imports orphaned by the deletions — `virustotal` in `registry.py`, `get_args` in `main.py`, `EntityKind` in `broker.py`.

- [ ] **Step 8: Commit**

```bash
git add backend/src/smartops/broker.py backend/tests/test_broker.py
git commit -m "broker: drop the migration aliases now every consumer reads DOMAINS

test_broker.py's references move with the symbols; no assertion changed,
which is what keeps this a refactor.

Adding a security domain is now three declarative edits -- a DomainSpec, a
ToolFamily member, an mcp_servers.json entry -- where it was ten sites
across five files, none of which failed loudly when missed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Make the one-entry claim executable

**Files:**
- Test: `backend/tests/test_domains.py` (append)

**Interfaces:**
- Consumes: `smartops.domains.DomainSpec`, `smartops.broker.make_investigate_tool`, `smartops.subagents._system_prompt_for`
- Produces: nothing. This exists so the plan's central claim is a test rather than a sentence.

- [ ] **Step 1: Write the test**

Append to `backend/tests/test_domains.py`:

```python
class TestAddingADomainIsOneEntry:
    """The claim this refactor is for, made executable.

    A new domain should need a DomainSpec and nothing else in code. This builds
    one that is not in DOMAINS and drives it through the machinery that used to
    require nine other edits.
    """

    def _spec(self):
        return DomainSpec(
            family="edr",  # a real ToolFamily member; the values below are not EDR's
            description=(
                "Fictional domain used only by this test.\n"
                "\n"
                "Do NOT use it for anything real."
            ),
            required_kinds=frozenset({"user"}),
            time_scoped=False,
            mcp_servers=("fictional",),
        )

    def test_a_new_spec_produces_a_working_tool_with_no_other_code_change(self):
        from smartops.broker import make_investigate_tool

        tool = make_investigate_tool(self._spec())

        assert tool.tool_name == "investigate_edr"
        assert "Fictional domain" in tool.tool_spec["description"]
        assert set(tool.tool_spec["inputSchema"]["json"]["properties"]) == {"question"}

    def test_a_new_spec_carries_its_own_prompt_shape(self):
        from smartops.subagents import _system_prompt_for

        spec = self._spec()
        prompt = _system_prompt_for(spec.family, turns=4, time_scoped=spec.time_scoped)

        # time_scoped=False must select the lookup guidance, not the time rule.
        assert "rate limited" in prompt
        assert "do NOT use relative times" not in prompt
```

- [ ] **Step 2: Run it**

Run: `uv run pytest backend/tests/test_domains.py::TestAddingADomainIsOneEntry -v`
Expected: PASS immediately — the work was done in Tasks 1–6. If it fails, a consumer is still reading a hard-coded map.

- [ ] **Step 3: Run the whole suite one last time**

Run: `uv run pytest -q`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add backend/tests/test_domains.py
git commit -m "domains: make the one-entry claim executable

Builds a spec that is not in the registry and drives it through the tool
factory and the prompt builder, so 'adding a domain is one entry' is a
test rather than a sentence in a commit message.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Done when

- `uv run pytest -q` is green, and **every commit in the series is green**.
- The only existing test file touched is `test_broker.py`, and `git diff` on it shows only import statements and symbol references — no assertion text.
- `uv run ruff check backend/` is clean.
- `git grep -n "FAMILY_REQUIRED_KINDS\|MCP_SERVERS_BY_FAMILY\|NATIVE_TOOLS_BY_FAMILY\|ENRICHERS_BY_FAMILY\|_TIME_SCOPED_FAMILIES\|_ALL_FAMILIES" -- backend/ contracts/` returns nothing.
- The scripted VT run exits 0.
- Seven commits on `task-broker-agent`, nothing pushed.

## Not in this plan

Plan B (spec §2–§6) adds `assessment_model`, `findings_model` and `index_allowlist` to `DomainSpec`, along with the typed payload, the fetch plan, the rewritten prompts, `BrokerReport` and `temperature`. Plan C (§7–§8) adds the flat Broker arm and the bench runner. Do not add fields for them here — a dead field is worse than a missing one, because it reads as supported.
