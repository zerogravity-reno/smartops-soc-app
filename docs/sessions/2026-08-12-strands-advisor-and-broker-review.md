---
date: 2026-08-12
title: Strands advisor subagent, ground-truth skill, and the broker.py review it produced
---

## Context

Mohammed asked for a Claude Code subagent that acts as a Strands expert — helping
implement correctly and flagging when the code strays — and for the right way to
build subagents and skills generally.

The session split into building that tooling, then using it against `broker.py`.
The findings in the second half are the deliverable; the tooling is what produced
them.

## The problem the tooling exists for

A "Strands best practices" guide Mohammed supplied put `SteeringHandler`, `Guide`,
and `Proceed` at import paths that do not exist. Its *shape* was right — the
`steer_before_tool` signature, `Guide(reason=…)`, `Agent(plugins=[…])` all check
out — but the imports were invented. That is the characteristic failure: code that
reads as correct and does not import.

A web-research agent dispatched mid-session reported that `SharedContext` "is not
exposed to the LLM." Refuted directly against installed source:
`multiagent/swarm.py:681-685` emits "Shared knowledge from previous agents:" and
inlines each node's context verbatim into the next node's prompt. The 08-11 entry's
reasoning for rejecting `Swarm` stands, confirmed independently.

That agent also concluded "no documentation lag detected." Its method was searching
the docs and finding them self-consistent, which cannot detect docs-versus-source
divergence. `backend/pyproject.toml:9-11` already recorded the opposite.

## Decisions

### Ground truth is the installed tree, then a pinned tag, then the web

The advisor may not assert that a Strands API exists, or how it behaves, from
memory or a web page. It reads the installed package and cites `file:line`.

Version comes from `**/strands_agents-*.dist-info/METADATA`, **not** the pin in
`backend/pyproject.toml`. The pin is intent; dist-info is what actually imports,
and a drifted venv is exactly the case that produces confident wrong answers.
`strands/__init__.py` exposes no `__version__`.

GitHub is a second source with a defined role — known bugs, deprecation rationale,
what a version bump changes, how the SDK's own tests use an API. Every citation
pins to the tag matching the install
(`harness-sdk/tree/python/v1.50.2`), never `main`, which is at `python/v1.51.0`.

### Two scopes, because the two kinds of knowledge are not portable together

Strands API facts belong to the library and travel to any project. SmartOps'
architectural decisions do not. Mohammed caught a first draft that hardcoded
`backend/pyproject.toml` and `docs/PROJECT_DOCS.md` into a user-scoped agent —
those exist in this repo and nowhere else, so the agent would have degraded
silently in any other project rather than failing loudly.

### Recorded decisions are settled

The advisor raises only two things against a recorded decision: **drift** (code no
longer matches its own decision) and **falsified premise** (the decision rests on
a stated fact that is no longer true). It does not re-argue Swarm, Graph,
`as_tool()`, or `strands-agents-tools`. Both categories fired this session.

## The Strands org restructured

- `sdk-python` and `sdk-typescript` **no longer exist as repos**. The SDK is
  `strands-agents/harness-sdk`, Python and TypeScript together. Tags are
  `python/vX.Y.Z`; `python/v1.50.2` exists, so GitHub can be pinned to exactly
  what is installed.
- **`docs` is archived**, along with `mcp-server` and `agent-builder`. An archived
  documentation repo is worth remembering whenever a docs page contradicts source.
- `evals` is the live repo behind `strands-agents-evals` (deferred on 08-11).
- Latest published `strands-agents` is **1.51.0** (2026-08-07). We are on 1.50.2.

## Findings against `broker.py` — verified

Each of these was re-verified against source independently of the agent that
raised it.

### 1. Entity values reach the model unsanitized, inside the block labelled trusted

`broker.py:530` renders entities raw — `f"{e.kind}={e.value}"` — into a section
headed "Investigation scope (fixed by the system, not modifiable)". One block
down, `task.goal` is passed through `_neutralize_delimiter()` and wrapped in
`<goal>` with an explicit untrusted-data warning (`:536`).

So an injected instruction inside an entity value lands in the part of the prompt
the system prompt vouches for. The framing does not merely fail to protect it — it
actively marks it trustworthy. `EntityKind` includes `url`, `domain`, and
`process`, all of which carry attacker-influenceable strings from alert data.

The same shape exists in `subagents/__init__.py:220,238-239`.

### 2. `_neutralize_delimiter()` is one literal replace

`broker.py:522` is `text.replace("</goal>", "<​/goal>")`. It does not catch
`</GOAL>`, `</ goal>`, or an attacker opening a *new* tag such as `<system>`
rather than closing `<goal>`.

### 3. A comment in `broker.py` is false

`broker.py:527-528` states "Strands ships no input-sanitisation helper, so this
framing is ours to do." Strands ships `_escape_xml_text` and `_escape_xml_attr` at
`strands/injection/_xml.py:12,26`, whose module docstring names this exact threat
("opens a stored-prompt-injection surface"). They are private and reachable only
via `ContextInjector`/`MemoryManager`, so *"no public helper"* would be accurate.
As written the comment is wrong.

### 4. `invoke_async` uses the deprecating `**kwargs` channel

`broker.py:633-638` passes `smartops=request` as a bare kwarg.
`strands/agent/agent.py:1176-1177` warns whenever `kwargs` is non-empty:
"`**kwargs` parameter is deprecating, use `invocation_state` instead."

This fires on **every** Broker invocation. No `filterwarnings` is configured
anywhere in the project, so nothing surfaces it. Behaviour is identical today;
the fix is:

    return await agent.invoke_async(
        prompt,
        invocation_state={"smartops": request},
        limits=Limits(turns=turns, output_tokens=max_output_tokens),
    )

The comment at `:636` already says "Becomes `invocation_state` inside every tool
call" — the intent was right, expressed through the wrong channel.

## Reimplementation sweep — what is *not* redundant

- **`budget.py` is not redundant.** `Limits` (`strands/types/agent.py:17-47`) is a
  soft per-call cap inside one `invoke_async`, with no shared pool and no
  cross-role accounting. `LedgerProvider`
  (`vended_plugins/steering/context_providers/ledger_provider.py`) is a steering
  audit trail with no cost concept at all, despite the name. Nothing in 1.50.2
  offers pre-flight, cross-role, reserve-then-settle admission control against a
  shared pool.
- **`_usage_from_accumulated()` is a legitimate adapter**, not a reimplementation —
  `telemetry/metrics.py` exposes only the camelCase dict and a private text
  formatter. It is byte-for-byte duplicated in `subagents/__init__.py:419-428`
  though, which is a DRY note unrelated to Strands.
- **`telemetry.py`, retry strategy, and concurrent fan-out** all correctly delegate
  rather than reimplement.
- **`tools/registry.py:398-420`'s `_load_tools_off_loop`** works around a real SDK
  footgun: `MCPClient.load_tools()` is `async def` with no `await` in its body,
  blocking on `concurrent.futures.Future.result()`. The workaround is correct.

### One falsified premise

The recorded decision rejects `strands-agents-tools` for VirusTotal because its
fixed auth types emit `Authorization:` or `X-API-Key`, never `x-apikey`. That is a
separate external package, not installed. **`strands.vended_tools.http_request`
now ships inside core 1.50.2** and has no fixed auth list — `make_http_request()`
takes `client: httpx.AsyncClient | None`
(`vended_tools/http_request/http_request.py:36-40`), so an operator-supplied client
carries credentials that are never model-visible, which is the property
`virustotal.py:6-12` says a generic HTTP tool lacks.

The decision is probably still right — `http_request` would not replace VT's
base64url URL-identifier encoding (`virustotal.py:120-138`), its
404-as-unknown-versus-error semantics, or its `Verdict`/`Evidence` shaping. But its
**stated reason now points at the wrong package** and should be restated if
revisited.

## Correction to the 08-09 entry

That entry says running `pytest` from the workspace root fails every async test
because the root has no `[tool.pytest.ini_options]`, and that you must `cd` into
each package. **No longer true.** Root `pyproject.toml:13-15` now defines
`asyncio_mode = "auto"` and `testpaths = ["contracts/tests", "backend/tests"]`,
with a comment recording that it was moved there for exactly this reason. A bare
`uv run pytest` from the root is now the correct invocation.

## What we built

- `~/.claude/agents/strands-advisor.md` — read-only advisor (`Read`, `Grep`,
  `Glob`, `WebSearch`, `WebFetch`; `sonnet`). User-scoped, no project paths.
- `~/.claude/skills/strands-api-ground-truth/SKILL.md` — verified 1.50.2 surface
  map, corrections table, search quirks, GitHub pinning rules.
- `CLAUDE.md` at the repo root — the SmartOps-specific layer, pointing at
  `docs/PROJECT_DOCS.md` rather than restating it. Now tracked, with uncommitted
  edits (the test-command correction below).

Two SDK traps recorded in the skill, both verified:

- **`Guide` and `Proceed` exist twice** — `vended_plugins/steering/core/action.py`
  (pydantic, `reason` required) and `interventions/actions.py` (frozen dataclass,
  `reason` optional). Both accept `reason=`; both carry a `type` field with the
  same string values. The steering dispatch is `isinstance`
  (`core/handler.py:114-130`) with a terminal `else: raise ValueError`.
- **A steering handler that throws silently disables itself.**
  `core/handler.py:97-101` catches `Exception`, logs at **debug**, and returns —
  the tool then executes normally. A `KeyError` in policy code stops the guard
  with no visible trace.

## Open items

1. **Entity sanitization** — not fixed. Decide between escaping entity values,
   moving them inside an untrusted-data block, or both. Note the current framing
   explicitly tells the model they are system-fixed.
2. **`invocation_state` fix** in `broker.py:633-638` — not applied.
3. **Restate or retire the VirusTotal decision's premise**, given
   `vended_tools.http_request`.
4. **De-duplicate `_usage_from_accumulated()`** across `broker.py` and
   `subagents/__init__.py`.
5. **`CLAUDE.md` has uncommitted edits** — the corrected test command and the
   `filterwarnings` note. Review and commit.
6. **1.51.0 is out.** No assessment made of what changed since 1.50.2.
   Note `broker.py:519-522`'s module-level aliases are flagged in-code as
   temporary pending the DomainSpec migration, which has uncommitted work in
   `docs/superpowers/plans/2026-08-12-domainspec-refactor.md`.
7. **Items 3–10 of the advisor's ranked list were not independently verified** —
   re-dispatch semantics for a model-authored `rejected`, cancellation leaving
   `dispatched` without a `collected` entry, `enrich_mission()`'s PARTIAL case not
   setting `gaps`, and several latent footguns. Worth reading before acting.
