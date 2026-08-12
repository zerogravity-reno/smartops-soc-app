# SmartOps SOC App

Multi-agent SOC triage/IR engine. Python 3.13, `uv` workspace: `contracts/`,
`backend/`, `frontend/`.

## Decisions of record

`docs/PROJECT_DOCS.md` is the decision record, compiled from `docs/sessions/` by
`docs/compile_docs.py`. **Edit a session file and re-compile — never edit
PROJECT_DOCS.md directly.**

Read the relevant section before proposing architectural changes. Decisions
recorded there are settled; raise one again only if the code has drifted from it,
or if its stated premise is no longer true.

Open cross-team questions live in `docs/open-questions-for-team.md`.

## Strands

Pinned to `strands-agents==1.50.2` exactly (`backend/pyproject.toml`). The
installed source at `.venv/Lib/site-packages/strands/` is ground truth over any
documentation — verify APIs there and cite `file:line`.

Deliberately not used, each with reasoning in PROJECT_DOCS.md (2026-08-11):
`Swarm` (inlines shared context verbatim into node prompts), `Graph` (node set
fixed before `build()`), `Agent.as_tool()` (single `input: string`, refuses
concurrent invocation), `strands-agents-tools` (cannot send VirusTotal's
`x-apikey`).

## Tests

Run scoped to each package. The workspace root has no
`[tool.pytest.ini_options]`, so `asyncio_mode = "auto"` is not picked up from
there and every async test fails:

    cd backend && uv run pytest tests
    cd contracts && uv run pytest tests

## Scope discipline

A prior plan reached ~28 new files and was cut to 2 source files as
over-engineered. Prefer the smallest change against the current structure.
