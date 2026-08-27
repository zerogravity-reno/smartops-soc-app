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

Pinned to `strands-agents==1.51.0` exactly (`backend/pyproject.toml:18`). The
installed source at `.venv/Lib/site-packages/strands/` is ground truth over any
documentation — verify APIs there and cite `file:line`.

Deliberately not used, each with reasoning in PROJECT_DOCS.md (2026-08-11):
`Swarm` (inlines shared context verbatim into node prompts), `Graph` (node set
fixed before `build()`), `Agent.as_tool()` (single `input: string`, refuses
concurrent invocation), `strands-agents-tools` (cannot send VirusTotal's
`x-apikey`).

## Tests

`[tool.pytest.ini_options]` lives at the workspace root (`pyproject.toml:13-15`)
with `asyncio_mode = "auto"` and `testpaths` covering both members, so a bare run
from the root collects everything:

    uv run pytest

PROJECT_DOCS.md (2026-08-09) says root runs fail every async test and that you
must `cd` into each package. That was true when the config lived only in
`backend/`; it was moved to the root afterwards. Prefer this file for the test
command.

`filterwarnings` at `pyproject.toml:35-39` promotes `DeprecationWarning`,
`PendingDeprecationWarning` and `UserWarning` to **errors**, so an SDK deprecation
fails the suite rather than scrolling by. Other categories are not promoted — the
suite currently emits `RuntimeWarning`s from `MCPClient.stop` and passes. To
silence a third-party warning, add a targeted `ignore:<regex>:<Category>` line
rather than weakening the three.

## Scope discipline

A prior plan reached ~28 new files and was cut to 2 source files as
over-engineered. Prefer the smallest change against the current structure.
