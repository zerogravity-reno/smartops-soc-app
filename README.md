# SmartOps SOC

An investigation pipeline for Splunk ES notable events. It builds the alert's context (ESCU rule, OpenCTI intel), has an Analyst model plan hypotheses and tasks, sends those tasks to a Tool Broker that fetches evidence from Splunk and VirusTotal, and loops until the Analyst reaches a verdict.

**Models:** Foundation-Sec-8B (Analyst) and Claude Sonnet (Tool Broker), both on AWS Bedrock.

---

## How it works

```
Splunk ES notable  (Import from Mission Control, via the official Splunk MCP server)
        │
        ▼
Context pipeline      webapp/static/app.js + webapp/main.py
  seed → ESCU match → OpenCTI lookup → context contract
        │
        ▼
Analyst               Foundation-Sec-8B, webapp/main.py _run_investigation
  plan: hypotheses H1..H3 + tasks {task_id, question, entity, time_window}
        │  run_trace.to_task_file()  →  .smartops/runs/<run_id>/tasks-L<n>.json
        ▼
Tool Broker           python -m smartops.main --task-file … --batch-id <run_id>-L<n>
  per task: plan_fetch → siem / vt subagents → identity / network / endpoint sub-analysts
        │  writes .smartops/runs/<run_id>-L<n>/analyst-payload.json
        ▼
Analyst synthesis     scores the hypotheses → verdict, or follow-up tasks → next loop
```

Everything for one investigation is joined by the webapp's `run_id`:
- `.smartops/runs/<run_id>/investigation.jsonl` has one line per step: `analyst_plan`, `broker` (task file, exit code, handshake, per-task run dirs), `synthesis`.
- `.smartops/runs/<run_id>/broker-L<n>.log` has the engine's output for each loop.
- `.smartops/runs/<run_id>-L<n>-T<k>/<stamp>/` has each task's `report.json`, `evidence.json` and `findings.json`.

The UI shows the loop in two lanes, Analyst and Tool Broker, with a handshake stamp per loop (`sent → fetched → returned`).

---

## Project structure

```
webapp/                      FastAPI app and UI
  main.py                    endpoints, the investigation loop, Broker subprocess
  prompts/system_prompt.txt  Analyst prompt (plan and synthesis)
  services/
    llm_service.py           Foundation-Sec-8B client (Bedrock)
    run_trace.py             task-file conversion, handshake, investigation.jsonl
    splunk_mcp.py            official Splunk MCP client (alert import)
  static/                    index.html, app.js (the UI)
engine/                      Tool Broker package (smartops)
  src/smartops/
    main.py                  CLI: python -m smartops.main
    broker.py                Broker agent: plan_fetch and family dispatch
    subagents/               siem / vt investigation subagents
    subagent_analysts/       identity / network / endpoint sub-analysts
    guards.py                scope, time-window and tstats guards
    budget.py                cost ceiling and model setup
  contracts/                 shared Pydantic models and JSON schemas (task-input.v1, …)
  tests/                     engine test suite
tests/                       webapp tests
mcp_servers.json             MCP server config (official Splunk MCP)
docs/
  analyst-bug-report.md      open Analyst and integration bugs
  handover-2026-09-30.md     latest handover
  examples/                  sample task files for the Broker CLI
  corpus/bm25_corpus.json    ESCU detection corpus
start.ps1                    load .env, uv sync, start the server
```

---

## Setup

**Prerequisites**
- Windows with PowerShell, or any OS with a POSIX shell.
- Python 3.13 (the engine requires it) and [uv](https://docs.astral.sh/uv/).
- AWS Bedrock access to the imported Foundation-Sec-8B model and to Claude Sonnet.
- A Splunk ES instance with the official Splunk MCP server app, plus a token for it.
- A VirusTotal API key. OpenCTI is optional.

**Install**

```powershell
git clone https://github.com/zerogravity-reno/smartops-soc-app.git
cd smartops-soc-app
uv sync                      # installs webapp + engine + contracts + dev tools into .venv
Copy-Item .env.example .env  # then fill in .env (see below)
```

`.env` is git-ignored. Never put secrets in a tracked file.

### Environment variables (`.env`)

| Variable | Used by | What it is |
|---|---|---|
| `FS8B_MODEL_ARN` | Analyst | ARN of the imported Foundation-Sec-8B model |
| `FS8B_API_KEY` | Analyst and Broker | Bedrock API key (`ABSK…`). The Broker also uses it as its Bedrock bearer token. |
| `AWS_REGION` | both | Bedrock region; must match the model ARN |
| `AWS_BEDROCK_MODEL_ID` | Broker | Claude Sonnet inference profile, e.g. `us.anthropic.claude-sonnet-4-6-…` |
| `SPLUNK_MCP_URL` | import and Broker | official Splunk MCP endpoint, e.g. `https://<host>:8089/services/mcp` |
| `SPLUNK_TOKEN` | import and Broker | Splunk token for the MCP server |
| `SMARTOPS_MCP_TLS_NO_VERIFY` | Broker | `splunk` to accept a self-signed :8089 certificate |
| `SMARTOPS_SIEM_INDEXES` | Broker | comma list of indexes the siem subagent may search (default `botsv3`) |
| `VT_API_KEY` | Broker | VirusTotal API key |
| `OPENCTI_URL`, `OPENCTI_TOKEN` | context pipeline | OpenCTI GraphQL endpoint and token (optional) |

---

## Run

### The web app

```powershell
.\start.ps1
```

This loads `.env`, runs `uv sync` and starts the server with auto-reload on http://localhost:8001. To start it without the sync and reload:

```powershell
uv run uvicorn webapp.main:app --port 8001
```

`start_server.bat` also works, but it uses whatever `python` is on your PATH, so run it from an activated `.venv`.

**In the browser:**
1. Click **Import from Mission Control**. It loads the newest notable event from Splunk into the form. You can also fill the form by hand; the rule name is required.
2. Click **Process Event & Build Context**. This builds the seed, runs the ESCU and OpenCTI lookups, and has the Analyst plan the investigation. The OpenCTI lookup can take a few minutes.
3. The full investigation then starts on its own: Broker loops, synthesis, then the verdict banner.

### The Tool Broker on its own

```powershell
# Free: no model calls, scripted dispatch
uv run python -m smartops.main --task-file docs\examples\botsv3-coinhive-tasks.json --batch-id demo-L2 --scripted

# Live: real Bedrock and Splunk calls
uv run python -m smartops.main --task-file docs\examples\botsv3-coinhive-tasks.json --batch-id demo-L2
```

Run `uv run python -m smartops.main --help` for all flags (`--budget-usd`, `--families`, `--verbose`, …).

### Cost

A live investigation costs real money. On 2026-09-30, one Broker loop over 6 tasks cost about **$12** (run `cecd266a`). Most of that came from long Splunk results being re-sent to the model on every turn. Only `--scripted` is guaranteed free. Leaving `SMARTOPS_LLM_PROVIDER` blank does **not** stop Broker model calls.

### Tests

```powershell
uv run pytest -q
```

The suite needs no network and makes no model calls.

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | web UI |
| `GET` | `/debug` | debug page |
| `GET` | `/api/import-from-splunk` | newest notable event from Splunk ES, with its rule's SPL |
| `POST` | `/api/escu` | match a rule name against the ESCU corpus |
| `POST` | `/api/opencti` | OpenCTI lookup for the alert's observables |
| `POST` | `/api/analyst/start` | start the Analyst plan (async) |
| `GET` | `/api/analyst/result/{job_id}` | poll for the plan |
| `POST` | `/api/analyst` | Analyst plan, synchronous (older path) |
| `POST` | `/api/synthesis` | one synthesis call (older path) |
| `POST` | `/api/run` | start the full investigation; returns `run_id` |
| `GET` | `/api/run/stream/{run_id}` | investigation events (SSE) |

---

## Status

- Open bugs: [`docs/analyst-bug-report.md`](docs/analyst-bug-report.md). It has two sections: Analyst, and the integration release.
- Latest handover: [`docs/handover-2026-09-30.md`](docs/handover-2026-09-30.md).
- The secrets committed in the 2026-09-20 integration release are still in git history and must be rotated (bug report, C1–C2).
