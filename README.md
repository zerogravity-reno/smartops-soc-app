# SmartOps SOC

An investigation pipeline for Splunk ES notable events. It builds the alert's context (ESCU rule, OpenCTI intel), has an Analyst model plan hypotheses and tasks, sends those tasks to a Tool Broker that fetches evidence from Splunk and VirusTotal, and loops until the Analyst reaches a verdict.

**Models:** Foundation-Sec-8B (Analyst, AWS Bedrock) and Claude (Tool Broker, Anthropic API).

For installation, local development, testing, and collaboration, start with the [contributor guide](CONTRIBUTING.md). Local tests and ESCU search work without service credentials.

---

## How it works

```
Splunk ES notable  (Import from Mission Control, via the official Splunk MCP server)
        │
        ▼
Context pipeline      frontend/ + smartops/context.py
  seed → ESCU match → OpenCTI lookup → context contract
        │
        ▼
Analyst               Foundation-Sec-8B, smartops/analyst.py investigate()
  plan: hypotheses H1..H3 + tasks {task_id, question, entity, time_window}
        │  to_task_file() → broker.run_round(), in process
        ▼
Tool Broker           smartops/broker.py run_round()
  per task: plan_fetch → siem / vt subagents → identity / network / endpoint sub-analysts
        │  returns the payload (RoundResult); also written to runs/<run_id>/L<n>/
        ▼
Analyst synthesis     scores the hypotheses → verdict, or follow-up tasks → next loop
```

Everything for one investigation is joined by its `run_id`, under `.smartops/runs/<run_id>/` (the record; nothing reads it back):
- `investigation.jsonl` has one line per step: `analyst_plan`, `broker` (tasks, handshake, per-task run dirs), `synthesis`.
- `L<n>/` holds each round: `tasks.json`, `broker.log` (the Broker's output), `analyst-payload.json`, and one `T<k>/` per task with `report.json`, `evidence.json` and `findings.json`.

The UI shows the run as five stages (Context, Plan, Evidence, Findings, Synthesis), each card tagged Analyst or Tool Broker, with a handshake stamp per loop (`sent → fetched → returned`).

---

## Project structure

```
engine/                      the backend (package smartops)
  src/smartops/
    main.py                  the entry point: API server (smartops.main:app) and CLI
    analyst.py               Analyst agent: plan, Broker rounds, synthesis, verdict gate
    broker.py                Tool Broker agent: plan_fetch, family dispatch, run_round
    context.py               alert context: Splunk queue and import, ESCU, OpenCTI
    prompts/                 Analyst system prompt (plan and synthesis)
    subagents/               siem / vt investigation subagents
    subagent_analysts/       identity / network / endpoint sub-analysts, Foundation-Sec client
    tools/                   MCP client registry (Splunk, VirusTotal): the only place MCP clients are built
    telemetry.py             spans, the investigation record, per-round output
    guards.py                scope, time-window and tstats guards
    budget.py                cost ceiling and model setup
  contracts/                 shared Pydantic models and JSON schemas (task-input.v1, …)
  tests/                     engine test suite
frontend/                    React + TypeScript UI (built by start.ps1; served at /)
tests/                       Analyst and server tests
mcp_servers.json             MCP server config (official Splunk MCP)
docs/
  examples/                  sample task files for the Broker CLI
  corpus/bm25_corpus.json    ESCU detection corpus
start.ps1                    uv sync, build the frontend, start the server
```

---

## Setup

**Prerequisites**
- Windows with PowerShell, or any OS with a POSIX shell.
- Python 3.13, pinned in `.python-version` and `pyproject.toml` (`>=3.13,<3.14`), and [uv](https://docs.astral.sh/uv/), which fetches that Python if it is missing.
- Node.js 24 with npm is the tested development baseline.
- For live investigations: AWS Bedrock access to the imported Foundation-Sec-8B model, an Anthropic API key, and a Splunk ES instance with the official Splunk MCP server app and token.
- A VirusTotal API key enables VirusTotal lookups. OpenCTI is optional. These services are not needed to install, build, or run the local tests.

**Install**

```powershell
git clone https://github.com/zerogravity-reno/smartops-soc-app.git
cd smartops-soc-app
uv sync --frozen              # backend + contracts + dev tools in .venv
cd frontend
npm ci
npm run build
cd ..
```

No `.env` is needed for local tests or ESCU search. For live services, create a git-ignored `.env` with the settings you need below. Never put secrets in a tracked file.

### Environment variables (`.env`)

The env file is `.env` in the repo root. Use [`.env.example`](.env.example) as a reference; replace placeholders and leave `SMARTOPS_MCP_TLS_NO_VERIFY` unset to keep certificate verification enabled.
- The server and the Broker CLI (`python -m smartops.main`) both search upward from the working directory for a `.env`, the server once at startup. `--verbose` prints which file the CLI loaded.
- A variable already set in your shell wins over the file (`override=False`).

| Variable | Used by | Required | Default | What it is |
|---|---|---|---|---|
| `AWS_REGION` | Analyst and sub-analysts | yes | `us-east-1` | Bedrock region; keep it the same as the Foundation model ARN's region. |
| `SMARTOPS_ANALYST_MODEL_ARN` | Analyst and sub-analysts | yes for the Analyst | none | Imported Foundation-Sec model: the Analyst, and the identity, network and endpoint sub-analysts. Empty skips the sub-analysts. |
| `SMARTOPS_ANALYST_API_KEY` | Analyst and sub-analysts | yes for the Analyst | falls back to the standard AWS credential chain | `ABSK...` bearer token, or `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]`. Scoped to the Analyst model's own client, never the Broker's (AR3). |
| `ANTHROPIC_API_KEY` | Broker | yes for live Broker calls | none | First-party Anthropic API key for the Broker's Claude models. |
| `SMARTOPS_LLM_PROVIDER` | Broker | yes for live Broker calls | `anthropic` in `.env.example` | Set to `anthropic`. Set `none` to disable Broker model calls. |
| `SMARTOPS_BROKER_TIERS` | Broker | no | `A` | Claude model/effort preset for the Broker, SIEM, and VirusTotal roles. |
| `SMARTOPS_MODEL_ID_BROKER`, `SMARTOPS_MODEL_ID_SIEM`, `SMARTOPS_MODEL_ID_VT` | Broker | no | tier preset | Per-role Claude model overrides. |
| `SPLUNK_MCP_URL` | import and Broker | yes | none | Official Splunk MCP endpoint, e.g. `https://<host>:8089/services/mcp` |
| `SPLUNK_TOKEN` | import and Broker | yes | none | Splunk token for the MCP server |
| `SMARTOPS_MCP_TLS_NO_VERIFY` | import and Broker | no | blank (verify TLS) | `splunk` to accept a self-signed :8089 certificate |
| `SMARTOPS_MCP_CONFIG` | Broker | no | `mcp_servers.json` in the working directory | Path to a different MCP server config (same as `--mcp-config`) |
| `SMARTOPS_SIEM_INDEXES` | Broker | no | `botsv3` | Comma list of indexes the siem subagent may search, e.g. `windows_lab,main`. `notable` and `risk` (ES detection records) are always rejected, even if listed |
| `VT_API_KEY` | Broker | no | none | VirusTotal API key. Without it the vt family reports the missing key. |
| `OPENCTI_URL` | context pipeline | no | `http://localhost:8080/graphql` | OpenCTI GraphQL endpoint, e.g. `http://<opencti-host>:8080/graphql` |
| `OPENCTI_TOKEN` | context pipeline | no | blank | OpenCTI token |
| `SMARTOPS_RUNS_DIR` | Analyst and Broker | no | `.smartops/runs` | Where run folders are written (relative to the working directory) |
| `SMARTOPS_ANALYST_TEMPERATURE`, `SMARTOPS_ANALYST_TOP_P` | Broker sub-analysts | no | `0.3`, `0.95` | Generation settings (defaults per `.env.example`) |
| `SMARTOPS_ANALYST_MAX_GEN_LEN` | Broker sub-analysts | no | `3072` | Max generated tokens; values above the default are clamped |
| `SMARTOPS_SKILLS_ENABLED` | Broker | no | off | `true` enables the reference skill pack for siem (same as `--skills`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Broker | no | none (no export) | OTLP collector for traces. Spans can carry SOC data, so read `.env.example` before enabling. |

Not fully explained here: `SMARTOPS_ANALYST_CMU_COUNT` and `SMARTOPS_ANALYST_CMU_PRICE` (read in `engine/src/smartops/analyst_cost.py`; they set the cost model for the imported Analyst model, default count `0`).

Copy-paste template (placeholders only; fill in your own values):

```
SMARTOPS_ANALYST_MODEL_ARN=arn:aws:bedrock:us-east-1:<acct>:imported-model/<id>
SMARTOPS_ANALYST_API_KEY=<your-bedrock-api-key>
AWS_REGION=us-east-1
ANTHROPIC_API_KEY=<your-anthropic-api-key>
SMARTOPS_LLM_PROVIDER=anthropic
SPLUNK_MCP_URL=https://<splunk-host>:8089/services/mcp
SPLUNK_TOKEN=<your-splunk-token>
SMARTOPS_SIEM_INDEXES=botsv3
VT_API_KEY=<your-vt-key>
OPENCTI_URL=http://<opencti-host>:8080/graphql
OPENCTI_TOKEN=<your-opencti-token>
# optional
# SMARTOPS_RUNS_DIR=.smartops/runs
```

---

## Run

### The web app

```powershell
.\start.ps1
```

This runs `uv sync`, builds the frontend (`npm install`, `npm run build` in `frontend/`) and starts the server on http://localhost:8013 with `--reload`. `main.py` is the one entry point: the FastAPI app and the Broker CLI. The Analyst and the Broker run in that process; there is no second launcher and no Broker subprocess.

**`--reload` restarts the server on any `.py` change, and a restart kills a live run** (runs are held in memory; the browser reports the lost stream). Don't edit Python while an investigation is running, or start without reload:

```powershell
uv run uvicorn smartops.main:app --port 8013
```

The Broker's MCP clients are built and warmed at startup, and warmed again at the start of every round, so a Splunk client that failed once is retried rather than staying failed. A healthy client returns its cached tools. An unreachable Splunk makes startup wait out three connection attempts.

**In the browser:**
1. Pick an alert in the **Incident queue** on the left (the latest 10 notables from Splunk ES). Its facts (host, user, event time, command line, parent, hash) show at the top; **Edit fields** opens the form, which you can also fill by hand (the rule name is required).
2. Click **Investigate**. This builds the context contract (seed, ESCU match, OpenCTI lookup) and starts one `/api/run`: Analyst plan, Broker loops, synthesis, verdict. The OpenCTI lookup can take a few minutes.
3. Follow it live in the stage list: the active stage is open, a finished one folds to a one-line summary (click to reopen). The right rail keeps the verdict, hypothesis scores, per-task progress (click a task to open its findings) and the run's spend and tokens in view. The raw context sent to the pipeline is under the Context stage.

### The Tool Broker on its own

```powershell
# No model calls; configured domain services may still receive requests
uv run python -m smartops.main --task-file docs\examples\botsv3-coinhive-tasks.json --batch-id demo-L2 --scripted

# Live: real Anthropic and Splunk calls
uv run python -m smartops.main --task-file docs\examples\botsv3-coinhive-tasks.json --batch-id demo-L2
```

Run `uv run python -m smartops.main --help` for all flags (`--budget-usd`, `--families`, `--verbose`, …).

### Cost

A live investigation costs real money. On 2026-09-30, one Broker loop over 6 tasks cost about **$12** (run `cecd266a`). Most of that came from long Splunk results being re-sent to the model on every turn. `--scripted` disables model calls, but configured domain services can still receive requests. Set `SMARTOPS_LLM_PROVIDER=none` to disable Broker model calls without that flag; this does not disable the Analyst's Bedrock calls during a web investigation.

### Tests

```powershell
uv run --frozen pytest -q -ra  # engine/contracts/tests, engine/tests, tests

cd frontend
npm test                      # vitest: the run reducer and formatting
npm run build                 # tsc --noEmit, then vite build
```

None of these needs a network or makes model calls. Type-check the frontend through `npm run build`, not a separate `tsc` call. There is no Playwright e2e script in `frontend/`; do not run `npm run e2e`.

**Live investigation** (real calls, costs money): start the server (`.\start.ps1`, port 8013), pick an alert in the Incident queue, and click Investigate. The run itself lands in `.smartops/runs/<run_id>/`. The old `tests/test-integration/scripts/repeats.sh` harness and its `notable.json` no longer exist (only past `rep1*.log`/`server-rep*.log` output remains), so do not run that command.

### Common problems

- **HTTP 429 from Foundation-Sec-8B at the start:** the imported model is cold-starting. The client retries every 30 s, so wait.
- **TLS errors against Splunk :8089:** use a certificate valid for the endpoint hostname and configure trust for your organization's CA. Keep certificate verification enabled.
- **A live run stalls or the browser dies:** check free memory first; the Playwright driver plus the server need about 1 GB.

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | web UI |
| `GET` | `/api/incident-queue` | notables for the queue |
| `GET` | `/api/import-from-splunk` | one notable event from Splunk ES, with its rule's SPL |
| `POST` | `/api/escu` | match a rule name against the ESCU corpus |
| `POST` | `/api/opencti` | OpenCTI lookup for the alert's observables |
| `POST` | `/api/run` | start the full investigation (plan, rounds, synthesis); returns `run_id` |
| `POST` | `/api/run/{run_id}/stop` | stop a run |
| `POST` | `/api/run/{run_id}/pause` | pause a run |
| `POST` | `/api/run/{run_id}/resume` | resume a paused run |
| `GET` | `/api/run/stream/{run_id}` | investigation events (SSE); resumes after `Last-Event-ID` |

---

## Status

- Open bugs: [`docs/smartops-issues-report.md`](docs/smartops-issues-report.md); "Where things stand" under Priorities is the current summary.
- The secrets committed in the 2026-09-20 integration release were rotated on 2026-10-12 (S1); confirm the `33ccf52` keys were included.
