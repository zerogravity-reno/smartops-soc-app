# SmartOps SOC

An investigation pipeline for Splunk ES notable events. It builds the alert's context (ESCU rule, OpenCTI intel), has an Analyst model plan hypotheses and tasks, sends those tasks to a Tool Broker that fetches evidence from Splunk and VirusTotal, and loops until the Analyst reaches a verdict.

**Models:** Foundation-Sec-8B (Analyst) and Claude Sonnet (Tool Broker), both on AWS Bedrock.

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
  e2e/                       Playwright browser checks, API mocked
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
- Node.js with npm, to build the frontend.
- AWS Bedrock access to the imported Foundation-Sec-8B model and to Claude Sonnet.
- A Splunk ES instance with the official Splunk MCP server app, plus a token for it.
- A VirusTotal API key. OpenCTI is optional.

**Install**

```powershell
git clone https://github.com/zerogravity-reno/smartops-soc-app.git
cd smartops-soc-app
uv sync                      # installs the backend + contracts + dev tools into .venv
Copy-Item .env.example .env  # then fill in .env (see below)
```

`.env` is git-ignored. Never put secrets in a tracked file.

### Environment variables (`.env`)

The env file is `.env` in the repo root (copy [`.env.example`](.env.example), which holds placeholders only).
- The server and the Broker CLI (`python -m smartops.main`) both search upward from the working directory for a `.env`, the server once at startup. `--verbose` prints which file the CLI loaded.
- A variable already set in your shell wins over the file (`override=False`).

| Variable | Used by | Required | Default | What it is |
|---|---|---|---|---|
| `FS8B_API_KEY` | every Bedrock client | yes, until AR3 | none | Bedrock API key, e.g. `ABSK...`, applied to every Bedrock client by a patch in `smartops/main.py` (AR3: goes once `SMARTOPS_ANALYST_API_KEY` holds the working key). |
| `AWS_REGION` | both | yes for Broker on Bedrock | `us-east-1` for the Analyst; the Broker also accepts `AWS_DEFAULT_REGION` and refuses to start with neither | Bedrock region; keep it the same as the model ARN's |
| `AWS_BEDROCK_MODEL_ID` | Broker | yes, to use a model | none | Claude Sonnet inference profile, e.g. `us.anthropic.claude-sonnet-4-6`. Find yours with `aws bedrock list-inference-profiles --region <region>`. |
| `SMARTOPS_LLM_PROVIDER` | Broker | no | blank | `bedrock`, `deepseek` or `none`. `none` turns the Broker model off even if credentials are set. Blank means detect: Bedrock if `AWS_BEDROCK_MODEL_ID` is set, else DeepSeek if `DEEPSEEK_API_KEY` is set, else no model (scripted dispatch). Any other value is an error. |
| `SMARTOPS_MODEL_ID` | Broker | no | none | Model id override for any provider; wins over `AWS_BEDROCK_MODEL_ID`. |
| `SMARTOPS_PRICING_KEY` | Broker | no | inferred from the model id | Pricing entry for the budget. Set only if the model family can't be read from its id. |
| `DEEPSEEK_API_KEY` | Broker | no | none | Selects DeepSeek when no Bedrock model id is set. `.env.example` notes that selecting DeepSeek currently fails at startup (no pricing entry yet). |
| `AWS_PROFILE` | Broker | no | none | Standard AWS profile; boto3 uses it when set. If the Broker model then fails to build, the error says to unset it to fall back to `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (`engine/src/smartops/broker.py`). |
| `SPLUNK_MCP_URL` | import and Broker | yes | none | Official Splunk MCP endpoint, e.g. `https://<host>:8089/services/mcp` |
| `SPLUNK_TOKEN` | import and Broker | yes | none | Splunk token for the MCP server |
| `SMARTOPS_MCP_TLS_NO_VERIFY` | import and Broker | no | blank (verify TLS) | `splunk` to accept a self-signed :8089 certificate |
| `SMARTOPS_MCP_CONFIG` | Broker | no | `mcp_servers.json` in the working directory | Path to a different MCP server config (same as `--mcp-config`) |
| `SMARTOPS_SIEM_INDEXES` | Broker | no | `botsv3` | Comma list of indexes the siem subagent may search, e.g. `windows_lab,main`. `notable` and `risk` (ES detection records) are always rejected, even if listed |
| `VT_API_KEY` | Broker | no | none | VirusTotal API key. Without it the vt family reports the missing key. |
| `OPENCTI_URL` | context pipeline | no | `http://localhost:8080/graphql` | OpenCTI GraphQL endpoint, e.g. `http://<opencti-host>:8080/graphql` |
| `OPENCTI_TOKEN` | context pipeline | no | blank | OpenCTI token |
| `SMARTOPS_RUNS_DIR` | Analyst and Broker | no | `.smartops/runs` | Where run folders are written (relative to the working directory) |
| `SMARTOPS_ANALYST_MODEL_ARN` | Analyst and sub-analysts | yes for the Analyst | none | Imported Foundation-Sec model: the Analyst, and the identity, network and endpoint sub-analysts. Empty skips the sub-analysts. |
| `SMARTOPS_ANALYST_API_KEY` | Broker sub-analysts | no | falls back to the standard AWS credential chain | `ABSK...` bearer token, or `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]` |
| `SMARTOPS_ANALYST_TEMPERATURE`, `SMARTOPS_ANALYST_TOP_P` | Broker sub-analysts | no | `0.3`, `0.95` | Generation settings (defaults per `.env.example`) |
| `SMARTOPS_ANALYST_MAX_GEN_LEN` | Broker sub-analysts | no | `3072` | Max generated tokens; values above the default are clamped |
| `SMARTOPS_SKILLS_ENABLED` | Broker | no | off | `true` enables the reference skill pack for siem (same as `--skills`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Broker | no | none (no export) | OTLP collector for traces. Spans can carry SOC data, so read `.env.example` before enabling. |

Not fully explained here: `SMARTOPS_ANALYST_CMU_COUNT` and `SMARTOPS_ANALYST_CMU_PRICE` (read in `engine/src/smartops/analyst_cost.py`; they set the cost model for the imported Analyst model, default count `0`).

Copy-paste template (placeholders only; fill in your own values):

```
SMARTOPS_ANALYST_MODEL_ARN=arn:aws:bedrock:us-east-1:<acct>:imported-model/<id>
FS8B_API_KEY=<your-bedrock-api-key>
AWS_REGION=us-east-1
AWS_BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6
SMARTOPS_LLM_PROVIDER=bedrock
SPLUNK_MCP_URL=https://<splunk-host>:8089/services/mcp
SPLUNK_TOKEN=<your-splunk-token>
SMARTOPS_MCP_TLS_NO_VERIFY=splunk
SMARTOPS_SIEM_INDEXES=botsv3
VT_API_KEY=<your-vt-key>
OPENCTI_URL=http://<opencti-host>:8080/graphql
OPENCTI_TOKEN=<your-opencti-token>
# optional
# SMARTOPS_RUNS_DIR=.smartops/runs
# SMARTOPS_ANALYST_API_KEY=<your-bedrock-api-key>
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
uv run pytest -q              # engine/contracts/tests, engine/tests, tests (pyproject testpaths)

cd frontend
npm test                      # vitest: the run reducer and formatting
npm run e2e                   # Playwright: the console against a mocked API, both colour modes, axe WCAG AA
npm run build                 # tsc --noEmit, then vite build
```

None of these needs a network or makes model calls. Type-check the frontend through `npm run build`, not a separate `tsc` call.

**Live end-to-end run** (real calls, costs money): starts the server on :8001, drives the UI with Playwright through one notable (`tests/test-integration/scripts/notable.json`), and stops the server.

```bash
RUNS=1 bash tests/test-integration/scripts/repeats.sh
```

The UI log and screenshots land in `tests/test-integration/scripts/rep1*`, and the run itself in `.smartops/runs/<run_id>*`.

### Common problems

- **HTTP 429 from Foundation-Sec-8B at the start:** the imported model is cold-starting. The client retries every 30 s, so wait.
- **TLS errors against Splunk :8089:** set `SMARTOPS_MCP_TLS_NO_VERIFY=splunk` for a self-signed certificate.
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
