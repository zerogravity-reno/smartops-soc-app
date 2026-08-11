# SmartOps SOC

A SOC triage and incident-response engine. An Analyst agent forms a hypothesis;
a **Task Broker** agent decides which security domains can help and dispatches
work to them; domain subagents query the relevant tools and report back with
citable evidence.

## Current state

The Task Broker runs end to end. **Nothing executes yet** — no MCP server is
configured and no model credentials are present, so every domain reports
honestly why it cannot answer and the process exits 0. That failure path is the
only path available until credentials exist, and it is the one that is
exercised.

| Component | State |
|---|---|
| `contracts` | `AnalystTask`, `SubagentMission`, `SubtaskResult`, `Evidence`, typed `Entity` |
| Task Broker (`broker.py`) | Working — an LLM agent dispatching via Agents-as-Tools |
| `siem` (Splunk, over MCP) | Config-driven; needs `SPLUNK_MCP_URL` + `SPLUNK_TOKEN` |
| `vt` (VirusTotal, REST) | Working — needs `VT_API_KEY`. Runs with no model at all |
| `edr` / `ndr` | No vendor chosen; disabled in config |
| Domain subagents | Not built — `run_subagent` is the seam they slot into |
| Model providers | Bedrock or DeepSeek, selected from env; neither required |

## Quick start

```bash
uv sync
cp .env.example .env          # optional — it runs without any of it
uv run smartops-broker --goal "unusual auth activity for someuser" \
                       --entity user:someuser --hours 24
```

With nothing configured you get four honest rejections and exit 0:

```
4 result(s):
  [rejected] siem  no tools resolved for siem: no MCP server configured yet
  [rejected] edr   no tools resolved for edr: no MCP server configured yet
  [rejected] vt    no vt observable in scope: needs one of ['domain', 'file_hash', 'ip', 'url'], scope has ['user']
  [rejected] ndr   no ndr observable in scope: needs one of ['domain', 'ip', 'url'], scope has ['user']
```

Two different kinds of "no", and the difference is the point. `siem` and `edr`
*could* answer this question — a username is something both understand — they
just aren't connected. `vt` and `ndr` **cannot** answer it at all: reputation
services and network telemetry have no concept of a username, so no amount of
configuration would help.

Swap the entity and the two groups swap with it:

```bash
uv run smartops-broker --goal "beaconing to 10.2.4.9" --entity ip:10.2.4.9
```

```
  [rejected] siem  no tools resolved for siem: no MCP server configured yet
  [rejected] edr   no edr observable in scope: needs one of ['host', 'process', 'user'], scope has ['ip']
  [rejected] vt    vt lookup unavailable: VT_API_KEY is not set
  [rejected] ndr   no tools resolved for ndr: no MCP server configured yet
```

Now `edr` is the one that cannot help, and `vt` has cleared the gate — it got as
far as attempting a real lookup and reports the missing credential instead.

Entities are `kind:value`, where kind is one of `host`, `user`, `ip`,
`file_hash`, `domain`, `url`, `process`. Add `--verbose` for logs, `--scripted`
to bypass the model even when one is configured.

## How it works

```
Analyst agent
    │  AnalystTask (goal + scope; no tool named)
    ▼
Task Broker ── an LLM agent ───────────────────────────────┐
    │  Its choice of which tool to call IS the             │
    │  classification. One LLM call, not two.              │
    ▼                                                      │
investigate_siem / _edr / _vt / _ndr   ← typed @tool wrappers
    │  question: str is the model's ONLY parameter.        │
    │  scope arrives out-of-band and cannot be widened.    │
    ▼                                                      │
SubagentMission ──▶ tools_for(family) ──▶ subagent ──▶ SubtaskResult
                    (MCP + native)        (stubbed)    + Evidence
    │                                                      │
    └── digest + typed `gaps` back to the Broker ──────────┘
        Raw Evidence never enters a prompt.
```

Two properties worth knowing because they constrain everything else:

- **`scope` is not a tool parameter.** The Broker authors each domain's
  question, but the entity list and time window reach the mission out-of-band,
  so a model cannot widen them or invent them.
- **Raw `Evidence` never reaches a model.** Tool wrappers return a short digest;
  the full result and its raw responses are collected by code, for the
  aggregator and the case file.

Domains are gated on what they can actually be *asked*: VirusTotal needs a
hash, IP, domain, or URL; EDR needs a host, process, or user; SIEM accepts
anything. That is a precondition, not a judgement, which is why it lives in code
rather than in a prompt.

## Layout

```
contracts/          shared types — the Analyst↔Broker↔subagent interfaces
backend/
  src/smartops/
    broker.py       the Task Broker agent and its family tools
    budget.py       cost ledger, budget gating, model/provider selection
    main.py         the smartops-broker CLI
    telemetry.py    OpenTelemetry wiring (exports nothing by default)
    tools/          registry (family → servers/tools), native tools
mcp_servers.json    MCP server config; credentials as ${VAR}
docs/               per-session decision record (see docs/README.md)
```

## Configuration

Everything is optional. See `.env.example` for the full annotated set; the
essentials:

| Variable | Effect |
|---|---|
| `SPLUNK_MCP_URL`, `SPLUNK_TOKEN` | Connects `siem` |
| `VT_API_KEY` | Connects `vt` (works with no model) |
| `AWS_REGION` (+ AWS credentials) | Selects Bedrock |
| `DEEPSEEK_API_KEY` | Selects DeepSeek, if Bedrock is absent |
| `SMARTOPS_LLM_PROVIDER` | Forces `bedrock` or `deepseek` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Enables span export (off by default) |

**Provider selection is configuration, not failover.** A Bedrock outage does not
fall through to DeepSeek mid-run — that would silently change which model, and
which price, served a request.

**Nothing is exported by default.** Strands' GenAI spans can carry prompt and
response content, and this is a SOC tool. If you enable an exporter, set
`OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_unredacted_attributes=` too — Strands'
content redaction is opt-in and **off** by default.

## Development

```bash
uv run pytest                    # 124 tests; none touch the network or a model
uv run pytest backend/tests -q
```

No test makes a live model call or contacts a real MCP server or API. The
Broker's real invoker exists and is deliberately unexercised; tests inject a
scripted invoker of the same shape.

Two pinned decisions worth knowing before changing dependencies:

- **`strands-agents==1.50.2` is pinned exactly.** Several APIs relied on here
  are real in 1.50.2 and undocumented on strandsagents.com, which documents an
  older surface. Treat the installed source as the spec and the tests as the
  contract.
- **Money is integer nano-USD per token, never a float.** Rates below $1 per
  million tokens are why: storing USD-per-Mtok as an integer truncates them to
  zero, which both mis-reports cost and disables budget gating.

## Documentation

`docs/` is a per-session record of *why* the project looks the way it does.
`docs/PROJECT_DOCS.md` is **generated** — edit the session file and re-run:

```bash
python docs/compile_docs.py
```

Start with the most recent session entry for current architecture and its open
questions.
