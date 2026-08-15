# SmartOps SOC

A SOC triage and incident-response engine built on Strands Agents. An Analyst
agent forms an investigative hypothesis; a **Task Broker** agent plans the fetch
work and dispatches it to specialized domain subagents; those subagents query
real tools (Splunk over MCP, VirusTotal's REST API) and report back typed
findings with citable evidence.

---

## 🚀 Current State

The Task Broker and its domain subagents run **end-to-end** against live
endpoints: the Splunk BOTSv3 dataset over MCP, the VirusTotal REST API, and
Bedrock (or DeepSeek) for the model.

| Component | State | Notes |
|---|---|---|
| `contracts` | Working | Typed `AnalystTask`, `FetchPlan`/`FetchStep`/`CompletionRule`, `SubagentMission`, `SubagentAnswer`, `SubtaskResult`, `Evidence`, `Scope`, `Entity`. |
| Task Broker (`broker.py`) | Working | An LLM agent. Plans via `plan_fetch`, then dispatches domain specialists through typed `@tool` wrappers. |
| `siem` (Splunk, over MCP) | Working | CIM-compliant predicates (`sourcetype`, `datamodel`, `tag`, `eventtype`) or an allowlisted `index=`. `index=*` is refused. |
| `vt` (VirusTotal, REST) | Working | `domain`, `ip`, `file_hash`, `url`. Native tools — needs no MCP server. |
| `ndr` / `edr` | Not wired | No MCP server configured. Withheld from the Broker's toolset, so they are neither planned nor dispatched. |
| Domain subagents (`subagents/`) | Working | Bounded model loop (`DEFAULT_TURNS = 14`). A loop that ends without an answer gets one bounded turn to report what it already retrieved. |
| Benchmark runner (`bench.py`) | Working | Single-topology runner over 10 BOTSv3 cases, reporting cost, tokens, wall clock, query count and findings completeness. |
| Skill pack (`skills/`) | Off by default | `superman-splunk` reference pack for the `siem` subagent. Opt in per run with `--skills`. |

> **Note on history.** A flat-broker baseline (`broker_flat.py`) and an Arm S vs
> Arm F comparison existed and were **removed** in `2dc5ff9`: the subagent
> topology is the design, so the baseline had no job left. Any document
> describing an "Arm F" or a `--arms` flag predates that and does not describe
> this tree.

---

## ⚡ Quick Start

### 1. Install and configure

```bash
uv sync
cp .env.example .env          # then fill in credentials
```

Nothing in `.env` is strictly required: with none of it set the CLI still runs,
every family reports honestly why it cannot answer, and the process exits 0.

```ini
# Model provider — Bedrock is primary, DeepSeek is the alternative
AWS_BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-5-20250929-v1:0
AWS_REGION=us-east-1

# Splunk MCP server
SPLUNK_MCP_URL=https://<host>:8089/services/mcp
SPLUNK_TOKEN=<token>
SMARTOPS_MCP_TLS_NO_VERIFY=splunk

# VirusTotal
VT_API_KEY=<key>
```

### 2. Run an investigation

```bash
uv run smartops-broker \
  --goal "Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?" \
  --entity domain:coinhive.com --entity host:BSTOLL-L --hours 24
```

Other flags: `--since` / `--until` (absolute window), `--families`,
`--budget-usd`, `--mcp-config`, `--scripted` (no model call, nothing billed),
`--console-traces`, `--verbose`.

Each run writes `report.json` and `evidence.json` to
`.smartops/runs/<task_id>/<timestamp>/`.

---

## 📊 Benchmark Suite (`smartops.bench`)

Measures a run's cost, token usage, wall clock, query count, index scoping and
findings completeness, and writes a `BenchmarkReport` artifact.

### Cases

| Case ID | Objective | Entities | Domains |
|---|---|---|---|
| `botsv3_coinhive` | Cryptomining domain reputation and host activity | `domain:coinhive.com`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_powershell_hash` | Suspicious PowerShell payload hash and execution | `file_hash:e2ac36894c…`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_c2_ip` | Outbound C2 IP reputation and flow correlation | `ip:217.182.164.14`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_web_shell_url` | Web shell URL reputation and server-side access | `url:http://po18-s92-l01/swm/upload/shell.php` | `siem`, `vt` |
| `botsv3_dns_tunneling` | DNS tunnelling over resolution | `domain:a1b2c3.tunnel.malicious.net`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_mimikatz_hash` | LSASS-dumper hash and host execution | `file_hash:31d6cfe0d1…`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_phishing_domain` | Phishing domain reputation and user contact | `domain:secure-login-account.com`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_exfil_ip` | Exfiltration destination and transfer volume | `ip:104.20.208.59`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_ransomware_note` | Ransomware payload hash reputation | `file_hash:8f4e2b1091…`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_suspicious_user_auth` | Anomalous authentication for a user | `user:bostoll`, `host:BSTOLL-L` | `siem` |

Several cases carry **synthetic indicators** (the tunnelling domain, the
phishing domain, the ransomware hash) that do not appear in BOTSv3. They
exercise the pipeline and the empty-result path; they are not expected to
return telemetry.

### Running

```bash
# One case, one run, real model calls
uv run python -m smartops.bench --cases botsv3_coinhive --runs 1 --budget-usd 10

# Offline: exercises the whole pipeline, calls no model, bills nothing
uv run python -m smartops.bench --cases botsv3_coinhive --runs 1 --scripted

# Every case, three runs each, JSON artifact
uv run python -m smartops.bench --runs 3 --budget-usd 10 \
  --cases botsv3_coinhive,botsv3_powershell_hash,botsv3_c2_ip,botsv3_web_shell_url,botsv3_dns_tunneling,botsv3_mimikatz_hash,botsv3_phishing_domain,botsv3_exfil_ip,botsv3_ransomware_note,botsv3_suspicious_user_auth \
  --out docs/benchmark.json

# With the superman-splunk skill pack attached to the siem subagent
uv run python -m smartops.bench --cases botsv3_coinhive --runs 1 --skills
```

**A report whose `scripted` field is `true` measured the plumbing, not the
system** — it records zero cost and zero tokens by construction. Check that
field before quoting any figure from an artifact.

The skill pack is off unless `--skills` is passed. It is pinned per run rather
than inherited from the environment, because a run that silently had it on
reports token and cost figures no other run can be compared against — so the
report records which way it ran.

---

## 📐 Architecture

```
Analyst Agent
    │  AnalystTask (goal + scope; no tool named)
    ▼
Task Broker ── an LLM agent ───────────────────────────────┐
    │  plan_fetch() authors a FetchPlan first, so code      │
    │  can validate it; then its choice of which tool to    │
    │  call IS the classification. One LLM call, not two.   │
    ▼                                                       │
investigate_siem / _vt  ← typed @tool wrappers, one per     │
    │  CONFIGURED family. `question` is the model's only    │
    │  parameter; scope arrives out-of-band and cannot be   │
    │  widened.                                             │
    ▼                                                       │
SubagentMission ─▶ tools_for(family) ─▶ subagent ─▶ SubtaskResult
                   (MCP + native)      (≤14 turns)   + Evidence
    │                                                       │
    └── digest + typed `gaps` back to the Broker ───────────┘
        Raw Evidence never enters a prompt.
```

**Principles**

1. **The Broker is an agent, not an orchestrator.** Its choice of tool *is* the
   classification, which is why there is no separate classifier call.
2. **The plan is explicit and code-evaluated.** `plan_fetch` emits a `FetchPlan`
   before any dispatch; `evaluate_step()` applies each `CompletionRule`. The
   model never ticks its own boxes.
3. **Context isolation.** Each subagent runs its own prompt context and returns
   a compact digest. Raw evidence is assembled by code and never re-enters a
   model's context.
4. **Preconditions are facts, not judgements.** A family with no entity of the
   kind it needs, and a family with no tools behind it, are both refused before
   a model is asked — without taking any decision away from the Broker.
5. **Findings are projected by code.** Tool output captured via
   `AfterToolCallEvent` is projected into typed `SiemFindings` / `VtFindings`;
   citations are minted by code, never authored by the model.
6. **Absence is reported honestly.** `confirmed_empty` means the data was looked
   for and is not there. A subagent that failed to answer does not set it, and
   neither does a step scoped to a CIM category nobody ever queried — "we asked
   and found nothing" is a finding, "we never asked" is a gap.
7. **A step is judged on what it asked for.** `CompletionRule.categories` scopes
   a `siem` step to the CIM categories it owns, so splitting siem into several
   steps gives code something it can actually evaluate per step.

Deeper detail lives in [`docs/agent_architecture.md`](docs/agent_architecture.md).
Decisions of record are in [`docs/PROJECT_DOCS.md`](docs/PROJECT_DOCS.md), which
is **compiled** from `docs/sessions/` — edit a session file and re-run
`python docs/compile_docs.py`, never edit it directly.

---

## 🧪 Testing

```bash
uv run pytest        # 513 tests, from the workspace root
```

`[tool.pytest.ini_options]` lives at the workspace root with
`asyncio_mode = "auto"` and `testpaths` covering both members, so a bare run
from the root collects everything.

No test makes a live model call or contacts a real MCP server.
`DeprecationWarning` and `PendingDeprecationWarning` are configured as errors,
so a deprecated SDK call fails the suite rather than passing silently.
