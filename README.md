# SmartOps SOC

A SOC triage and incident-response engine built on Strands Agents. An Analyst agent forms an investigative hypothesis; a **Task Broker** agent evaluates domain capabilities and dispatches work to specialized domain subagents; domain subagents query relevant tools (Splunk MCP Server, VirusTotal API) and report back with citable evidence and projected findings.

---

## 🚀 Current State

The Task Broker and Domain Subagents run **end-to-end** against live endpoints (Splunk BOTSv3 dataset over MCP, VirusTotal threat intelligence REST API, and Bedrock/DeepSeek LLM models).

| Component | State | Description |
|---|---|---|
| `contracts` | Working | Typed `AnalystTask`, `TaskClassification`, `SubagentMission`, `SubagentAnswer`, `SubtaskResult`, `Evidence`, `Scope`, and `Entity`. |
| Task Broker (`broker.py`) | Working | Multi-agent orchestrator dispatching domain specialists via Strands `@tool` wrappers. |
| Flat Broker (`broker_flat.py`) | Working | Baseline single-context broker used for A/B topology performance comparison. |
| `siem` (Splunk, over MCP) | Working | Connects to Splunk MCP Server. Supports CIM-compliant queries (`sourcetype`, `datamodel`, `tag`, `eventtype`) and `index` scoping. |
| `vt` (VirusTotal, REST API) | Working | Queries VirusTotal API for `domain`, `ip`, `file_hash`, and `url`. Projects findings into `VtFindings` with verdicts. |
| Domain subagents (`subagents/`) | Working | Specialized subagents running bounded turns (5-turn cap) with automatic early-stop digests. |
| Benchmark Runner (`bench.py`) | Working | Automated A/B runner comparing Arm S (Hierarchical Subagents) vs Arm F (Flat Broker) across metrics. |

---

## ⚡ Quick Start

### 1. Installation & Configuration

```bash
uv sync
cp .env.example .env          # Set model credentials & API keys
```

Set the required environment variables in your `.env`:
```ini
# Model Selection (Bedrock or DeepSeek)
AWS_BEDROCK_MODEL_ID=us.anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_REGION=us-east-1

# Splunk MCP Server Credentials
SPLUNK_MCP_URL=https://192.168.40.212:8089/services/mcp
SPLUNK_TOKEN=your_splunk_token
SMARTOPS_MCP_TLS_NO_VERIFY=splunk

# VirusTotal API Key
VT_API_KEY=your_virustotal_api_key
```

### 2. Running an Investigation CLI

```bash
uv run smartops-broker --goal "Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?" \
                       --entity domain:coinhive.com --entity host:BSTOLL-L --hours 24
```

---

## 📊 Benchmark Suite & Test Cases (`smartops.bench`)

The A/B Benchmark Runner evaluates topology efficiency (Arm S Hierarchical Subagents vs. Arm F Flat Baseline) across metrics: **wall-clock duration, input/output token usage, micro-USD cost, query count, and findings completeness**.

### Available Benchmark Cases

| Case ID | Hypothesis / Objective | Observables / Entities | Target Domains |
|---|---|---|---|
| `botsv3_coinhive` | Coinhive crypto-mining investigation | `domain:coinhive.com`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_powershell_hash` | Suspicious PowerShell payload file hash reputation & host execution | `file_hash:e2ac36894c2560d2b277ff9618b76c8c`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_c2_ip` | External C2 outbound IP reputation & network flow correlation | `ip:217.182.164.14`, `host:BSTOLL-L` | `siem`, `vt` |

### Running the Benchmark Suite

```bash
# Run A/B benchmark comparison on botsv3_coinhive (1 run per arm, $3.00 budget limit)
uv run python -m smartops.bench --cases botsv3_coinhive --arms S,F --runs 1 --budget-usd 3.00

# Run across all benchmark test cases with multiple runs
uv run python -m smartops.bench --cases botsv3_coinhive,botsv3_powershell_hash,botsv3_c2_ip --arms S,F --runs 3 --budget-usd 10.00
```

---

## 📐 Architecture & How It Works

```
Analyst Agent
    │  AnalystTask (goal + scope; no tool named)
    ▼
Task Broker ── an LLM Agent ───────────────────────────────┐
    │  Its choice of which tool to call IS the             │
    │  classification. One LLM call, not two.              │
    ▼                                                      │
investigate_siem / _edr / _vt / _ndr   ← typed @tool wrappers
    │  question: str is the model's ONLY parameter.        │
    │  scope arrives out-of-band and cannot be widened.    │
    ▼                                                      │
SubagentMission ──▶ tools_for(family) ──▶ subagent ──▶ SubtaskResult
                    (MCP + native)      (5-turn cap)    + Evidence
    │                                                      │
    └── digest + typed `gaps` back to the Broker ──────────┘
        Raw Evidence never enters a prompt.
```

### Core Architecture Principles:
1. **Context Isolation**: Subagents run in isolated prompt contexts with bounded turns (5 turns), preventing prompt history explosion.
2. **CIM-Compliant & Sourcetype Scoping**: SIEM queries target standard Splunk CIM sourcetypes (`stream:dns`, `stream:tcp`, `WinEventLog`) and data models without requiring hardcoded index strings.
3. **Structured Findings Projection**: Raw `Evidence` collected via `AfterToolCallEvent` is projected by code into typed findings (`SiemFindings`, `VtFindings`).

---

## 🧪 Testing

```bash
uv run pytest                    # Runs all 512 unit & integration tests
```
No unit tests make live model calls or contact real MCP servers.
