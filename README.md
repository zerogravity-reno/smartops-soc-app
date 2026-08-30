# SmartOps SOC

A SOC triage and incident-response engine built on Strands Agents. An Analyst
agent forms an investigative hypothesis; a **Task Broker** agent plans the fetch
work and dispatches it to specialized domain subagents; those subagents query
real tools (Splunk over MCP, VirusTotal's REST API) and report back typed
findings with citable evidence. Three **blind domain analysts** then read that
evidence — never the hypothesis — and each report a `Disposition`, assembled
into `HypothesisFindings`: the contract handed back to the Analyst Agent.

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
| Domain subagents (`subagents/`) | Working | Bounded model loop — the library default is `DEFAULT_TURNS = 14`, but the CLI's `--subagent-turns` defaults to **25** and wins. A loop that ends without an answer gets one bounded turn to report what it already retrieved. |
| Domain analysts (`subagent_analysts/`) | Working | Three **blind** analysts (identity/network/endpoint) read the `BrokerReport`'s routed evidence — never the hypothesis — and each emit a `Disposition`. `gather()` assembles the three into `HypothesisFindings`: the contract boundary handed to the separate Analyst Agent. Runs on a Bedrock **custom-imported** model (Foundation-Sec-8B-Reasoning). Enabled by passing `--hypothesis` **and** setting `SMARTOPS_ANALYST_MODEL_ARN` (see the `.env` block below); without the ARN, `--hypothesis` alone prints `analysis: skipped`. |
| Benchmark runner (`bench.py`) | Working | Single-topology runner over 11 BOTSv3 cases, reporting cost, tokens, wall clock, query count and findings completeness. |
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

# Analyst tier (blind domain analysts) — Bedrock custom-imported model.
# Required for --hypothesis to do anything; without it a run with
# --hypothesis prints "analysis: skipped" and stops there.
SMARTOPS_ANALYST_MODEL_ARN=<bedrock custom model import ARN>
```

### 2. Run an investigation

```bash
uv run smartops-broker \
  --goal "Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?" \
  --entity domain:coinhive.com --entity host:BSTOLL-L --hours 24
```

Other flags: `--since` / `--until` (absolute window), `--families`,
`--budget-usd`, `--mcp-config`, `--scripted` (no model call, nothing billed),
`--subagent-turns` (default 25), `--console-traces`, `--verbose`.

Add `--hypothesis "<claim>"` **and** set `SMARTOPS_ANALYST_MODEL_ARN` (see the
`.env` block above) to also run the **analyst tier**: three blind domain
analysts read the fetched evidence and each report a `Disposition` — see the
Architecture section below. `--hypothesis` alone, with no ARN configured (or
with `--scripted`), prints `analysis: skipped (set SMARTOPS_ANALYST_MODEL_ARN
to enable, and do not pass --scripted)` and runs nothing further.

Each run writes `report.json` and `evidence.json` to
`.smartops/runs/<task_id>/<timestamp>/`; a run with `--hypothesis` also writes
`findings.json` and `traces.json` there (see **Behaviour to know** below).

---

## 📊 Benchmark Suite (`smartops.bench`)

Measures a run's cost, token usage, wall clock, query count, index scoping and
findings completeness, and writes a `BenchmarkReport` artifact.

### Cases

| Case ID | Objective | Entities | Domains |
|---|---|---|---|
| `botsv3_coinhive` | Cryptomining domain reputation and host activity | `domain:coinhive.com`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_hdoor_tool` | Backdoor/network-scanner tool hash reputation and host activity | `file_hash:586EF56F4D…`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_c2_beacon` | Outbound C2 IP reputation and flow correlation | `ip:45.77.53.176`, `host:ABUNGST-L` | `siem`, `vt` |
| `botsv3_web_shell_url` | Web shell URL reputation and server-side access | `url:http://po18-s92-l01/swm/upload/shell.php` | `siem`, `vt` |
| `botsv3_dns_tunneling` | DNS tunnelling over resolution | `domain:a1b2c3.tunnel.malicious.net`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_mimikatz_hash` | LSASS-dumper hash and host execution | `file_hash:31d6cfe0d1…`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_phishing_domain` | Phishing domain reputation and user contact | `domain:secure-login-account.com`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_exfil_ip` | Exfiltration destination and transfer volume | `ip:104.20.208.59`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_ransomware_note` | Ransomware payload hash reputation | `file_hash:8f4e2b1091…`, `host:BSTOLL-L` | `siem`, `vt` |
| `botsv3_suspicious_user_auth` | Anomalous authentication for a user | `user:bostoll`, `host:BSTOLL-L` | `siem` |
| `botsv3_hard_multivector` | Full-spectrum compromise correlation across domain, IP, hash and auth | `user:bostoll`, `host:BSTOLL-L`, `domain:coinhive.com`, `ip:217.182.164.14`, `file_hash:e2ac36894c…` | `siem`, `vt` |

Seven cases (`SYNTHETIC_INDICATOR_CASES` in `bench.py`) are built on indicators
BOTSv3 does not contain — kept anyway because they exercise the empty-result
path and entity-kind routing coverage the other cases don't. What's actually
wrong per case is not uniform:

- `botsv3_web_shell_url`, `botsv3_dns_tunneling`, `botsv3_ransomware_note` —
  genuinely synthetic: the host/URL, the DNS label, and the hash are all
  placeholders (sequential hex, `a1b2c3`-style) absent from BOTSv3.
- `botsv3_exfil_ip` — one digit off a real BOTSv3 row (`104.20.208.59` vs.
  BOTSv3's `104.20.209.59`, a DNS response for coinhive.com, not an exfil
  destination).
- `botsv3_mimikatz_hash` — **mislabelled**, not merely synthetic: the hash is
  the NTLM hash of an *empty password*, not Mimikatz. A correct system returns
  `inconclusive`; the case name implies a credential dumper.
- `botsv3_phishing_domain` — **not synthetic**: `secure-login-account.com` is
  a real flagged domain (our saved VirusTotal lookup has it at `mal=14`). It is
  *absent from BOTSv3*, which is a different claim — this is a VT-only case
  that expects no SIEM rows.
- `botsv3_hard_multivector` — **partly synthetic**: the file hash
  `e2ac36894c2560d2b277ff9618b76c8c` is absent from BOTSv3 (VT NOT FOUND), but
  the domain `coinhive.com` and the IP `217.182.164.14` are both genuine
  BOTSv3 indicators.

See the `SYNTHETIC_INDICATOR_CASES` docstring in `bench.py` for the full
per-case detail.

### Running

```bash
# One case, one run, real model calls
uv run python -m smartops.bench --cases botsv3_coinhive --runs 1 --budget-usd 10

# Offline: exercises the whole pipeline, calls no model, bills nothing
uv run python -m smartops.bench --cases botsv3_coinhive --runs 1 --scripted

# Every case, three runs each, JSON artifact
uv run python -m smartops.bench --runs 3 --budget-usd 10 \
  --cases botsv3_coinhive,botsv3_hdoor_tool,botsv3_c2_beacon,botsv3_web_shell_url,botsv3_dns_tunneling,botsv3_mimikatz_hash,botsv3_phishing_domain,botsv3_exfil_ip,botsv3_ransomware_note,botsv3_suspicious_user_auth,botsv3_hard_multivector \
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
                   (MCP + native)     (≤25 turns)    + Evidence
    │                                                       │
    └── digest + typed `gaps` back to the Broker ───────────┘
        Raw Evidence never enters a prompt.
        │
        ▼
   BrokerReport ─▶ route() ─▶ 3 blind domain analysts
                              (identity / network / endpoint;
                               Foundation-Sec-8B, invoke_model)
                                          │
                                          ▼
                              HypothesisFindings ┄┄▶ Analyst Agent
                              (findings.json)        (contract boundary —
                                                       separate component)
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

Deeper detail lives in [`docs/architecture.md`](docs/architecture.md) — the single
map of the system — and its three `docs/confluence-*.md` per-subsystem companions.
Decisions of record are in [`docs/PROJECT_DOCS.md`](docs/PROJECT_DOCS.md), which
is **compiled** from `docs/sessions/` — edit a session file and re-run
`python docs/compile_docs.py`, never edit it directly.

### Behaviour to know

A few things a new engineer would otherwise trip over. Depth is in
[`docs/architecture.md`](docs/architecture.md).

| Behaviour | Detail |
|---|---|
| Analyst sampling | **Greedy** (`temperature=0`, `DEFAULT_TEMPERATURE` in `subagent_analysts/model.py`) — deliberately not the model's shipped `0.6`. Verdicts are byte-reproducible on a warm model copy. |
| Analyst billing | Per **Custom Model Unit per minute**, not per token (`smartops/analyst_cost.py`) — absent from `Budget`. Set `SMARTOPS_ANALYST_CMU_COUNT` to get a dollar figure. |
| Run artifacts | Two files always: `report.json`, `evidence.json`. A run with `--hypothesis` **and** a configured `SMARTOPS_ANALYST_MODEL_ARN` also writes `findings.json` and `traces.json` — four files total. `traces.json` holds the analysts' reasoning traces — local-audit only, never on the wire or on a span. |
| Output contract | `contracts/schemas/hypothesis-findings.v1.schema.json` is the published `HypothesisFindings` shape — regenerated by `contracts/schemas/generate.py`, drift-checked by a test. |
| `subagent_analysts/shown.py` | **Not the pipeline.** The hypothesis-shown arm, kept only for `blind_compare`'s A/B measurement. |
| Tracing | Two OTel traces per run — fetch and analyze — joined on `task_id` + `hypothesis_id` + `run_id`. `--console-traces` prints them. |
| Logging | **`--verbose` is required to see any warning at all.** The default log level is `ERROR`, which discards every `logger.warning` in the codebase. |

---

## 🧪 Testing

```bash
uv run pytest        # 848 tests, from the workspace root
```

`[tool.pytest.ini_options]` lives at the workspace root with
`asyncio_mode = "auto"` and `testpaths` covering both members, so a bare run
from the root collects everything.

No test makes a live model call or contacts a real MCP server.
`DeprecationWarning`, `PendingDeprecationWarning` and `UserWarning` are configured
as errors, so a deprecated SDK call fails the suite rather than passing silently.
