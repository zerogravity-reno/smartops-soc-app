# Superman Splunk Reference Skill Pack (superman-splunk)

`superman-splunk` is a specialized, production-grade reference skill pack for Splunk SIEM data retrieval, search optimization, Common Information Model (CIM) mapping, and SOC threat hunting within SmartOps SOC App.

This skill pack is designed for lazy-loading via the `read_reference(name: str)` tool. Analysts and SIEM subagents should consult the routing table below to fetch specific technical guidance on-demand without inflating prompt context during initial turns.

---

## Skill Pack Specification & Metadata

- **Skill Name:** `superman-splunk`
- **Version:** 1.0.0
- **License:** MIT License (Vended Reference Pack)
- **Target Platform:** Splunk Enterprise 9.x+ / Splunk Cloud / BOTSv3 Dataset
- **Primary Domain:** SIEM (Security Information & Event Management)
- **Purpose:** Maximize SIEM query precision, enforce CIM compliance, eliminate unindexed `index=*` scans, accelerate threat hunting investigations, and provide on-demand reference documentation.

---

## Reference Routing Table

Use `read_reference(name)` with any of the reference identifiers below to load detailed reference documentation into context:

| Reference Name | Subject / Description | When to Consult |
|---|---|---|
| `spl_syntax` | **SPL Query Syntax & Aggregation**<br>Comprehensive guide to Splunk Search Processing Language (SPL), including commands (`search`, `stats`, `eval`, `timechart`, `rex`, `rename`, `table`, `where`, `transaction`, `top`, `rare`, `streamstats`, `eventstats`, `lookup`), functions, macros, multi-value fields, and subsearches. | Consult when authoring complex queries, constructing aggregations, writing regular expressions, formatting search outputs, or using advanced streaming functions. |
| `cim_data_models` | **Common Information Model (CIM) Mapping**<br>Field mappings and standard schemas for Splunk CIM data models: Authentication, Network Resolution (DNS), Network Traffic (Flows), Endpoint Processes, Web, Malware, and Filesystem. Includes vendor log mapping tables. | Consult when mapping raw log fields to standardized CIM names, validating query field schemas, projecting SIEM findings, or resolving cross-vendor log formats. |
| `botsv3_sourcetypes` | **BOTSv3 Dataset Architecture & Sourcetypes**<br>Complete reference for Boss of the SOC v3 (BOTSv3) telemetry: `stream:dhcp`, `stream:dns`, `stream:http`, Sysmon Event IDs (1 to 26), `WinEventLog:Security` (4624, 4625, 4688, 4720, etc.), `suricata`, `pan:traffic`, and AWS logs. | Consult when selecting sourcetypes, filtering by Windows Event IDs, investigating BOTSv3 host/user telemetry, resolving raw log structures, or mapping host identities. |
| `investigation_playbooks` | **SOC Investigation & Threat Hunting Playbooks**<br>Step-by-step detection strategies and search templates for browser cryptomining (e.g., Coinhive), C2 beaconing, credential dumping (Mimikatz), lateral movement (PsExec/WMI), ransomware, persistence, and data exfiltration. | Consult when translating investigation goals into structured multi-step retrieval plans, conducting threat hunting, or executing systematic SOC investigations. |
| `performance_optimization` | **SPL Performance Tuning & Guardrails**<br>Guidelines for fast search execution: index and sourcetype pre-filtering, fast-mode vs verbose-mode, `tstats` utilization, avoiding leading wildcards, time window constraints, join replacements, and row count limits. | Consult when optimizing slow searches, refactoring wildcard queries, avoiding time range timeouts, replacing heavy joins, or ensuring index boundary compliance. |

---

## Architecture & Lazy-Loading Design

### Why Lazy-Loading is Necessary
Loading all reference materials eagerly into the SIEM system prompt on turn 1 would inject over 25,000 tokens of documentation into context. Across a 14-turn investigation loop, re-sending that context on every turn would add over 350,000 input tokens (~$0.85 per run) and reduce reasoning performance due to context bloat.

By injecting only this concise routing table into the system prompt and exposing `read_reference(name: str)` as a `@tool`, the SIEM subagent consumes less than 1,200 tokens initially and loads only the specific reference file needed for the task at hand.

```
+-------------------------------------------------------------+
| SIEM Subagent System Prompt                                 |
| - Role & Budget                                             |
| - superman-splunk Routing Table                             |
+-------------------------------------------------------------+
                               |
                               v (LLM needs SPL function syntax)
              Calls read_reference("spl_syntax")
                               |
                               v
+-------------------------------------------------------------+
| read_reference Tool Result: spl_syntax.md (Loaded on demand)|
+-------------------------------------------------------------+
```

---

## Lazy-Loading Usage Guidelines for SIEM Subagents

1. **Do not load all references upfront.** Read only the reference file needed for the immediate step in your investigation.
2. **First step in unfamiliar domains:** If searching sourcetypes or data models for the first time, consult `botsv3_sourcetypes` or `cim_data_models`.
3. **When constructing complex queries:** Use `spl_syntax` for command syntax, functions, and regular expressions. Use `performance_optimization` for index scoping and search speed.
4. **When executing threat investigations:** Follow the specific hunting procedures and multi-stage SPL queries outlined in `investigation_playbooks`.
5. **Error handling:** If `read_reference` returns an invalid name error, check the routing table above for the exact reference identifier.

---

## Verification & Compliance

All SPL examples in this skill pack conform to Splunk 9.x+ best practices and adhere to the strict index scoping rules enforced by `smartops.guards.IndexScopeGuard`.
