# Reference: SPL Performance Tuning & Guardrails (`performance_optimization`)

Executing fast, cost-effective Splunk searches requires strict adherence to index boundaries, index-time field filtering, efficient command pipeline construction, `tstats` optimization, and memory resource management.

This reference provides engineering rules, performance patterns, troubleshooting steps, and execution guardrails to eliminate slow searches, avoid query timeouts, and adhere to `smartops.guards.IndexScopeGuard` safety constraints.

---

## 1. Golden Rules of Search Performance

### Rule 1: NEVER Use Unscoped `index=*`
- **Why:** `index=*` forces Splunk indexers to search every index across the deployment (security logs, internal metrics, deployment debug logs, proxy dumps). On enterprise environments or multi-gigabyte datasets, `index=*` consumes tens of gigabytes of disk I/O and takes minutes to respond.
- **Guardrail:** SmartOps SOC App automatically enforces `IndexScopeGuard` on all SIEM searches. Searches using `index=*` or missing explicit index allowlist entries (e.g. `index=botsv3`) are cancelled before execution.
- **Correct Pattern:**
  ```spl
  index=botsv3 sourcetype=stream:dns query="*coinhive.com*"
  ```
- **Incorrect Pattern:**
  ```spl
  index=* query="*coinhive.com*"  # REJECTED BY INDEX SCOPE GUARD
  ```

### Rule 2: Filter by Sourcetype and Host Early
- **Why:** Indexers partition data by index, sourcetype, and host at ingestion time. Specifying `sourcetype=` reduces scanned TSIDX bucket files by up to 90%.
- **Correct Pattern:**
  ```spl
  index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1
  ```
- **Incorrect Pattern:**
  ```spl
  index=botsv3 EventCode=1  # Scans every sourcetype in botsv3 index
  ```

### Rule 3: Avoid Leading Wildcards (`*text`)
- **Why:** Splunk's lexicon index (TSIDX) operates on tokenized prefixes. Searching `query="*coinhive.com*"` cannot use lexicon index lookups and triggers a full raw-text scan of matching event buckets.
- **Optimization Strategy:**
  - If searching for a domain, specify explicit host components: `query="coinhive.com"` or `query="*.coinhive.com"`.
  - Use `domain` or `site` field extraction predicates rather than unanchored raw text searches.
  - If a wildcard is required, place it at the end of a prefix string (`coinhive*`).

### Rule 4: Specify Time Boundaries explicitly
- **Why:** Searching without explicit time bounds defaults to searching all historical buckets or the last 24 hours of data.
- **Rule:** Subagents MUST pass explicit `earliest_time` and `latest_time` parameters in tool calls using epoch timestamps.

---

## 2. High-Performance Index Scans with `tstats`

`tstats` operates purely on indexed fields stored in TSIDX files without reading raw event journal files from disk. It runs up to **100x faster** than standard `stats`.

### When to Use `tstats`
- Counting total events by index, sourcetype, or host.
- Summarizing high-volume data models (Network Traffic, Data Access).
- Listing available sourcetypes or hosts within a time window.

### `tstats` Syntax Templates

#### Template A: List All Available Sourcetypes in `index=botsv3`
```spl
| tstats count where index=botsv3 by sourcetype | sort - count
```

#### Template B: Summarize Outbound Traffic Volume by Host
```spl
| tstats sum(All_Traffic.bytes_out) as total_bytes_out where index=botsv3 sourcetype=pan:traffic by All_Traffic.src
| sort - total_bytes_out
```

#### Template C: Count Process Executions per Host in Window
```spl
| tstats count where index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" by host, EventCode
```

#### Template D: Distinct Count of Unique Domains per Client
```spl
| tstats dc(dns.query) as unique_domains where index=botsv3 sourcetype=stream:dns by dns.src
```

---

## 3. Fast Mode vs. Verbose Mode vs. Smart Mode

Splunk operates in three search modes that affect what data is parsed and returned:

| Mode | Field Extraction Behavior | Best Used For |
|---|---|---|
| **Fast Mode** (`search_mode=fast`) | Extracts ONLY fields required by the SPL query. Disables unquoted key-value discovery. | Production investigations, automated subagents, performance-critical searches. |
| **Smart Mode** (`search_mode=smart`) | Default mode. Switches between Fast mode (for transforming searches) and Verbose mode (for event searches). | General interactive analyst searches. |
| **Verbose Mode** (`search_mode=verbose`) | Extracts ALL fields and returns full raw event structures for every event. | Initial manual exploration when field names are completely unknown. |

**Subagent Requirement:** Subagents MUST run searches in `Fast` or `Smart` mode.

---

## 4. Replacing Heavy Joins & Appends with `stats`

In SPL, using `join` or `append` is slow and subject to subsearch row limits (10,000 rows max). Replace joins with unified `stats` queries whenever possible.

### Slow Join Pattern
```spl
# Poor performance: joins DNS and Sysmon results
index=botsv3 sourcetype=stream:dns query="*coinhive.com*"
| join src_ip [
  search index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1
  | rename SourceIp as src_ip
]
```

### High-Performance `stats` Replacement Pattern
```spl
# Optimal performance: single-pass search with eval & stats
index=botsv3 (sourcetype=stream:dns query="*coinhive.com*") OR (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1)
| eval client_ip = coalesce(src_ip, SourceIp)
| stats values(query) as dns_queries, values(Image) as processes, values(CommandLine) as cmds by client_ip
```

---

## 5. Bounding Result Sets (`head`, `limit`, `sample`)

Returning hundreds of thousands of events exhausts model token budgets and causes memory pressure. Always bound result sizes:

### Bounding Patterns

```spl
# Bound transforming output to top 20 rows
index=botsv3 sourcetype=stream:http
| stats count by site, uri
| sort - count
| head 20

# Use top command limit
index=botsv3 sourcetype=stream:dns
| top limit=10 query by src_ip

# Sample high-volume log streams (e.g. 1 in 100 events)
index=botsv3 sourcetype=pan:traffic sample=100
| stats count by action
```

---

## 6. Subsearch Optimization & Limits

Subsearches are searches enclosed in square brackets `[ search ... ]` that execute prior to the main pipeline.

### Default Limits
- `maxout`: Subsearches return at most 10,000 rows.
- `maxtime`: Subsearches time out after 60 seconds.
- `subsearch_format`: Subsearches format their results as boolean OR clauses passed to the main query.

### Subsearch Performance Rules
1. Always apply `stats` and `fields` inside the subsearch to return only the necessary match keys.
2. Deduplicate subsearch outputs (`| stats count by field | fields field`) to prevent sending redundant search terms to the parent query.
3. If a subsearch exceeds 10,000 rows, do NOT use a subsearch — use a multi-sourcetype `stats` query instead.

---

## 7. IndexScopeGuard Enforcement & Error Recovery

`smartops.guards.IndexScopeGuard` is an automated security hook attached to SIEM tool invocations.

### Guard Behavior
- Intercepts all SPL tool calls before they reach the Splunk MCP server.
- Verifies that the SPL query explicitly references an allowed index (e.g., `index=botsv3`).
- If `index=*` or no allowed index is found, `IndexScopeGuard` cancels the tool call and returns a structured error tool result:
  `"Tool call cancelled by IndexScopeGuard: SPL query must target an allowlisted index (allowed: ['botsv3']). Found query missing valid index predicate."`

### Error Recovery Procedure for SIEM Subagents
1. **Read the guard error message.**
2. **Prepend `index=botsv3`** to the beginning of your search string.
3. **Re-execute the tool call.** Do not repeat the rejected search string.

---

## 8. Performance Optimization Summary Matrix

| Optimization Goal | Poor SPL Pattern | Optimized SPL Pattern | Speedup Factor |
|---|---|---|---|
| **Index Scoping** | `index=* query="coinhive.com"` | `index=botsv3 sourcetype=stream:dns query="coinhive.com"` | 10x - 50x |
| **Sourcetype List** | `index=botsv3 \| dedup sourcetype \| table sourcetype` | `\| tstats count where index=botsv3 by sourcetype` | 50x - 100x |
| **Event Limit** | `index=botsv3 sourcetype=stream:http` | `index=botsv3 sourcetype=stream:http \| head 50` | 5x - 20x |
| **Wildcard Search** | `query="*coinhive.com*"` | `query="coinhive.com" OR query="*.coinhive.com"` | 5x - 15x |
| **Field Reduction** | `index=botsv3 sourcetype=stream:http` | `index=botsv3 sourcetype=stream:http \| fields _time, src_ip, site, uri` | 2x - 5x |
| **Join Elimination** | `... \| join ip [search ...]` | `(search1) OR (search2) \| stats values(...) by ip` | 10x - 30x |
| **Subsearch Format** | `[search index=botsv3]` | `[search index=botsv3 \| stats count by ip \| fields ip]` | 3x - 10x |
