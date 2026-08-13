# Reference: SPL Query Syntax & Aggregation Guide (`spl_syntax`)

This reference provides exhaustive documentation of Splunk Search Processing Language (SPL) commands, pipeline architecture, functions, evaluation operators, streaming commands, and aggregation patterns for SOC analysts and SIEM subagents.

---

## 1. Search Pipeline Architecture & Execution Order

Splunk executes searches sequentially through a streaming and transforming pipeline:

```
[Index & TSIDX Search] -> [Streaming Commands] -> [Transforming Commands] -> [Post-Filtering] -> [Formatting]
```

### Core Execution Rules
1. **Pre-filter Early:** Place `index=`, `sourcetype=`, `host=`, and field equality predicates at the very beginning of the pipeline before the first pipe (`|`).
2. **Limit Raw Event Passing:** Use `fields` or transforming commands (`stats`, `chart`) early to drop unnecessary raw log data before sending rows downstream.
3. **Avoid Streaming Filtering After Transform:** Filtering using `search` or `where` after `stats` operates on summarized rows, not raw events.

---

## 2. Core Search Commands Reference

### `search`
Filters raw events or pipeline results based on boolean expressions and key-value matches.
- **Syntax:** `search <predicate1> <predicate2> [AND|OR|NOT] ...`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:dns query="*coinhive.com*"
  index=botsv3 sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10
  ```

### `stats`
Calculates summary statistics across events grouped by specified fields.
- **Supported Functions:**
  - `count`: Total count of matching events.
  - `count(field)`: Count of events where `field` is non-null.
  - `dc(field)` / `distinct_count(field)`: Count of unique values in `field`.
  - `values(field)`: Unique list of values in `field` (sorted).
  - `list(field)`: List of all values in `field` (in event order, capped at 100).
  - `earliest(_time)` / `latest(_time)`: Earliest or latest timestamp.
  - `earliest_time(field)` / `latest_time(field)`: Field value associated with earliest/latest event.
  - `sum(field)`, `avg(field)`, `min(field)`, `max(field)`, `median(field)`, `stdev(field)`, `perc<N>(field)`.
  - `mode(field)`: Most frequent value of `field`.
  - `range(field)`: Difference between max and min numeric value.
- **Syntax:** `stats <function>(<field>) [as <alias>] by <by_clause_fields>`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:http
  | stats count, values(uri) as uris, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, dest_ip

  index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1
  | stats count, values(CommandLine) as cmds by Image, ParentImage, User
  ```

### `eval`
Calculates expressions and assigns results to new fields or overwrites existing fields.
- **Syntax:** `eval <field>=<expression>`
- **Complete Function Categories:**
  - **String Manipulation:**
    - `lower(s)` / `upper(s)`: Convert string case.
    - `len(s)`: Character length of string.
    - `substr(s, start, length)`: Extract substring (1-indexed).
    - `replace(s, regex, replacement)`: Regex string replacement.
    - `trim(s, [chars])` / `ltrim(s)` / `rtrim(s)`: Strip whitespace or characters.
    - `split(s, delimiter)`: Split string into multi-value field array.
    - `join(array, delimiter)`: Join multi-value array into single string.
  - **Conditional & Logical:**
    - `if(condition, true_val, false_val)`: Binary branch.
    - `case(cond1, val1, cond2, val2, ...)`: Multi-branch conditional.
    - `coalesce(val1, val2, val3, ...)`: Returns first non-null argument.
    - `isnull(val)` / `isnotnull(val)`: Check for null/missing values.
    - `isnum(val)` / `isstr(val)`: Type assertions.
  - **Type & Time Formatting:**
    - `tostring(val, [format])`: Convert to string (format: `"commas"`, `"duration"`, `"hex"`).
    - `tonumber(val)`: Parse number from string.
    - `strftime(time_epoch, format_str)`: Format epoch seconds into human-readable timestamp (e.g. `"%Y-%m-%d %H:%M:%S UTC"`).
    - `strptime(date_str, format_str)`: Parse human-readable timestamp into epoch seconds.
    - `now()`: Return current epoch time.
  - **Network & IP Helper Functions:**
    - `cidrmatch("192.168.0.0/16", ip_address)`: Evaluate if IP resides in CIDR block.
    - `relative_time(time, relative_expr)`: Calculate epoch offset (e.g. `relative_time(_time, "-1h")`).
  - **Mathematical & Cryptographic:**
    - `round(val, decimals)` / `floor(val)` / `ceil(val)`: Rounding operations.
    - `abs(val)` / `pow(val, exp)` / `sqrt(val)`: Basic math.
    - `md5(string)` / `sha256(string)` / `sha512(string)`: Calculate cryptographic hashes.
- **Examples:**
  ```spl
  | eval is_internal=if(cidrmatch("192.168.0.0/16", src_ip) OR cidrmatch("10.0.0.0/8", src_ip), "True", "False")
  | eval duration_sec = round(end_time - start_time, 2)
  | eval epoch_readable = strftime(_time, "%Y-%m-%d %H:%M:%S UTC")
  | eval action_clean = case(status==200, "success", status==404, "not_found", status>=500, "server_error", 1==1, "other")
  ```

### `timechart`
Creates a time series aggregation table for plotting or trend analysis over time buckets.
- **Syntax:** `timechart span=<interval> <function>(<field>) [by <split_by_field>]`
- **Interval Options:** `1s`, `10s`, `1m`, `5m`, `1h`, `1d`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:dns query="*.com"
  | timechart span=1h count by query limit=10 useother=f

  index=botsv3 sourcetype=WinEventLog:Security EventCode=4625
  | timechart span=15m count by TargetUserName
  ```

### `streamstats`
Calculates cumulative or windowed statistics over streaming events as they arrive, preserving individual raw events.
- **Syntax:** `streamstats [window=<N>] [current=<t|f>] <function>(<field>) [by <group_fields>]`
- **Examples:**
  ```spl
  # Calculate delta time between consecutive network connections
  index=botsv3 sourcetype=stream:tcp src_ip="10.0.1.42"
  | streamstats window=2 current=f last(_time) as prev_time by dest_ip
  | eval delta_sec = _time - prev_time
  | table _time, src_ip, dest_ip, delta_sec
  ```

### `eventstats`
Calculates summary statistics across all events in the search results and attaches the aggregated metrics to every event without collapsing the rows.
- **Syntax:** `eventstats <function>(<field>) [by <group_fields>]`
- **Examples:**
  ```spl
  # Calculate total bandwidth per host and compare each request to the average
  index=botsv3 sourcetype=stream:http
  | eventstats avg(bytes_out) as avg_bytes by src_ip
  | eval is_anomaly = if(bytes_out > (avg_bytes * 5), "High", "Normal")
  | where is_anomaly == "High"
  ```

### `rex`
Extracts new fields using regular expressions with named capture groups `(?<field_name>regex_pattern)`.
- **Syntax:** `rex [field=<target_field>] "(?<capture_name>pattern)"`
- **Options:** `mode=sed` (in-line text replacement), `max_match=<N>`.
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:http
  | rex field=uri "coinhive(?:[.]min)?[.]js[?]pool=(?<mining_pool>[^&]+)"
  | stats count by mining_pool, src_ip

  index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1
  | rex field=CommandLine "-enc(?:odedcommand)?\s+(?<b64_payload>[A-Za-z0-9+/=]+)"

  # SED mode regex replacement
  | rex field=User mode=sed "s/AzureAD\\\\//g"
  ```

### `top` / `rare`
Finds the most or least frequent values of specified fields. Automatically calculates count and percentage.
- **Syntax:** `top limit=<N> showperc=<t|f> <fields> [by <group_fields>]`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:dns
  | top limit=15 query by src_ip

  index=botsv3 sourcetype=WinEventLog:Security EventCode=4688
  | rare limit=10 NewProcessName by ComputerName
  ```

### `table` / `fields`
Formats output by selecting specific columns (`table`) or retaining/removing fields in streaming pipeline (`fields`).
- **Syntax:** `table <field1> <field2> ...` | `fields [+|-] <field1> <field2> ...`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:dns query="*coinhive*"
  | table _time, src_ip, query, query_type, reply_code
  ```

### `rename`
Renames fields for cleaner output or CIM compliance.
- **Syntax:** `rename <old_name> as <new_name>`
- **Examples:**
  ```spl
  | rename src_ip as src, dest_ip as dest, query as domain
  ```

### `where`
Filters search results using `eval`-style Boolean expressions. Unlike `search`, `where` is case-sensitive for string comparisons and requires quote marks around string literals.
- **Syntax:** `where <boolean_expression>`
- **Examples:**
  ```spl
  | stats count by src_ip
  | where count > 100 AND src_ip != "127.0.0.1"
  ```

### `transaction`
Groups related events into a single transaction object based on common fields, start/end matching, or max pause/duration.
- **Syntax:** `transaction <field_list> [maxspan=<time>] [maxpause=<time>] [startswith=<string>] [endswith=<string>]`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:http
  | transaction src_ip dest_ip maxspan=30m maxpause=5m
  | table duration, eventcount, src_ip, dest_ip, uri
  ```

### `lookup`
Enriches events using static CSV lookups or KV Store collections.
- **Syntax:** `lookup <lookup_name> <match_field> OUTPUT <output_field1> ...`
- **Examples:**
  ```spl
  index=botsv3 sourcetype=stream:dns
  | lookup alexa_top1k domain as query OUTPUT rank
  | where isnull(rank)
  ```

---

## 3. Subsearches and Aggregations

Subsearches run enclosed in square brackets `[ search ... ]` before the main search and pass their output as search terms to the parent search.

### Subsearch Limits & Constraints
- Subsearches return a maximum of 10,000 results or execution time limit of 60 seconds by default.
- Format subsearch outputs using `fields` or `format` to avoid returning unintended fields to the parent search.

### Subsearch Patterns
- **Find IP addresses communicating with suspicious domain, then fetch all HTTP requests from those IPs:**
  ```spl
  index=botsv3 sourcetype=stream:http [
    search index=botsv3 sourcetype=stream:dns query="*coinhive.com*"
    | stats count by src_ip
    | fields src_ip
  ]
  | table _time, src_ip, dest_ip, http_method, uri, user_agent
  ```

- **Find hosts executing malicious process, then fetch authentication events:**
  ```spl
  index=botsv3 sourcetype=WinEventLog:Security EventCode=4624 [
    search index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 Image="*mimikatz.exe"
    | stats count by ComputerName
    | rename ComputerName as WorkstationName
    | fields WorkstationName
  ]
  | table _time, WorkstationName, TargetUserName, LogonType, IpAddress
  ```

---

## 4. Key Field Functions Reference Table

| Function | Type | Description | Example |
|---|---|---|---|
| `count(field)` | Aggregation | Counts events where field is non-null | `stats count(src_ip) by dest_ip` |
| `dc(field)` | Aggregation | Distinct count of field values | `stats dc(query) as unique_domains by src_ip` |
| `values(field)` | Aggregation | Returns list of unique values for field | `stats values(dest_port) by src_ip` |
| `list(field)` | Aggregation | Returns ordered list of field values | `stats list(CommandLine) by Image` |
| `earliest(_time)` | Aggregation | Returns earliest timestamp in group | `stats earliest(_time) as first_seen by user` |
| `latest(_time)` | Aggregation | Returns latest timestamp in group | `stats latest(_time) as last_seen by user` |
| `median(field)` | Aggregation | Calculates median numeric value | `stats median(bytes_out) by src_ip` |
| `stdev(field)` | Aggregation | Calculates standard deviation | `stats stdev(duration) by dest_ip` |
| `perc95(field)` | Aggregation | Calculates 95th percentile value | `stats perc95(response_time) by uri` |
| `isnotnull(field)` | Eval | Returns true if field is not null | `eval has_parent=if(isnotnull(parent_process), 1, 0)` |
| `match(str, regex)`| Eval | Returns true if string matches regex | `where match(Image, "(?i)powershell\|cmd")` |
| `coalesce(a, b)` | Eval | Returns first non-null argument | `eval user=coalesce(TargetUserName, User, src_user)` |
| `cidrmatch(cidr, ip)`| Eval | True if IP matches CIDR network | `where cidrmatch("10.0.0.0/8", src_ip)` |

---

## 5. Multi-Value Field Handling Commands

Security logs frequently contain multi-value fields (e.g., list of IPs in a DNS reply, multiple process hashes, list of privilege rights).

### `mvexpand`
Expands a multi-value field into individual events, creating a duplicate event for each value.
- **Syntax:** `mvexpand <field_name>`
- **Example:**
  ```spl
  index=botsv3 sourcetype=stream:dns query="*coinhive.com*"
  | mvexpand name{}
  | rename name{} as resolved_ip
  | stats count by query, resolved_ip
  ```

### `mvcombine`
Combines multiple events sharing the same group key into a single event with a multi-value field.
- **Syntax:** `mvcombine delim="," <field_name>`

### Multi-Value Eval Functions
- `mvcount(mv_field)`: Returns the number of elements in a multi-value field.
- `mvindex(mv_field, index)`: Returns the element at zero-based index.
- `mvjoin(mv_field, delimiter)`: Joins elements into a single string.
- `mvfilter(boolean_expr)`: Filters elements of a multi-value field based on regex or condition.

---

## 6. SPL Best Practices & Execution Guardrails Checklist for Subagents

- [x] **Index Scoping:** ALWAYS include `index=botsv3` (or approved index allowlist) at the very start of search strings.
- [x] **Sourcetype Scoping:** ALWAYS specify `sourcetype=` when known to prevent full-index sourcetype scanning.
- [x] **Time Boundaries:** Pass exact epoch timestamps (`earliest_time=...` and `latest_time=...`) in tool call arguments.
- [x] **Aggregation First:** Use `stats` to summarize results rather than dumping thousands of raw events into context.
- [x] **Output Bounding:** Use `head` or `limit=` parameters to bound result row counts to manageable limits (e.g. `| head 50`).
- [x] **Field Reduction:** Use `fields` early in the pipeline to drop unused fields and speed up downstream operations.
