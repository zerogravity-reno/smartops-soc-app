# Broker and Subagents Architectural, Logic & Runtime Issues Report

> **Date:** November 2, 2026  
> **Investigation Scope:** Recent investigation runs (`c9611aa4`, `ff1221b4`, `feca66e2`, `3339d1e1`, `67477c37`, `7d60bab4`, `4cacdea1`, `4b95662c`), alongside code inspection of `broker.py`, `subagents/__init__.py`, and `subagent_analysts/`.

---

## Executive Summary

Across the latest investigation runs, investigations frequently suffered from:
1. **Severe observation loss** in the grounding gate (over 29 valid observations dropped due to rigid verification checks and subagent extrapolation).
2. **MCP Splunk session teardowns** causing zero-result task failures without retry or reconnection.
3. **Subagent 900s timeouts** due to unconstrained or broad Splunk queries.
4. **Infinite unanswerable task loops** across rounds (e.g., CMDB/Asset Inventory and Change Management) because the Broker lacks global source exclusion feedback to the Analyst.
5. **Invented citations and narrative hallucinations** by domain subagent analysts.
6. **Async task & callback leaks** when subagents are cancelled or timed out.
7. **Payload template structure budget collapse** where empty domain schemas alone breach the character ceiling.

---

## 1. Broker Logic Flaws

### 1.1 MCP Session Loss Treated as Task Termination Instead of Reconnect (`_SessionWatch`)
- **Location:** `engine/src/smartops/subagents/__init__.py` (lines 435–465)
- **Code Flaw:**
  ```python
  class _SessionWatch:
      def _check(self, event: Any) -> None:
          if SESSION_LOST in text:
              self.refused += 1

      def _halt(self, event: Any) -> None:
          if self.refused:
              event.end_turn = "The Splunk connection was lost. Stop querying."
  ```
  When an MCP session terminates (`CLIENT_SESSION_NOT_RUNNING_ERROR_MESSAGE`), `_SessionWatch` instructs the subagent to halt immediately with an `end_turn`. It never invokes `mcp_client.reconnect()` or retries the tool call.
- **Impact in Runs (`c9611aa4-L3-FU1`):**
  ```text
  ERROR strands.tools.executors: tool execution failed: MCPClientInitializationError(CLIENT_SESSION_NOT_RUNNING_ERROR_MESSAGE)
  [error] siem MCP session lost (1 call(s) refused); siem subagent produced no structured answer (stop_reason=end_turn); 0 raw result(s) retained
  ```
  The entire task fails with 0 evidence collected, directly degrading subsequent synthesis rounds.
- **Recommended Fix:** Implement automatic connection reset and query retry when catching `SESSION_LOST` before giving up.

---

### 1.2 Unanswerable Task Loops Across Rounds (Missing Global Source Feedback)
- **Location:** `engine/src/smartops/broker.py` (`_offered_families`, lines 1841–1855)
- **Code Flaw:**
  The Broker knows that unsupported domains (e.g., CMDB, Asset Inventory, Change Management, Ticketing) cannot be served by any available specialist (`siem`, `virustotal`, `decoder`). However, when it marks a task as `UNANSWERABLE`, this status is returned as a per-task finding rather than a global environment constraint.
- **Impact in Runs (`3339d1e1` L3, L4, L5):**
  The Analyst asked whether host `ar-f6eddb5b-df6` was a dev/prod machine in Loop 3. The Broker marked it unanswerable. In Loop 4, the Analyst asked the exact same question. The Broker marked it unanswerable again. In Loop 5, the question was submitted a third time.
- **Recommended Fix:** The Broker payload returned to the Analyst should explicitly expose a `permanently_unavailable_sources: ["cmdb", "change_management", "asset_inventory"]` section, preventing the Analyst from regenerating duplicate follow-ups.

---

### 1.3 Missing Field Attribution in Grouped SPL Queries (Attribution Dropped at Gate)
- **Location:** SIEM query generation logic in `subagents/__init__.py`
- **Code Flaw:**
  Subagents frequently generate aggregation queries using `| stats count by ...` that omit foundational correlation fields (`host`, `dest`, `user`).
- **Impact in Runs (`ff1221b4-L3-FU1`, `3339d1e1-L5-G1`):**
  - In `ff1221b4`: The subagent fetched 100 DNS queries and wrote *"Host ar-f6eddb5b-df6 queried _ldap repeatedly"*. Because the query only returned `query` and `count` without the `dest` column, the Claim Check dropped the observation entirely:
    ```text
    claim check dropped an observation: The rows show the query repeated 100 times, but no row contains a host field.
    ```
- **Recommended Fix:** Enforce mandatory entity attribution columns (`host`/`dest`/`user`) in all subagent `stats` and table formatting templates.

---

## 2. Subagent & Grounding Gate Flaws

### 2.1 Narrative Semantic Extrapolation vs. Rigid Verification Conflict
- **Location:** `engine/src/smartops/subagent_analysts/prompts.py` vs `verify.py`
- **Code Flaw:**
  - `prompts.py` instructs the model to translate raw data into fluent natural prose:
    > *"NARRATIVE is PROSE... Say what happened and who and what was involved."*
  - `verify.py` enforces a literal strict substring and entity check:
    > *"A claim that names a value, process, account, address, command or action the rows do not contain is unsupported."*
- **Impact in Runs (29 dropped observations across recent runs):**
  - **Action mismatch:** For EventCode 4104 (script block execution), the subagent wrote *"script blocks were written to disk"*. Since EID 4104 does not explicitly log disk writes, the observation was dropped.
  - **Path inference:** For Sysmon Event 11 (File Create), the subagent wrote *"file written to TEMP directory"*. Because the row did not explicitly render the `$env:TEMP` string, it was dropped.
  - **Outcome inference:** For `Test-Connection`, the subagent wrote *"inventory checks confirmed reachable targets"*. The rows only logged the execution of the command without the standard output result, causing total drop.
- **Recommended Fix:** Add explicit negative constraints to `_ANSWER_RULES` in `prompts.py`:
  - *"Do not infer physical actions (do not state 'written to disk' for script block executions)."*
  - *"Do not infer success or reachability unless explicit status/return code fields are visible in the rows."*

---

### 2.2 Invented Citations (`[reputation#1]`)
- **Location:** `engine/src/smartops/subagent_analysts/prompts.py`
- **Code Flaw:**
  Subagent prompts mention example citation formats (such as `reputation#1`), which primes LLMs to hallucinate reputation lookups even when VirusTotal was never dispatched.
- **Impact in Runs (`feca66e2-L2-T4`, `7d60bab4-L2-T1`):**
  ```text
  WARNING smartops.subagent_analysts.analyze: dropped 1 invented citation(s) from a finding: reputation#1
  dropped an observation citing only unresolvable id(s): reputation#1
  ```
- **Recommended Fix:** Dynamically construct citation instructions in `_NARRATIVE_FOOTER` containing **only** the set IDs that actually exist in the current task evidence.

---

### 2.3 Unconstrained Mission Timeouts (900s Ceiling)
- **Location:** `engine/src/smartops/subagents/__init__.py` (line 113)
  ```python
  MISSION_TIMEOUT_SECONDS = 900  # 15 minutes
  ```
- **Code Flaw:**
  If a subagent writes an unindexed or overly broad Splunk search (e.g. scanning across an entire index without bounded `earliest`/`latest`), the subagent hangs for 15 full minutes before aborting.
- **Impact in Runs:**
  13 timeout incidents logged across recent runs, severely blocking the pipeline and eventually yielding `0 evidence items retained`.
- **Recommended Fix:**
  1. Reduce `MISSION_TIMEOUT_SECONDS` to a reasonable ceiling (e.g., 180s–240s).
  2. Implement an execution pre-guard in `subagents/__init__.py` that rejects any Splunk query lacking `earliest` and `latest` timestamps.

---

### 2.4 Evidence Payload Inflation & Row Capping (`row_cap=20`)
- **Location:** `engine/src/smartops/subagent_analysts/packing.py`
- **Code Flaw:**
  When subagents return high-volume raw events instead of aggregated summaries, evidence exceeds the character budget. The packer applies a hard clamp `row_cap=20`.
- **Impact in Runs (`ff1221b4-L2-T4`, `7d60bab4-L3-FU2`):**
  ```text
  WARNING smartops.subagent_analysts.packing: evidence over budget, rendered at row_cap=20
  ```
  The Broker discards up to 95% of gathered events, blinding the Analyst to critical lateral movements or secondary executions.
- **Recommended Fix:** Subagents should prioritize statistical aggregations (`stats count by ...`, `top`, `dedup`) before fetching raw sample rows.

---

## 3. Runtime, Concurrency & Contract Flaws

### 3.1 Unhandled Future Cancellations and Async Task Leaks
- **Location:** `engine/src/smartops/broker.py` & `subagents/__init__.py`
- **Code Flaw:**
  When tasks are cancelled or hit timeouts, async task futures are destroyed abruptly without cancellation draining or safe callback unregistration.
- **Impact in Runs (`4b95662c`, `c9611aa4`):**
  ```text
  ERROR asyncio: Task was destroyed but it is pending!
  ERROR concurrent.futures: exception calling callback for <Future at 0x... state=cancelled>
  ```
  Leaves stray background tasks attempting to complete or access database/network connections after rounds terminate, wasting system resources.
- **Recommended Fix:** Ensure graceful cancellation handling using `asyncio.shield` and explicit `task.cancel()` with `try...finally` resource cleanup.

---

### 3.2 Payload Template Structure Budget Collapse
- **Location:** `engine/contracts/src/contracts/reasoning.py`
- **Code Flaw:**
  Strict character constraints (e.g., `2212` characters for analyst payloads) measure the total serialized JSON size. When multi-domain schemas (endpoint, network, identity, file, registry) are included even with empty observation blocks, the JSON schema boilerplate itself exceeds the budget.
- **Impact in Runs (`3339d1e1-L2-T6`, `feca66e2-L2-T4`, `feca66e2-L2-T5`):**
  ```text
  ERROR contracts.reasoning: task=3339d1e1-L2-T6 | analyst payload: its structure alone exceeds the 2212-character budget
  ```
- **Recommended Fix:** Strip empty domain blocks from the payload before applying budget sizing, or allocate structure baseline budget separately from content budget.

---

### 3.3 Premature `end_turn` Evidence Discard (State Machine Trap)
- **Location:** `engine/src/smartops/subagents/__init__.py`
- **Code Flaw:**
  When a subagent completes its research or encounters a minor parsing hiccup, LLMs occasionally emit an informal closing text message (`stop_reason=end_turn`) instead of invoking the structured output tool schema.
- **Impact in Runs (`c9611aa4-L3-FU1`):**
  ```text
  ERROR smartops.subagents: no structured output (stop_reason=end_turn); keeping 0 evidence item(s)
  error: subagent returned no structured output and no evidence
  ```
  All successfully retrieved raw query rows are discarded completely rather than preserved as fallback evidence.
- **Recommended Fix:** Add a recovery fallback that parses previously collected tool call outputs from the conversation history if the final structured call was missed.

---

## 4. Comprehensive Issues & Solutions Matrix

| Category | Component | Observed Issue | Root Cause | Proposed Resolution |
|---|---|---|---|---|
| **Broker Logic** | `_SessionWatch` | Lost MCP connection causes immediate task abort | `_halt()` forces `end_turn` without calling reconnect | Add auto-reconnect logic upon catching `SESSION_LOST` |
| **Broker Logic** | Task Routing | Infinite loop on unanswerable questions (CMDB, etc.) | Broker marks single task unanswerable without global feedback | Feed forward `unsupported_sources` list to the Analyst |
| **Broker Logic** | Query Validation | Attribution dropped by Claim Check | Aggregation queries omit `host`/`dest`/`user` columns | Enforce mandatory entity columns in subagent query formatting |
| **Subagent** | Grounding | 29 observations dropped by Claim Check | Natural language extrapolation conflicts with literal verify rules | Update `_ANSWER_RULES` with strict anti-extrapolation constraints |
| **Subagent** | Prompting | Invented citations (`reputation#1`) | Prompt mentions static examples of non-dispatched tools | Dynamically render only active set IDs in citation footer |
| **Subagent** | Execution | 900s subagent timeouts | Query without time boundaries blocks on Splunk | Enforce `earliest`/`latest` in all queries & reduce timeout to 180s |
| **Subagent** | Packing | Hard row cap at 20 lines | High volume raw rows exceed budget | Enforce aggregation-first methodology in subagent instructions |
| **Runtime** | Concurrency | `Task was destroyed but it is pending!` / Cancelled callbacks | Abrupt task cancellation without asyncio loop cleanup | Wrap cancellation in explicit `gather(return_exceptions=True)` cleanup |
| **Contracts** | Packaging | Payload structure exceeds 2212 char limit | Empty schema boilerplate counts against content budget | Prune empty domain blocks before serialization |
| **Subagent** | State Machine | 0 evidence retained on `end_turn` | No fallback recovery when LLM ends without structured tool call | Retain collected raw tool outputs even if final schema call missed |
