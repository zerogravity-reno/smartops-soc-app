# 2026-08-11 — From "nothing runs" to two live subagents against BOTSv3

## What was asked

Credentials had just been added. The question was how to test the Task Broker
against `index="botsv3"` and benchmark how correctly it runs.

Answering it required first making the system *able* to run. It now does: a live
investigation produces analyst-grade findings from real 2018 data, with the
Broker and two domain subagents all making real model calls.

## Decisions taken (Mohammed's)

| Decision | Note |
|---|---|
| TLS verification **disabled** for the lab Splunk box only | I recommended certificate pinning; overruled. Scoped by server name, secure by default in the repo. |
| Score SIEM answers and Broker routing **separately** | `edr`/`ndr` legitimately stay REJECTED on this dataset. |
| Ground truth from the **official BOTSv3 answer key**, verified against the index | I do not have the key and will not invent it. |
| The **CLI is the mimicked Analyst** | We are testing the Broker; no Analyst contract to design. |
| `vt` subagent uses the **Broker's model** | Per-family model selection deferred. |
| Bare-minimum subagents now | Dynamic subagent creation deferred to next week. |

## Seven defects, every one found by running rather than reading

1. **Splunk TLS.** The cert is `CN=SplunkServerDefaultCert`, issued by
   `SplunkCommonCA`, with **no subjectAltName**. Two independent failures: no
   public trust store carries that CA, *and* with no SAN there is nothing for
   hostname verification to match against an IP, since Python dropped CN
   fallback. Importing the CA is necessary and insufficient. `MCPServerConfig`
   has no TLS fields at all, so trust cannot be expressed in `mcp_servers.json`
   — but `streamablehttp_client` accepts an `httpx_client_factory` and
   `MCPClient` takes a transport callable, so building the client ourselves is
   the supported seam. No patching.

2. **All botsv3 data is one day: 2018-08-20.** The CLI could only build windows
   ending at *now*, so every search returned zero events — indistinguishable
   from an empty domain. A benchmark built on that would have scored 0% and
   taught us nothing. Hence `--since` / `--until`.

3. **Verbose subagent answers crowded the Broker's output ceiling**, so the run
   ended before emitting a `TaskClassification`. `_digest()` now trims and says
   it trimmed; the full text still reaches the aggregator.

4. **The Broker re-dispatched `siem` three times**, spending 85% of the budget.
   `MAX_DISPATCHES_PER_FAMILY = 2`.

5. **`Limits(output_tokens=)` is cumulative across the loop**, not per call. A
   dozen SPL queries as tool arguments starved the final answer. Raised, and
   `stop_reason` is now surfaced wherever structured output goes missing —
   Strands ends a capped run with a stop reason and raises nothing, so "out of
   turns", "out of tokens", and "the model didn't answer" were one symptom
   needing three different fixes.

6. **`UnicodeEncodeError` destroyed a finished investigation.** Windows cp1252
   could not encode the model's answer, so `_print_outcome` raised *after* the
   work was done and billed. The findings existed, were paid for, and were
   replaced by a stack trace.

7. **`telemetry.py` was dead code.** `trace_attributes_for()`,
   `record_cost()`, and `record_result_status()` had no call sites. Traces
   carried Strands' generic spans with no task_id, no cost, no status — while
   every test passed, because a helper tested in isolation cannot reveal that
   nothing calls it.

## What the SIEM subagent actually did

Given a host, a domain, and a 24-hour window in 2018, with no pre-authored
query, it correlated three sourcetypes:

- `stream:dns` — six CoinHive endpoints (`coinhive.com`, `ws001/005/011/014/019`)
  with resolved IPs and per-query timestamps
- `stream:tcp` + `WinEventLog` 5156 — every connection permitted on :443, with
  byte counts (~43K in / ~126K out)
- `WinEventLog` 4624 — **`chrome.exe` (PID 9752)** as initiator, under user
  **`AzureAD\BudStoll`**

It reported the absences too — no `stream:http` hits (direct WSS, not proxied)
and no Symantec detections — and set `gaps: ndr, vt`, using the typed field to
tell the Broker what it could not reach.

VirusTotal, independently: `coinhive.com` — **11 malicious / 1 suspicious of 91
engines**.

## The trace (72 spans, 137s, one root)

```
smartops.investigation                      137.4s   broker $0.037
  invoke_agent (broker)                     137.2s   5,786 in / 1,307 out
    chat                                      5.5s
    execute_tool investigate_vt              11.4s   vt   $0.020  ok
    execute_tool investigate_siem           115.2s   siem $0.976  ok
    execute_tool investigate_ndr             0.01s   rejected
    execute_tool investigate_edr             0.01s   rejected
```

Three things the trace showed that reading the code had not:

**Dispatch is parallel.** All four family tools start at +5.74s — Strands runs a
turn's tool calls concurrently. Wall clock is the slowest family, not the sum.
Worth knowing before adding more domains.

**The SIEM subagent ran 24 tool calls** (22 × `splunk_run_query`, plus
`get_metadata` and `get_indexes` to orient first) across ~14 event-loop cycles —
right at the `DEFAULT_TURNS = 14` ceiling. It succeeded, but with no headroom.

**Cost is input, not output.** The SIEM subagent accumulated **297,225 input
tokens** against 5,629 output — $0.89 of its $0.976, because every turn re-sends
the whole conversation. Prompt caching, not a smaller window, is the lever.

## Open, and worth acting on

- **`vt`'s reservation was 42× its actual cost** — $0.84 reserved, $0.020 spent.
  `_estimated_input_tokens()` assumes worst-case turns × tool count, which is
  wildly pessimistic for a two-turn lookup. Harmless at `--budget-usd 3.00`;
  under a tight budget it would block real work by reserving money nothing spends.
- **The SIEM subagent sits at its turn ceiling.** Fine today, brittle tomorrow.
- **No prompt caching.** The single biggest cost lever, untouched.
- **No evidence persistence.** `SubtaskResult.evidence` carries the raw tool
  output, `main.py` prints a summary, and the process exits. Re-answering "what
  exactly did it see" means re-running and re-paying. The contract already names
  the missing piece — "the aggregator ... writes them into the case file's
  evidence store" — and the aggregator does not exist.
- **The pivot problem.** The Broker asked for it itself: discovered domains
  should feed back as observables for `vt`/`ndr`. Scope immutability is a
  security property worth keeping, so the answer is a second *round* with a newly
  authorised scope, not a mutable one. Open: who authorises the new entities, and
  does one budget span rounds?

## Blocked on the team

- `edr` / `ndr` vendors unpicked. On botsv3 their data is all in Splunk anyway,
  which is why they stay REJECTED here.
- The official BOTSv3 question/answer key, if Phase 5 should be sourced from it
  rather than from SPL I write and Mohammed reviews.

## State

Six commits on `task-broker-agent`, nothing pushed. **148 → 209 tests.**
Live cost for the whole session: roughly $7 of Bedrock.
