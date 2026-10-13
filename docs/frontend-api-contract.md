# SmartOps API: frontend contract

The frontend (`frontend/`, AR10) talks only to these routes, served by `smartops.main:app`. The Analyst now calls the Broker in process (AR11) and **none of this changed** with that move. Source: `engine/src/smartops/main.py` (routes), `analyst.py` (run events), `context.py`, `engine/contracts/src/contracts/reasoning.py`.

Conventions:
- JSON in and out. Most failures come back as **HTTP 200 with `{"status": "error", "message": str}`**, so check `status`, not the HTTP code. The exceptions are the run-control routes, which return a real 404.
- Times are ISO 8601. Alert/event times are UTC.
- Fields marked *model* are written by Foundation-Sec. Their keys are asked for, but not guaranteed: render defensively, since any of them may be missing or have the wrong type.

## 1. Alert intake (Splunk ES)

### `GET /api/incident-queue`
The latest 50 notables over 30 days, deduplicated per event, grouped by rule + host.
```jsonc
{ "status": "ok", "groups": [ {
    "rule_name": str, "dest": str, "time": str,        // time of the group's newest event
    "urgency": "informational|low|medium|high|critical|",
    "users": [str], "srcs": [str], "count": int,
    "events": [ { "index": int, "time": str, "rule_name": str, "urgency": str,
                  "src": str, "dest": str, "user": str } ]   // index -> /api/import-from-splunk?index=
} ] }
```

### `GET /api/import-from-splunk?index=0&rule_name=`
One notable (index 0 = newest), plus its deployed detection SPL. `rule_name` optionally filters to one rule.
```jsonc
{ "status": "ok" | "empty" | "error", "selected_index": int, "total_available": int,
  "event_time": str /* UTC, the event itself, not when ES fired */,
  "rule_name", "urgency", "src", "dest", "user", "file_hash", "domain", "mitre", "sig": str,  // "" when absent
  "deployed_spl": str, "raw_event_data": { ...every Splunk field } }
```
## 2. Enrichment (building the context contract)

### `POST /api/escu` `{ "rule_name": str }`
The top 3 matches from the local ESCU corpus (BM25).
`{ "status": "success", "matches": [ { "rule": str, "score": float, "data": { ...ESCU rule metadata } } ] }`

### `POST /api/opencti` `{ "observables": [str] }`
`{ "status": "success" | "unavailable", "source": str, "total_observables": int, "results": { "<observable>": { "_queried_as": str, ...raw GraphQL } } }`
`unavailable` means OpenCTI is unreachable (one probe, ~5 s). Show this as unavailable, not as an error.

## 3. Investigation run (the main flow)

### `POST /api/run` → `{ "run_id": str }`
```jsonc
{ "context_contract": {            // what the UI builds from import + enrichment
    "normalized_seed": { "alert_name", "event_time", "severity",
                         "entities": { "host"|"hostname", "user", "src_ip", ... },
                         "file": { "sha256" }, "process": { "process_guid" } },   // optional
    "escu_context": { ... }, "opencti_threat_intelligence": { ... }, "goal": str },
  "max_loops": 15 }               // the alert_name/host/domain/event_time fields are a demo fallback, used only without a contract
```

### `GET /api/run/stream/{run_id}`: Server-Sent Events
Each message is `data: <json>`. Lines starting with `: keepalive` are heartbeats (the Broker can go quiet for minutes), so ignore them. The stream closes after `done`, `error` or `stopped`. Unknown `run_id` → `{"error": "run not found"}` (plain JSON, not a stream).

Every event: `{ "type": str, "data": object, "message": str, ...extras }`. `loop` is the round number (1 = planning, 2+ = Broker + synthesis).

| `type` | When | `data` | extras |
|---|---|---|---|
| `analyst` | round 1 starts (`data` = `{}`), then the plan | the plan (*model*): `model_reasoning`, `semantic_alignment`, `alignment_reasoning`, `hypotheses: [{id, verdict, description}]`, `tasks: [{task_id, question, entity, time_window}]`, `reasoning` | `tokens: {prompt_tokens, generation_tokens, stop_reason}` |
| `handoff` | each round, before the Broker | `{ tasks: [{task_id, hypothesis_id, question, entity: [{type, value}], time_window: {start, end}}], dropped: [{task_id, question, why, sent?: true}], task_file: str }` (`sent: true` = sent with a change, explained in `why`) | `loop` |
| `broker_log` | each Broker log line (many) | `{ line: str }` | `loop` |
| `broker` | Broker finished | `{ runs: [BrokerRun], handshake: {sent, fetched, returned, not_fetched, not_returned, unexpected: [task_id]} }` | `loop` |
| `payload` | sub-analyst findings back | `AnalystPayloadBatch` (below) | `loop` |
| `synthesis` | evaluation starts (`{}`), then the result | *model* + gate: `hypothesis_scores: {H1: 0-100}`, `verdict`, `verdict_reasoning`, `evidence_refs: [str]`, `status: VERDICT_REACHED \| REQUIRES_INVESTIGATION` (decided by the gate, not the model), `evidence_gaps: [str]`, `refused_refs: [str]`, `follow_up_tasks` | `loop`, `reasoning: str`, `tokens` |
| `verdict` | the run's conclusion | the final synthesis; `verdict` ∈ `TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, REQUIRES_INVESTIGATION` | |
| `paused` / `resumed` | at a stage boundary | `{}` | |
| `done` | finished normally | none | |
| `error` | failed | none; read `message` | `trace` (the round's link, on a Broker failure) |
| `stopped` | stopped by the user | none | |

**BrokerRun** (one per task): `{ task_id, run_dir: str|null /* null = never ran */, trace_id, plan_rationale, classification, plan_repairs: [], spend_micro_usd: int, steps: [{step_id, family, objective, categories, completed, rows_retrieved, confirmed_empty, status, reason}], dispatched: [], results: [{family, status, reason, error, gaps, queries: [str], blocked}] }`

**AnalystPayloadBatch:** `{ schema_version, batch_id, created_at, payloads: [ { task_id, run_id, hypothesis_id, hypothesis /* the task's question */, findings: [ { domain: "identity"|"network"|"endpoint"|..., narrative: str, observations: [str], summaries: [str], facts: [str] } ] } ] }`. `evidence_refs` cite `<task_id>:<domain>`, or `<task_id>:<block id>` where a block id appears as `[id]` in a narrative or observation. `<task_id>` may be the full id or its short `T1` tail.

### Run control
`POST /api/run/{run_id}/stop | /pause | /resume` → `{"status": "ok"}`, or **HTTP 404** once the run has finished. Pause and stop take effect at the next stage boundary, because a model call already in flight can't be interrupted. Stop also cancels a running Broker round at once.
