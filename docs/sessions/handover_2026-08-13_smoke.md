# Handover — 2026-08-13, after the first live smoke run

Branch `task-broker-agent`, **62 commits ahead of origin, nothing pushed**, tree
clean, **511 tests green**, **ruff 122** (pre-new-module baseline is 70, so Task 14
still owes ~-52). `strands-agents==1.51.0`.

The authoritative board is `progress.md` in this directory — it carries every
ruling, retired risk and measured figure. This document covers the smoke run and
what it proved.

---

## THE HEADLINE: the smoke run worked, and it found that Splunk never runs

A live A/B pair (one run per arm, `--budget-usd 12.00`) completed cleanly, exit 0.
Full log at `scratchpad/smoke.log`, JSON report at `scratchpad/smoke-report.json`.

| | Arm S | Arm F |
|---|---|---|
| Wall clock | 62.2s | 58.5s |
| **Total cost** | **$0.193** | **$0.149** |
| Input / output tokens | 44,759 / 3,933 | 28,737 / 4,166 |
| Sequential turns | 2 | 2 |
| Queries run | 1 | 1 |
| Findings rows | **0** | 2 (vt verdicts) |
| Routing correctness | 0% | 0% |
| Cost by role | vt 36,402 · broker 156,870 | broker_flat 148,701 |

**Both arms cost ~40x less than the ~$7.67 reservation estimate, because almost no
work happened.** Two turns and one query per arm is not an investigation.

### Root cause, measured directly

```
siem | servers= 0 | tools= 0
vt   | servers= 0 | tools= 4
edr  | servers= 0 | tools= 0
ndr  | servers= 0 | tools= 0
```

`tools_for("siem")` returns **zero tools** and `server_count("siem")` is **zero**,
with `.env` loaded — the Splunk MCP client is never constructed by
`smartops.tools.registry`. `vt`'s 4 tools are native and need no MCP server, which is
why VT is the only thing that ran.

So the smoke run measured **VirusTotal lookups plus broker overhead**, on both arms.
Splunk — the domain the entire case is about, holding 2,030,269 events — contributed
nothing to either arm.

### The actual cause: TLS certificate verification, not availability

Reproduced directly with `MCPClient.load_servers('mcp_servers.json')` after loading
`.env`:

```
SPLUNK_MCP_URL set: True
servers in config: ['splunk', 'edr', 'ndr']
clients built: 1
  ERROR MCPClientInitializationError: the client initialization failed
httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
  self-signed certificate in certificate chain (_ssl.c:1032)
```

**Splunk is not down.** The host answers and the TLS handshake begins — it is
rejected because the server presents a **self-signed certificate** that httpx will
not verify. Client construction then raises `MCPClientInitializationError`, the
registry swallows it, and `server_count("siem")` reports 0. Every layer above sees
"this domain isn't available" and reports honestly on that basis.

Note the correction: an earlier subagent claimed it had loaded 10 tools including
`splunk_run_query` through this same path. **Treat that as unreliable** — it is
contradicted by this reproduction, and that agent had already been wrong once today.
It most likely used a raw `httpx` call with verification disabled.

Also visible above: only **1 of 3** configured servers is built at all. `edr` and
`ndr` produce no client, presumably missing their env vars — consistent with both
scoring zero spend in the smoke run.

**This is blocker #1. Nothing about the A/B means anything until it is fixed.**

#### Where the TLS seam actually is — verified in the installed packages

- `MCPClient.load_servers()` **cannot** be configured for TLS. At
  `strands/tools/mcp/mcp_client.py:1715` it builds the transport as
  `streamablehttp_client(url=..., headers=headers)` — url and headers only. There is
  no hook. **This is the path `registry.py` uses today, which is why the certificate
  cannot currently be trusted through configuration.**
- The underlying transport **does** expose one:
  `mcp/client/streamable_http.py:686-693` declares
  `httpx_client_factory: McpHttpClientFactory = create_mcp_http_client`.

So the fix is to stop routing this server through `load_servers()` and construct its
`MCPClient` with an explicit transport callable:

```python
MCPClient(lambda: streamablehttp_client(
    url=url, headers=headers,
    httpx_client_factory=<factory returning an httpx client with the right verify=>,
))
```

**Prefer `verify="<path to the Splunk CA/cert>"` over `verify=False`.** It is the
same size of change and keeps MITM protection; `verify=False` on a SIEM connection
means anything on the path can feed this system fabricated security telemetry, which
is a worse failure than the one being fixed. If `verify=False` is used anyway, gate
it behind an explicit, named, lab-only env flag that defaults to off and logs loudly
on every run — never a silent default.

Do **not** assume `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` will fix this without
testing: httpx builds its default context from certifi, and whether those variables
are honoured depends on how the context is created. Verify before relying on it.

Second-order issue worth fixing alongside it: **the registry turns a construction
failure into silence.** A certificate rejection and "no server configured" are
opposite problems and currently look identical from `tools_for()`. That is what let
a whole live run proceed and report success while the primary domain was absent.

### Second finding, confirmed live: `dispatched` means different things per arm

```
S | dispatched=['vt','siem','edr','ndr'] | findings={}
F | dispatched=['vt']                    | findings={'vt_verdicts': 2}
```

Arm S records **intent** — all four families count as dispatched even though siem,
edr and ndr spent $0 and were rejected for having no tools. Arm F records **realised
work** — only `vt` appears. Both score 0% routing correctness against the expected
`['siem','vt']`, for opposite reasons: S dispatched a superset, F a subset.

`routing_correct = set(outcome.dispatched) == set(expected_families)`
(`bench.py:381`) therefore compares two different quantities. It was predicted from
the offline dry-run and is now confirmed live. **Pick one definition — attempted or
realised — and apply it to both arms.** This is a design call, not an edit.

### Third: the significance labels cannot be trusted

The report calls a 3.7-second wall-clock difference and a $0.04 cost difference
"statistically significant" off **a single run per arm**, where within-arm spread is
zero by construction. In the offline dry-run it made the same claim about a
one-millisecond delta. The hardcoded threshold at `bench.py:465` was already flagged
for Task 13; it is now confirmed producing nonsense at both extremes. Any real
comparison needs ≥3 runs per arm and a spread-aware rule.

### Fourth: `tool=VtAnswer | call failed, not recorded as evidence`

Logged once per arm. VT's structured-output answer failed both times, yet Arm F
recorded 2 verdicts and Arm S recorded none — so the failure degrades differently per
arm. Unexplained; worth a look before trusting VT completeness numbers.

---

## What landed this session

All verified by the controller, not taken from agent reports.

| Task | Commits | Result |
|---|---|---|
| 12 skills gate | `d3f4737` | one off-by-default switch, bench pins it for both arms |
| 12 fix round | `49ed2fc` | replay half-gate closed; env pin became a `ContextVar` |
| 12b plan+step binding | `35fa5b0` | planning mandatory in code; every dispatch names its step |
| 12b fix round | `8b35331` | `evaluated=False` at plan time; `FetchPlan` id uniqueness; turns 8→11 |
| 12c Arm F loop | `fd19db8` `b8ca062` `2d4032b` | Arm F plans and walks steps concurrently; `evaluate_step()` shared |
| 12c fix round | 7 commits `a3f4057`..`31d31f5` | retry allowance, `queries_run` symmetry, skills switch, aliasing pinned |
| **12d bench Arm S** | `1559efc` | **the bench finally hands Arm S a real subagent** |
| 15a partial | `9ccdd41` | VT `row_count` crash fixed; `--budget-usd` default 1.0 → 10.0 |

Tests went 403 → 511. Three code reviews ran; each found something that would have
invalidated the experiment.

## Ranked queue for the next session

1. **Fix siem MCP client construction** — blocker #1, above. Until then every run is
   a VT-only run.
2. **Re-run the smoke pair** and confirm siem actually queries. The $0.19/$0.15
   figures are meaningless as cost estimates; a real run will be far higher.
3. **Decide the `dispatched` definition** and apply it to both arms.
4. **Task 12f** — per-step artifacts. Arm F still writes none, `bench.RunMetrics`
   carries no `step_outcomes`, and the bench's 3-runs-per-arm already overwrite each
   other in `.smartops/runs/<task_id>/`. Brief at `task-12f-context.md`.
5. **Task 12e** — the owner's two prompts, with the five reconciliations recorded in
   `progress.md`. Two-phase: owner approves the text before it commits.
6. Fix the significance rule, then Task 14 lint, then the full 3×2.

`task-15b-context.md` holds the smoke-run brief; it is still accurate apart from the
budget figure, which the re-run will supersede.

## Process lessons worth keeping

- **Incremental commits saved a task.** The 12c fix round was killed by the spend
  limit *during final verification* — all seven fixes were already committed. The
  previous attempt at the same work, told to commit at the end, lost everything.
  Put "commit incrementally" in every implementer brief.
- **Subagents must run project code with `uv run python`.** A bare `python` picks up
  a different interpreter and produces confident nonsense — one agent concluded
  Strands was missing `MCPClient.load_servers()` when it exists at
  `mcp_client.py:168`.
- **Subagents need `.env` loaded explicitly** (`find_dotenv(usecwd=True)`), as
  `main.py:362-367` does. `bench.py` does **not** load it — the smoke run only worked
  because it was invoked through a wrapper that did.
- **Verify every agent report against the tree.** Three were materially wrong this
  session. Two of the three were environmental, not substantive.
- **Reviews earned their cost every time.** Three ran; three found experiment-
  invalidating defects. When budget forces a choice between another implementer and
  another reviewer, take the reviewer.
