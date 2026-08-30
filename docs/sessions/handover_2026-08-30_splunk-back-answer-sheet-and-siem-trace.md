---
date: 2026-08-30
title: Splunk is back — fill the answer sheet from BOTSv3's published answers, and verify the SIEM path is traced
---

# Handover — Splunk is back

Two jobs, both blocked until now by MCP being down. **Everything is committed and
pushed** — `task-broker-agent` level with `origin` at `9c2646c`, tag
`analyst-hardening-2026-08-30`, 826 tests passing, working tree clean apart from
the by-design untracked files (`scratchpad/`, `docs/confluence-subagent-analysts.md`,
`graphify-out/`, `.claude/`).

**Splunk verified reachable at the start of this handover:** `server_count('siem')
== 1`, `family_is_configured('siem') == True`, and `tools_for('siem')` loads **10
tools** — `splunk_run_query`, `splunk_get_indexes`, `splunk_get_metadata`,
`splunk_get_info`, `splunk_get_index_info`, `splunk_get_user_list`,
`splunk_get_user_info`, `splunk_get_kv_store_collections`, +2.

---

## JOB 1 — Verify the SIEM path is traced

`48cc35f` added analyst spans and `d1a6f8c` added the `run_id` join. Both were
verified live, but **only on the `vt` path**, because Splunk was down. What has
never been observed:

- Splunk MCP tool calls appearing as spans at all
- the siem subagent's `Agent` nesting under `investigation_span`
- **a multi-step siem plan executing** — see the warning below, this is the big one

### Run this

```bash
env -u AWS_PROFILE SMARTOPS_RUNS_DIR="$TEMP/siem-trace-runs" \
  uv run smartops-broker \
  --goal "Did host BSTOLL-L contact coinhive.com, and is coinhive.com known-malicious?" \
  --hypothesis "Host BSTOLL-L was cryptomining via coinhive.com" \
  --entity domain:coinhive.com --entity host:BSTOLL-L \
  --since 2018-08-20T00:00:00Z --until 2018-08-21T00:00:00Z \
  --console-traces --verbose > "$TEMP/siem-trace.log" 2>&1
```

**`--verbose` is not optional.** Default log level is `ERROR`
(`main.py`, `level=logging.INFO if args.verbose else logging.ERROR`), which
suppresses every `logger.warning` in the codebase — including the grounding gate's
"rests entirely on cited blocks with zero rows" and `plan_fetch`'s refusals. The
planner bug fixed in `e6df52c` survived for weeks partly because of this.

**The BOTSv3 time window is 2018-08-20 → 2018-08-21.** `--hours 24` computes from
*now* and will retrieve nothing.

### Parse the trace

The span-parsing snippet is at the bottom of this file. Check, in order:

1. **`DISTINCT TRACES == 2`** — `smartops.investigation` and `smartops.analysis`.
   Two roots is the design (`telemetry.analysis_span` documents why); they join on
   `task_id` + `hypothesis_id` + `run_id`. If `run_id` is absent from either root,
   `record_run_id()` did not fire.
2. **Splunk tool spans exist** — expect `execute_tool splunk_run_query` (and
   friends) nested under an `invoke_agent Strands Agents` carrying
   `tool_family=siem`. If the siem subagent's spans are missing entirely while vt's
   are present, that is new and worth its own investigation.
3. **`gen_ai.tool.status` on every tool span.** The `plan_fetch` bug presented as
   exactly this and nothing else — six `status: error` with the reason only in
   `status.description`. Any `error` here is a lead, not noise.
4. **`plan_fetch` called ONCE.** More than once means it is being refused again.

### ⚠️ The planning code is barely exercised

`plan_fetch` has worked for **one run, vt-only, and its steps completed
immediately**. A real multi-step siem plan has never executed. So this run is the
first stress of:

- `CompletionRule.categories` — a step declaring `dns_resolutions` closed only by
  rows in that category. Never exercised: no benchmark run has ever returned SIEM
  rows (see Job 2).
- `depends_on` — never populated by a real plan.
- `DISPATCHES_PER_PLANNED_STEP = 2` retry, and
  `MAX_PLANNED_DISPATCHES_PER_FAMILY = 6`.
- Re-planning: `plan_fetch` called a second time rebuilds `step_outcomes` while
  carrying counters. It has a careful implementation and no live evidence.

Expect to find something here. If a step reports `completed=False` with rows
retrieved, suspect `CompletionRule.categories` against `_infer_cim_category`'s
tagging before suspecting the model.

### Known bug to fix or document while you are here

**`--families` does nothing on the model path.** It reaches exactly one place,
`_scripted_invoker(families)`, and is never passed to `broker_task`. Its own help
says *"comma-separated families to dispatch"*, which reads as a constraint;
`--scripted`'s help does mention it drives dispatch, but not where anyone looks.
A previous verification run was described as "vt-only" and was not — it planned and
dispatched siem. Either wire it through, or narrow the help to say scripted-only.

---

## JOB 2 — Fill the answer sheet from BOTSv3's published answers

### The problem, measured

`bench.py` has `expected_families` for routing and **no expected dispositions**.
That was recorded as "needs a human to label 10-20 cases". Research this session
says the labelling is mostly unnecessary and the cases are worse than unlabelled:

**Every saved benchmark run has a `rejected` result. The SIEM side has never
returned a single row in any benchmark case.**

```
botsv3_coinhive              rejected[none]  ok[verdicts]
botsv3_c2_ip                 rejected[none]  ok[verdicts]
botsv3_dns_tunneling         rejected[none]  no_data[verdicts]
botsv3_suspicious_user_auth  rejected[none]                 <- siem-only, nothing at all
...
```

So the analysts have been judged almost entirely on VirusTotal reputation rows for
their entire existence. And **9 of 11 cases point at indicators BOTSv3 does not
contain**:

| case | indicator | reality |
| :--- | :--- | :--- |
| `coinhive` | coinhive.com | **REAL, and the answer is published** |
| `suspicious_user_auth` | bostoll / BSTOLL-L | **REAL** — Bud Stoll, bstoll@froth.ly |
| `c2_ip` | 217.182.164.14 | not in BOTSv3. OVH hosting, VT mal=1 |
| `powershell_hash` | e2ac36894c…6c8c | not in BOTSv3, VT NOT FOUND |
| `exfil_ip` | 104.20.208.59 | Cloudflare. BOTSv3 has `104.20.209.59` as a *coinhive DNS response* — one digit off, and not exfil |
| `web_shell_url` | po18-s92-l01/…/shell.php | not in BOTSv3 at all, VT NOT FOUND |
| `dns_tunneling` | a1b2c3.tunnel.malicious.net | **placeholder** (a1/b2/c3), does not resolve |
| `ransomware_note` | 8f4e2b1091…123456789abc | **placeholder** (sequential hex tail) |
| `mimikatz_hash` | 31d6cfe0d16ae931b73c59d7e0c089c0 | **the NTLM hash of an empty password.** Not Mimikatz, not malware, not a file hash. The case is *mislabelled*, not just synthetic |

`phishing_domain` / secure-login-account.com is the odd one: not documented in
BOTSv3, but our own saved VT lookup has it at **mal=14**, so it is a real flagged
domain. Keep it as a VT-only case or drop it; do not expect SIEM rows.

### The real scenario

**Frothly**, a fictional brewery, attacked by **Taedonggang**. Index `botsv3`.
Chain: spearphish (`Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm`, W97M
macro) → `HxTsr.exe` → tooling incl. `hdoor.exe` → cryptomining on BSTOLL-L → AWS
credential compromise and S3 exfiltration → Exchange transport-rule persistence →
Linux backdoor on port 1337.

Hosts: BSTOLL-L, FYODOR-L, ABUNGST-L, MKRAEUS-L, splunkhwf.froth.ly.

### Documented answers to build cases from

**Cryptomining — this is your `coinhive` case, and it is already correct:**

| fact | value | source |
| :--- | :--- | :--- |
| host actually mining Monero | **BSTOLL-L** | Q210 |
| process at 100% CPU | **chrome#5** | Q208 |
| coinhive destinations visited | **6** | writeups |
| domains queried | coinhive.com, **ws001 / ws005 / ws011 / ws014 / ws019**.coinhive.com | writeups |
| Symantec signature | *JSCoinminer Download 8*, SID 30358, Medium | writeups |
| mining duration | ~1,652–1,666 s (Cisco NVM flow) | writeups |

The `ws001`/`ws005` subdomains appear in our own live evidence from
`cli-20260823T112627`, which independently confirms the data is present.
**Expected disposition: `malicious` on network, and endpoint should see `chrome`.**

**Replacements for the synthetic cases:**

| replace | with | documented answer |
| :--- | :--- | :--- |
| `c2_ip` 217.182.164.14 | **45.77.53.176**, **45.77.65.211**; URL paths `/admin/get.php`, `/news.php`, `/login/process.php` | contacted by **ABUNGST-L** and **FYODOR-L** (Q323) |
| `powershell_hash` e2ac36… | **586EF56F4D8963DD546163AC31C865D7** | MD5 of `hdoor.exe` (Q307) |
| `web_shell_url` | *drop*, or use port **3333** / `logos.png` | attack-tool download (Q314, Q316) |
| `mimikatz_hash` | *drop* — replace with credential theft via AWS: key **AKIAJOGCDXJ5NW5PXUPA**, secret `Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk` | Q218, Q220 |
| `ransomware_note` | *drop* — no ransomware in BOTSv3. Use the Linux backdoor instead: port **1337**, PID **14356**, user **svcvnc**, password `ilovedavidverve` | Q303–Q305 |
| `dns_tunneling` | **brewertalk.com** — avg third-level subdomain length **8.10** | Q224 |
| `exfil_ip` | *drop the IP* — exfil in BOTSv3 is **S3**: bucket **frothlywebcode** made public by **bstoll**, file `OPEN_BUCKET_PLEASE_FIX.txt`, 2.93 MB `.tar.gz` | Q204–Q206 |
| `suspicious_user_auth` | keep; add **199.66.91.253** (external IP, expired-account login) | Q301 |

Other IOCs worth cases: attachment `Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm`
(Q310), 7 extracted files (Q312), `colonel.c` / `definitelydontinvestigatethisfile.sh`
streamed to `/tmp` (Q315), brute force from **Russia** (Q318), password
`Password123!` (Q320), disabled accounts `bgist@froth.ly` / `fyodor@froth.ly` (Q309).

### Two caveats — read before trusting any single value

1. **These come from community writeups, not Splunk's official answer file.**
   Corroborated across several independent sources (`clo.ng/blog/bots-part1..5`,
   `wind-flow.github.io/splunk/splunk-BOTS-v3-part1..3`,
   `github.com/splunk/botsv3`), but treat each value as verify-on-first-use. The
   cheapest verification is the query itself — if `splunk_run_query` returns the
   documented answer, the value is good.
2. **BOTSv3 is heavily AWS/CloudTrail flavoured, and our routing has nowhere to
   put it.** `aws:cloudtrail`, `aws:s3:accesslogs`, `aws:cloudwatchlogs:vpcflow`
   carry the richest documented answers (S3 exfil, IAM key compromise) and
   `routing._CATEGORY_DOMAIN` maps none of them — they would land in
   `uncategorised` and fan out by entity kind. **Decide before building AWS cases:**
   either add a CIM mapping, or scope the answer sheet to the endpoint/network/
   identity evidence BOTSv3 also has. This is an architectural call, not a
   labelling one.

### Suggested order

1. Fix `coinhive` first — it needs no change, only `expected_disposition`. It is the
   one case where a green result means something today.
2. Add `expected_disposition: Disposition` to `BENCHMARK_CASES` beside
   `expected_families`, and score it next to the existing
   `routing_correct = set(dispatched) == set(expected_families)` (`bench.py:578`).
   **That routing metric has never meant anything** — until `e6df52c` every run
   used the synthesized fallback, so `dispatched` reflected what the model
   *claimed*. It is real now.
3. Swap the indicators above, one case at a time, verifying each with
   `splunk_run_query` before writing an expectation.
4. Only then consider prompt tuning. Anything before this is tuned against vibes.

---

## Why an LLM-as-judge is still not the answer

Raised this session and deliberately deferred. The short version, so it is not
re-litigated from scratch:

- **A judge is not an answer key.** It gives *a* label, not a *true* one. Tuning
  against a judge's opinion of an 8B model's opinion measures agreement, not
  correctness — and BOTSv3's answers are *published*, so the gold set can just be
  written down.
- **You cannot evaluate a judge without labelled data either.** The gold set is a
  prerequisite, not an alternative.
- **A judge in the run path would undo `852e090`.** Verdicts are byte-reproducible
  now; a nondeterministic judge reintroduces the variance one layer up. If one ever
  lands it belongs offline in `blind_compare`, not in `gather()`.
- **The specific worry — "verdicts on empty rows" — is already detected.**
  `_as_judgement` flags a decisive disposition whose every cited block has
  `row_count == 0`. It `logger.warning`s, which the default log level discards, and
  `_print_findings` marks `<- EMPTY` per exhibit. Two cheap patches beat a judge:
  surface the warning, and put a `rests_on_empty_evidence` flag on
  `DomainJudgement` so it reaches the published schema.
- **The genuinely judge-shaped problem is the inverse**: a claim citing rows that
  *do* exist but do not support it. One observed draw called an IP "known
  malicious" whose cited row read `mal=1` of 91. `_as_judgement` concedes this is
  defect (c) and undecidable in code. That is where a judge would earn its place —
  after the gold set exists.

---

## Do not break

- **Never write under `.smartops/runs/`** — protected fixture. Point
  `SMARTOPS_RUNS_DIR` at a scratch directory and verify the tree afterwards.
- **`env -u AWS_PROFILE`, not `AWS_PROFILE=`.** The empty form is now handled
  (`a8ae6aa`) but `env -u` is unambiguous. A stale profile named alongside
  explicit keys is dropped with a warning.
- **`uv run python docs/fix_anchors.py`** after any refactor that moves lines, then
  `docs/check_anchors.py` to verify. This session's changes broke 23 anchors, then
  10 more an hour later.
- **The blind guarantee is structural.** `gather_finding(model, scope, slice_)` and
  `build_facts_user_turn(scope, evidence_text)` take no hypothesis. Do not add a
  parameter that could carry one.
- **`docs/confluence-subagent-analysts.md` stays untracked**, per its own scope.

## Span-parsing snippet

```python
import json, os
from pathlib import Path
log = Path(os.environ["TEMP"]) / "siem-trace.log"
spans, depth, buf = [], 0, []
for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
    if line.startswith("{"): depth += 1
    if depth: buf.append(line)
    if line.startswith("}") and depth:
        depth -= 1
        try: spans.append(json.loads("\n".join(buf)))
        except Exception: pass
        buf = []

traces = {}
for s in spans:
    traces.setdefault(s["context"]["trace_id"], []).append(s)
print(f"spans={len(spans)}  DISTINCT TRACES={len(traces)}")

by_id = {s["context"]["span_id"]: s for s in spans}
for tid, group in traces.items():
    kids = {}
    for s in group:
        kids.setdefault(s.get("parent_id"), []).append(s)
    def show(pid, ind=1):
        for s in sorted(kids.get(pid, []), key=lambda x: x["start_time"]):
            a, st = s.get("attributes", {}), s.get("status", {})
            extra = "".join(
                f"  {k}={a[k]}" for k in ("run_id", "tool_family", "analyst.disposition")
                if k in a
            )
            err = f"  !! {st.get('description')}" if st.get("status_code") == "ERROR" else ""
            print("  " * ind + f'{s["name"]}{extra}{err}')
            show(s["context"]["span_id"], ind + 1)
    print(f"\nTRACE {tid}")
    show(None)
```

## Where things are

- **Committed and pushed:** `45866c4..9c2646c`, tag
  `analyst-hardening-2026-08-30` (`git show` it for the full patch breakdown).
- **Untracked by design:** `scratchpad/*.py` (probe scripts — on disk, never
  committed, so they survive a session but not a clone),
  `docs/confluence-subagent-analysts.md`, `graphify-out/`.
- **Live verification artifacts** from this session:
  `$TEMP/vt-verify2-runs/` (all four artifacts, first run to write
  `findings.json` + `traces.json`) and `$TEMP/vt-verify2.log` (38 spans, the
  post-fix trace).
