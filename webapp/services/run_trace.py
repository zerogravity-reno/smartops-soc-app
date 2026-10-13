"""One investigation, end to end, under the webapp's run_id.

The main Analyst and the Tool Broker run in different processes. Everything that
joins them is written here: the task file the Analyst's plan became, the broker
runs it produced (with their trace ids), the payload that went back, and every
Analyst output -- one `investigation.jsonl` per run.
"""

import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# The Analyst's entity vocabulary -> the engine's `EntityKind`. Anything absent
# (e.g. "environment") has no engine kind and is dropped, and the drop is recorded.
_KIND = {
    "host": "host", "hostname": "host", "dest": "host", "computer": "host", "device": "host",
    "user": "user", "username": "user", "user_name": "user", "account": "user",
    "ip": "ip", "src_ip": "ip", "dest_ip": "ip", "ip_address": "ip", "ipaddress": "ip", "source_ip": "ip", "destination_ip": "ip",
    "domain": "domain", "url": "url", "uri": "url",
    "file_hash": "file_hash", "hash": "file_hash", "sha256": "file_hash", "sha1": "file_hash", "md5": "file_hash",
    "process": "process", "process_name": "process", "process_id": "process_id", "pid": "process_id",
    "process_guid": "process_guid", "processguid": "process_guid", "guid": "process_guid",
    "file": "file_name", "file_name": "file_name", "filename": "file_name", "image": "file_name",
    "file_path": "file_name", "path": "file_name", "process_path": "file_name",
    "command": "command_line", "command_line": "command_line", "commandline": "command_line", "cmdline": "command_line",
}


def _sha256(value) -> str | None:
    """The SHA256 out of Sysmon's `MD5=…,SHA256=…,IMPHASH=…`, or a bare one."""
    m = re.search(r"\b([0-9A-Fa-f]{64})\b", str(value or ""))
    return m.group(1) if m else None


def alert_entities(context: dict) -> list[dict]:
    """The alert's host, user, source IP, file hash and Sysmon process GUID as
    engine entities: the scope for a task that only says "search the logs"."""
    seed = (context or {}).get("normalized_seed") or {}
    ent = seed.get("entities") or {}
    guid = next((d.get("process_guid") for d in (seed.get("process"), seed.get("finding"))
                 if isinstance(d, dict) and d.get("process_guid")), None)
    picks = [("host", ent.get("hostname") or ent.get("host")), ("user", ent.get("user")), ("ip", ent.get("src_ip")),
             ("file_hash", _sha256((seed.get("file") or {}).get("sha256"))), ("process_guid", guid)]
    return [{"type": kind, "value": str(value).strip()} for kind, value in picks if value and str(value).strip()]


def _instant(value) -> datetime | None:
    """A timezone-aware ISO 8601 instant, or None for anything else (placeholders, naive times)."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def notable_event_time(ev: dict) -> str:
    """When the alert's event happened, in UTC. A notable's `_time` is when ES ran the
    search, often an hour after the event. ESCU's `firstTime` is the event, written
    without an offset in the search head's zone, the same zone `_time` is rendered in."""
    def one(key):
        v = ev.get(key)
        return (v[0] if isinstance(v, list) and v else v) or ""

    t, first = _instant(one("_time")), str(one("firstTime")).strip()
    try:
        if first.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(first), UTC).isoformat()
        if first and t:
            # ponytail: assumes firstTime shares _time's offset; true while ES and the saved search use one zone
            return datetime.fromisoformat(first).replace(tzinfo=t.tzinfo).astimezone(UTC).isoformat()
    except ValueError:
        pass
    return t.astimezone(UTC).isoformat() if t else str(one("_time"))


def notables_spl(rule_pattern: str | None = None) -> str:
    """The one base search the queue and the import share, newest first, one row
    per event. ESCU rules run every 5 minutes over a 60-minute span with no
    throttle, so each event was raised 12 times (2026-10-08). The queue and
    `?index=` must read the same list, or an index names a different row.
    `rule_pattern` is already SPL-escaped by the caller."""
    rule = f' (search_name="{rule_pattern}" OR source="{rule_pattern}")' if rule_pattern else ""
    return f"search index=notable{rule} | dedup search_name dest firstTime keepempty=true | sort -_time"


_URGENCY = ("informational", "low", "medium", "high", "critical")


def group_notables(rows: list[dict]) -> list[dict]:
    """Queue rows, newest first, folded by rule and host: repeats of one rule on one
    host filled the queue. Groups keep first-seen order, so each sits where its
    newest instance would; every row keeps its `index` for the import."""
    rank = lambda u: _URGENCY.index(u) if u in _URGENCY else -1
    groups: dict[tuple, dict] = {}
    for row in rows:
        g = groups.setdefault((row.get("rule_name"), row.get("dest")), {
            "rule_name": row.get("rule_name"), "dest": row.get("dest"), "time": row.get("time"),
            "urgency": "", "users": [], "srcs": [], "events": []})
        g["events"].append(row)
        if rank(str(row.get("urgency", "")).lower()) > rank(g["urgency"]):
            g["urgency"] = str(row["urgency"]).lower()
        for key, field in (("users", "user"), ("srcs", "src")):
            if row.get(field) and row[field] not in g[key]:
                g[key].append(row[field])
    return [{**g, "count": len(g["events"])} for g in groups.values()]


def runs_dir() -> Path:
    # Same resolution the engine uses, anchored at the repo because the engine runs there.
    return REPO / (os.environ.get("SMARTOPS_RUNS_DIR", "").strip() or ".smartops/runs")


def trace_id(run_id: str) -> str:
    """The run's one W3C trace id (O5), derived so every caller agrees without state.
    874ab334 was 9 traces: one per Broker task, none for the Analyst's calls."""
    return hashlib.sha256(run_id.encode()).hexdigest()[:32]


def traceparent(run_id: str, loop: int) -> str:
    """The parent a Broker round's spans hang from: one per round, all in the run's trace."""
    return f"00-{trace_id(run_id)}-{hashlib.sha256(f'{run_id}-L{loop}'.encode()).hexdigest()[:16]}-01"


def record(run_id: str, step: str, loop: int, **data) -> None:
    target = runs_dir() / run_id
    target.mkdir(parents=True, exist_ok=True)
    line = {"at": datetime.now(UTC).isoformat(), "step": step, "loop": loop, "trace_id": trace_id(run_id), **data}
    with (target / "investigation.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(line, default=str) + "\n")


_EVENT_MARGIN = timedelta(hours=1)


def to_task_file(tasks: list, run_id: str, loop: int, alert_scope: list | None = None,
                 event_time: str | None = None) -> tuple[dict, list]:
    """The Analyst's tasks as a `task-input.v1` file, plus what could not be sent.

    The engine's `TaskInputFile` stays the validator; this only renames what the
    two sides spell differently and drops what has no engine equivalent, so one
    bad task costs that task rather than the whole file.

    A task with no searchable entity -- one that names where to look ("log",
    "script_block_log", "scheduled_task") rather than a value to match -- is sent
    scoped to `alert_scope`, the alert's own host/user/ip: the siem family already
    searches the lab's indexes (SMARTOPS_SIEM_INDEXES), and the question carries
    what to look for. Without an alert scope it is dropped, and the drop recorded.

    Each window is widened to cover `event_time` +/- 1h, the floor the planning
    prompt asks for, and capped at now. On 5aae1a35 T1 got 18:41:51-18:42:51, a
    minute starting at the event, so the parent process created before it was
    out of reach for the third run running. A wider window the Analyst chose stays.
    """
    event = _instant(event_time)
    out, dropped = [], []
    for n, task in enumerate(tasks, 1):
        if not isinstance(task, dict):
            dropped.append({"task_id": None, "why": "not a task object", "task": task})
            continue
        raw = task.get("entity")
        entities, unusable = [], []
        for e in raw if isinstance(raw, list) else [raw]:
            label = str((e or {}).get("type", "")).lower() if isinstance(e, dict) else ""
            # "scheduled_task|group_policy": the model sometimes joins several types into one.
            kind = next((_KIND[t.strip()] for t in label.replace(",", "|").split("|") if t.strip() in _KIND), None)
            if kind and e.get("value"):
                # A PID sent as a process name (148b0e69's T3 sent `process=2900`).
                if kind == "process" and str(e["value"]).strip().isdigit():
                    kind = "process_id"
                # `powershell.exe (PID 12345)` (874ab334) is two values: a name and a PID.
                pid = re.fullmatch(r"(.+?)\s*\(PID\s*(\d+)\)", str(e["value"]).strip(), re.I) if kind == "process" else None
                if pid:
                    entities.append({"type": "process", "value": pid[1]})
                    entities.append({"type": "process_id", "value": pid[2]})
                    continue
                entities.append({"type": kind, "value": e["value"]})
            else:
                unusable.append(e.get("type") if isinstance(e, dict) else e)

        def drop(why):
            dropped.append({"task_id": task.get("task_id"), "question": task.get("question"), "why": why, "task": task})

        rescoped = not entities and bool(alert_scope)
        if rescoped:
            entities = [dict(e) for e in alert_scope]
        elif alert_scope:
            # Every task carries the alert's host, hash and process GUID. Without
            # the host the siem agent wrote `index=*` searches and was blocked (T3:
            # 26 times); without the hash the Broker could not choose VT (T2); a
            # PID alone matched six other processes on 5aae1a35, the GUID one.
            # The Broker decides whether to use them.
            have = {e["type"] for e in entities}
            entities += [dict(e) for e in alert_scope
                         if e["type"] in ("host", "file_hash", "process_guid") and e["type"] not in have]
        if not entities:
            drop(f"no entity the broker can search on (got: {', '.join(map(str, unusable)) or 'none'})")
            continue
        if not task.get("question"):
            drop("no question")
            continue
        asked = task.get("time_window") if isinstance(task.get("time_window"), dict) else {}
        start, end = (_instant(asked.get(k)) for k in ("start", "end"))
        # Widened before it is checked (B19): c90ca5f9's lookups (a path, a hash) had
        # start == end at the event and were dropped. A missing or empty window
        # becomes event +/- 1h; one the Analyst chose wider stays.
        widened = False
        if event:
            floor = (min(start or event, event - _EVENT_MARGIN),
                     min(max(end or event, event + _EVENT_MARGIN), datetime.now(UTC)))
            widened, (start, end) = floor != (start, end), floor
        # Checked here so an unusable window costs its own task: the engine's
        # `Scope` would reject it too, but at file load, taking every task with it.
        if not (start and end and start < end):
            drop("the time window needs a timezone-aware start and end, start first")
            continue
        window = {k: v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") for k, v in zip(("start", "end"), (start, end))}
        if widened:
            dropped.append({"task_id": task.get("task_id"), "question": task.get("question"), "sent": True,
                            "why": f"window {asked.get('start')}..{asked.get('end')} sent as "
                                   f"{window['start']}..{window['end']}: event +/- 1h, never past now"})
        if rescoped:
            dropped.append({"task_id": task.get("task_id"), "question": task.get("question"), "sent": True,
                            "why": f"{', '.join(map(str, unusable)) or 'no entity'} is not a value to match: sent scoped to the alert's "
                                   + ", ".join(f"{e['type']}={e['value']}" for e in entities) + " across the lab's indexes"})
        elif unusable:
            # Sent without them, and said so -- a silently narrowed task reads as the one asked.
            dropped.append({"task_id": task.get("task_id"), "question": task.get("question"), "sent": True,
                            "why": f"sent without entities the broker cannot search on: {', '.join(map(str, unusable))}"})
        task_id = f"{run_id}-L{loop}-{task.get('task_id') or f'T{n}'}"
        out.append({
            "task_id": task_id,
            # Unique per task, as `TaskInputFile` requires; the plan decouples
            # tasks from hypotheses, so the task is its own join key.
            "hypothesis_id": task_id,
            "question": task["question"],
            "entity": entities,
            "time_window": window,
        })
    return {"schema_version": 1, "tasks": out}, dropped


def _task_key(task: dict) -> tuple:
    entities = frozenset((e.get("type"), e.get("value")) for e in task.get("entity") or [])
    window = task.get("time_window") or {}
    return " ".join(str(task.get("question", "")).lower().split()), entities, window.get("start"), window.get("end")


def follow_up_tasks(follow_ups: list, sent: list, gaps: list | None = None, asked: list | None = None) -> list:
    """Synthesis follow-ups as tasks for the next broker round.

    Follow-ups carry only a question, so they inherit every entity and the whole
    window of the tasks just sent. With no follow-ups, each evidence gap becomes
    one (T17): a gap left unasked ended the run with the gap unexamined.

    A follow-up identical to a task in `asked` (every task already sent, any
    round) is dropped (W10): on 89674d75 the same three gaps came back and round 4
    re-ran round 3 unchanged. Nothing new left means the run ends.
    """
    # ponytail: union of entities + widest window; per-follow-up scoping needs the
    # synthesis prompt to emit entity/time_window, which is the main Analyst's side.
    if not sent:
        return []
    if not any(isinstance(f, dict) and f.get("question") for f in follow_ups or []):
        follow_ups = [{"task_id": f"G{n}", "question": g}
                      for n, g in enumerate((g for g in gaps or [] if isinstance(g, str) and g.strip()), 1)]
    entities = list({(e["type"], e["value"]): e for t in sent for e in t["entity"]}.values())
    starts = [t["time_window"]["start"] for t in sent]
    ends = [t["time_window"]["end"] for t in sent]
    # Every window here already passed `to_task_file`, so `_instant` never returns None.
    window = {"start": min(starts, key=_instant), "end": max(ends, key=_instant)}
    seen = {_task_key(t) for t in asked or []}
    tasks = [
        {"task_id": f.get("task_id"), "question": f["question"], "entity": entities, "time_window": window}
        for f in follow_ups
        if isinstance(f, dict) and f.get("question")
    ]
    return [t for t in tasks if _task_key(t) not in seen]


def compact_round(payload: dict, evaluation: dict) -> dict:
    """An older round as synthesis re-reads it: what was asked, which domains
    answered, and what the evaluation after it concluded. Narratives and
    summaries are left out; the record is built here, not by a model (W8).
    """
    # ponytail: 0.9-1.8 kB a round on b3aa0dd2; `packing._COMPACT_ROUNDS_RESERVE` covers
    # ~10 of them, so cap per task if a run nears 15 rounds.
    return {
        "tasks": [
            {"task_id": p.get("task_id"), "question": p.get("hypothesis"),
             "domains_with_observations": [f["domain"] for f in p.get("findings", []) if f.get("observations")]}
            for p in payload.get("payloads", [])
        ],
        "evaluation": {k: evaluation[k] for k in
                       ("hypothesis_scores", "verdict", "evidence_refs", "refused_refs", "evidence_gaps")
                       if evaluation.get(k)},
    }


def _ref_problem(ref: str, payloads: list, runs: list) -> tuple[str | None, str | None]:
    """(the cited task's question, why `ref` is no broker finding), or (None, None) when it is one.

    A ref is `<task>:<domain>` or `<task>:<block id>`, the task as the run's full
    id or its short `T1` tail. It holds when that task ran, the domain has
    observations or the block is cited in its findings, and none of the task's
    steps was rejected or left incomplete.
    """
    task, _, what = ref.partition(":")
    hits = [p for p in payloads if task and (p.get("task_id") == task or str(p.get("task_id", "")).endswith("-" + task))]
    if not hits:
        return None, f"{ref}: no task {task!r} ran"
    question = hits[0].get("hypothesis")
    findings = [f for p in hits for f in p.get("findings", [])]
    cited = any(f.get("domain") == what and f.get("observations") for f in findings) or (
        "#" in what and any(f"[{what}]" in " ".join([f.get("narrative", ""), *f.get("observations", [])]) for f in findings))
    if not cited:
        return question, f"{ref}: {what!r} is neither a domain with observations nor a block cited in {task}'s findings"
    ids = {p.get("task_id") for p in hits}
    for run in runs:
        if run.get("task_id") in ids:
            for st in run.get("steps", []):
                if not st.get("completed") or st.get("status") == "rejected":
                    state = "rejected" if st.get("status") == "rejected" else "incomplete"
                    return question, f"{ref}: step {st.get('step_id')} is {state}"
    return None, None


def verdict_gate(synth: dict, plan: dict, payloads: list | None = None, runs: list | None = None) -> dict:
    """The synthesis output with `status` decided here, not by the model.

    VERDICT_REACHED needs the top hypothesis at 85 or more and 20 clear of the
    runner-up. Evidence refs are informational only and do not block the verdict.
    """
    out = dict(synth)
    scores = {}
    for h, s in (synth.get("hypothesis_scores") or {}).items():
        try:
            scores[h] = int(s)
        except (TypeError, ValueError):
            scores[h] = 0
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_id, top = ranked[0] if ranked else (None, 0)
    gap = top - (ranked[1][1] if len(ranked) > 1 else 0)
    if top >= 85 and gap >= 20:
        out["status"] = "VERDICT_REACHED"
        out["follow_up_tasks"] = []
        if not out.get("verdict") or out["verdict"] == "REQUIRES_INVESTIGATION":
            out["verdict"] = next((h.get("verdict") for h in plan.get("hypotheses", []) if h.get("id") == top_id),
                                  "REQUIRES_INVESTIGATION")
        return out
    out["status"] = "REQUIRES_INVESTIGATION"
    return out


def broker_runs(task_ids: list[str], round_dir: Path) -> list[dict]:
    """What the Tool Broker did for each task, read from its `report.json` in the
    run's own `L<n>/` folder (O5), found by the `task_id` the report names.

    The fetch plan with each step's outcome, and every dispatch with the queries it
    ran and any the guards blocked -- the Broker's side of the loop, in the shape
    the UI renders. `run_dir` is None for a task the broker never recorded.
    """
    by_task = {json.loads(p.read_text(encoding="utf-8")).get("task_id"): p for p in round_dir.glob("*/report.json")}
    runs = []
    for task_id in task_ids:
        report_path = by_task.get(task_id)
        if report_path is None:
            runs.append({"task_id": task_id, "run_dir": None})
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        outcomes = {o["step"]["step_id"]: o for o in report.get("step_outcomes", [])}
        runs.append({
            "task_id": task_id,
            "run_dir": str(report_path.parent),
            "trace_id": report.get("trace_id"),
            "plan_rationale": (report.get("plan") or {}).get("rationale"),
            # What the CLI prints beside the plan: why these families, guard repairs, spend.
            "classification": (report.get("classification") or {}).get("rationale"),
            "plan_repairs": report.get("plan_repairs") or [],
            "spend_micro_usd": (report.get("cost") or {}).get("total_spend_micro_usd"),
            "steps": [
                {
                    "step_id": s["step_id"],
                    "family": s["family"],
                    "objective": s["objective"],
                    "categories": s.get("completion", {}).get("categories", []),
                    **{k: outcomes.get(s["step_id"], {}).get(k) for k in
                       ("completed", "rows_retrieved", "confirmed_empty", "status", "reason")},
                }
                for s in (report.get("plan") or {}).get("steps", [])
            ],
            "dispatched": report.get("dispatched", []),
            "results": [
                {
                    # Result ids are `<task>:<family>:<tool-use id>`.
                    "family": (r.get("task_id") or "").split(":")[1] if ":" in (r.get("task_id") or "") else "?",
                    "status": r.get("status"),
                    "reason": r.get("reason"),
                    "error": r.get("error"),
                    "gaps": r.get("gaps", []),
                    "queries": [q.get("query") for q in r.get("queries_run", [])],
                    "blocked": r.get("blocked_queries", []),
                }
                for r in report.get("results", [])
            ],
        })
    return runs


def handshake(sent: list[str], runs: list[dict], payload: dict | None) -> dict:
    """Did every task the Analyst sent come back? `sent -> fetched -> returned`, by task id."""
    fetched = [r["task_id"] for r in runs if r.get("run_dir")]
    returned = [p.get("task_id") for p in (payload or {}).get("payloads", [])]
    return {
        "sent": sent,
        "fetched": fetched,
        "returned": returned,
        "not_fetched": [t for t in sent if t not in fetched],
        "not_returned": [t for t in sent if t not in returned],
        "unexpected": [t for t in returned if t not in sent],
    }
