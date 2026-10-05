"""One investigation, end to end, under the webapp's run_id.

The main Analyst and the Tool Broker run in different processes. Everything that
joins them is written here: the task file the Analyst's plan became, the broker
runs it produced (with their trace ids), the payload that went back, and every
Analyst output -- one `investigation.jsonl` per run.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# The Analyst's entity vocabulary -> the engine's `EntityKind`. Anything absent
# (e.g. "command") has no engine kind and is dropped, and the drop is recorded.
_KIND = {
    "host": "host", "hostname": "host", "dest": "host",
    "user": "user",
    "ip": "ip", "src_ip": "ip", "dest_ip": "ip",
    "domain": "domain", "url": "url",
    "file_hash": "file_hash", "hash": "file_hash",
    "process": "process", "process_name": "process",
}


def _instant(value) -> datetime | None:
    """A timezone-aware ISO 8601 instant, or None for anything else (placeholders, naive times)."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def runs_dir() -> Path:
    # Same resolution the engine uses, anchored at the repo because the engine runs there.
    return REPO / (os.environ.get("SMARTOPS_RUNS_DIR", "").strip() or ".smartops/runs")


def record(run_id: str, step: str, loop: int, **data) -> None:
    target = runs_dir() / run_id
    target.mkdir(parents=True, exist_ok=True)
    line = {"at": datetime.now(UTC).isoformat(), "step": step, "loop": loop, **data}
    with (target / "investigation.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(line, default=str) + "\n")


def to_task_file(tasks: list, run_id: str, loop: int) -> tuple[dict, list]:
    """The Analyst's tasks as a `task-input.v1` file, plus what could not be sent.

    The engine's `TaskInputFile` stays the validator; this only renames what the
    two sides spell differently and drops what has no engine equivalent, so one
    bad task costs that task rather than the whole file.
    """
    out, dropped = [], []
    for n, task in enumerate(tasks, 1):
        if not isinstance(task, dict):
            dropped.append({"task_id": None, "why": "not a task object", "task": task})
            continue
        raw = task.get("entity")
        entities, unusable = [], []
        for e in raw if isinstance(raw, list) else [raw]:
            kind = _KIND.get(str((e or {}).get("type", "")).lower()) if isinstance(e, dict) else None
            if kind and e.get("value"):
                entities.append({"type": kind, "value": e["value"]})
            else:
                unusable.append(e.get("type") if isinstance(e, dict) else e)

        def drop(why):
            dropped.append({"task_id": task.get("task_id"), "question": task.get("question"), "why": why, "task": task})

        if not entities:
            drop(f"no entity the broker can search on (got: {', '.join(map(str, unusable)) or 'none'})")
            continue
        if not task.get("question"):
            drop("no question")
            continue
        window = task.get("time_window") if isinstance(task.get("time_window"), dict) else {}
        start, end = (_instant(window.get(k)) for k in ("start", "end"))
        # Checked here so a placeholder window costs its own task: the engine's
        # `Scope` would reject it too, but at file load, taking every task with it.
        if not (start and end and start < end):
            drop("the time window needs a timezone-aware start and end, start first")
            continue
        if unusable:
            # Sent without them, and said so -- a silently narrowed task reads as the one asked.
            dropped.append({"task_id": task.get("task_id"), "question": task.get("question"),
                            "why": f"sent without entities the broker cannot search on: {', '.join(map(str, unusable))}"})
        task_id = f"{run_id}-L{loop}-{task.get('task_id') or f'T{n}'}"
        out.append({
            "task_id": task_id,
            # Unique per task, as `TaskInputFile` requires; the plan decouples
            # tasks from hypotheses, so the task is its own join key.
            "hypothesis_id": task_id,
            "question": task["question"],
            "entity": entities,
            "time_window": task["time_window"],
        })
    return {"schema_version": 1, "tasks": out}, dropped


def follow_up_tasks(follow_ups: list, sent: list) -> list:
    """Synthesis follow-ups as tasks for the next broker round.

    Follow-ups carry only a question, so they inherit every entity and the whole
    window of the tasks just sent.
    """
    # ponytail: union of entities + widest window; per-follow-up scoping needs the
    # synthesis prompt to emit entity/time_window, which is the main Analyst's side.
    if not sent:
        return []
    entities = list({(e["type"], e["value"]): e for t in sent for e in t["entity"]}.values())
    starts = [t["time_window"]["start"] for t in sent]
    ends = [t["time_window"]["end"] for t in sent]
    # Every window here already passed `to_task_file`, so `_instant` never returns None.
    window = {"start": min(starts, key=_instant), "end": max(ends, key=_instant)}
    return [
        {"task_id": f.get("task_id"), "question": f["question"], "entity": entities, "time_window": window}
        for f in follow_ups
        if isinstance(f, dict) and f.get("question")
    ]


def verdict_gate(synth: dict, plan: dict) -> dict:
    """The synthesis output with `status` decided here, not by the model.

    VERDICT_REACHED needs the top hypothesis at 85 or more, 20 clear of the
    runner-up, and at least one cited broker finding (an `ALERT:` ref is the
    alert itself, not evidence). Anything short of that investigates again.
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
    refs = [r for r in synth.get("evidence_refs") or [] if isinstance(r, str) and not r.startswith("ALERT:")]
    if top >= 85 and gap >= 20 and refs:
        out["status"] = "VERDICT_REACHED"
        out["follow_up_tasks"] = []
        if not out.get("verdict") or out["verdict"] == "REQUIRES_INVESTIGATION":
            out["verdict"] = next((h.get("verdict") for h in plan.get("hypotheses", []) if h.get("id") == top_id),
                                  "REQUIRES_INVESTIGATION")
        return out
    out["status"] = "REQUIRES_INVESTIGATION"
    if top >= 85 and gap >= 20:
        out["evidence_gaps"] = [*(out.get("evidence_gaps") or []),
                                "No broker finding cited in evidence_refs: the verdict has no evidence behind it"]
    return out


def broker_runs(task_ids: list[str]) -> list[dict]:
    """What the Tool Broker did for each task, read from its `report.json` via `latest.txt`.

    The fetch plan with each step's outcome, and every dispatch with the queries it
    ran and any the guards blocked -- the Broker's side of the loop, in the shape
    the UI renders. `run_dir` is None for a task the broker never recorded.
    """
    runs = []
    for task_id in task_ids:
        case = runs_dir() / task_id
        pointer = case / "latest.txt"
        report_path = case / pointer.read_text(encoding="utf-8").strip() / "report.json" if pointer.is_file() else None
        if report_path is None or not report_path.is_file():
            runs.append({"task_id": task_id, "run_dir": None})
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        outcomes = {o["step"]["step_id"]: o for o in report.get("step_outcomes", [])}
        runs.append({
            "task_id": task_id,
            "run_dir": str(report_path.parent),
            "trace_id": report.get("trace_id"),
            "plan_rationale": (report.get("plan") or {}).get("rationale"),
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
