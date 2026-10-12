"""The Analyst agent: plans an investigation from the alert's context, hands its
tasks to the Tool Broker, and evaluates what comes back until a verdict holds.

The system prompt is `prompts/analyst_system_prompt.txt`. The verdict is gated
here by code (`verdict_gate`), not taken from the model.
"""

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from smartops.context import _instant

PROMPT_PATH = Path(__file__).parent / "prompts" / "analyst_system_prompt.txt"

FULL_ROUNDS = 2  # rounds synthesis reads in full; packing._ANALYST_ROUNDS must match


def load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def extract_json(text):
    import re as _re, json as _json
    cleaned = _re.sub(r"^```json\s*", "", text.strip())
    cleaned = _re.sub(r"\s*```$", "", cleaned)
    try:
        return _json.loads(cleaned)
    except _json.JSONDecodeError:
        pass
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        try:
            return _json.loads(text[first:last + 1])
        except _json.JSONDecodeError:
            pass
    i = first if first != -1 else 0
    while i < len(text):
        if text[i] == "{":
            depth, start = 0, i
            for j in range(i, len(text)):
                if text[j] == "{": depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = _json.loads(text[start:j+1])
                            if any(k in obj for k in ("hypotheses","verdict","hypothesis_scores","model_reasoning","status","tasks")):
                                return obj
                        except: pass
                        i = j; break
        i += 1
    return None


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

    VERDICT_REACHED needs the top hypothesis at 85 or more, 20 clear of the
    runner-up, and cited broker findings that all hold (`_ref_problem`, against
    every round's `payloads` and broker `runs`; an `ALERT:` ref is the alert
    itself, not evidence). Anything short of that investigates again, and a
    blocked verdict's failed refs become gaps: the cited task's question again.
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
    bad = [p for p in (_ref_problem(r, payloads or [], runs or []) for r in refs) if p[1]]
    if top >= 85 and gap >= 20 and refs and not bad:
        out["status"] = "VERDICT_REACHED"
        out["follow_up_tasks"] = []
        if not out.get("verdict") or out["verdict"] == "REQUIRES_INVESTIGATION":
            out["verdict"] = next((h.get("verdict") for h in plan.get("hypotheses", []) if h.get("id") == top_id),
                                  "REQUIRES_INVESTIGATION")
        return out
    out["status"] = "REQUIRES_INVESTIGATION"
    if top >= 85 and gap >= 20:
        gaps = list(out.get("evidence_gaps") or [])
        if not refs:
            gaps.append("No broker finding cited in evidence_refs: the verdict has no evidence behind it")
        gaps += [q for q in dict.fromkeys(q for q, _ in bad) if q and q not in gaps]
        out["evidence_gaps"] = gaps
        if bad:
            out["refused_refs"] = [why for _, why in bad]
    return out


def broker_runs(task_ids: list[str], fetched: list) -> list[dict]:
    """What the Tool Broker did for each task, from the round's outcomes
    (`RoundResult.fetched`, by the `task_id` each report names).

    The fetch plan with each step's outcome, and every dispatch with the queries it
    ran and any the guards blocked -- the Broker's side of the loop, in the shape
    the UI renders. `run_dir` is None for a task the broker never recorded.
    """
    by_task = {o.report.task_id: o for _, _, o in fetched if o.report is not None}
    runs = []
    for task_id in task_ids:
        outcome = by_task.get(task_id)
        if outcome is None:
            runs.append({"task_id": task_id, "run_dir": None})
            continue
        report = outcome.report.model_dump(mode="json")  # what `report.json` holds
        outcomes = {o["step"]["step_id"]: o for o in report.get("step_outcomes", [])}
        runs.append({
            "task_id": task_id,
            "run_dir": str(outcome.run_dir),
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
