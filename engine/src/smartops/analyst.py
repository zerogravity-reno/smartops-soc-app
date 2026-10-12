"""The Analyst agent: plans an investigation from the alert's context, hands its
tasks to the Tool Broker, and evaluates what comes back until a verdict holds.

The system prompt is `prompts/analyst_system_prompt.txt`. The verdict is gated
here by code (`verdict_gate`), not taken from the model.
"""

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from contracts import TaskInputFile
from smartops import telemetry
from smartops.broker import round_dir as broker_round_dir, runs_root
from smartops.context import _instant, alert_entities
from smartops.broker import round_args, run_round
from smartops.subagent_analysts.model import AnalystModel

PROMPT_PATH = Path(__file__).parent / "prompts" / "analyst_system_prompt.txt"

FULL_ROUNDS = 2  # rounds synthesis reads in full; packing._ANALYST_ROUNDS must match
MAX_GEN_LEN = 8192  # = packing._ANALYST_GENERATION_RESERVE, which sizes the handoff around it


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


class RunStopped(Exception):
    """Stop, at a stage boundary or mid-round: the run ends without a verdict."""


def emit(q, event_type: str, data: dict, **extra):
    q.put({"type": event_type, "data": data, "message": extra.get("message",""), **{k:v for k,v in extra.items() if k != "message"}})


class CutOff(Exception):
    """An Analyst call that hit its `max_gen_len` (stop_reason=length): its JSON, if
    any, is unfinished, so it is a model failure, not an answer to parse (T15)."""

    def __init__(self, stage: str, max_gen_len: int, result: dict):
        super().__init__(f"{stage} was cut off at {max_gen_len:,} tokens (stop_reason=length)")
        self.stage, self.max_gen_len, self.result = stage, max_gen_len, result


_model = None


def _ask(system: str, user: str, stage: str) -> dict:
    """One Analyst call on the engine's Foundation-Sec client, split at `</think>`.
    Raises `CutOff` when the model ran out of tokens."""
    global _model
    if _model is None:
        # The Analyst's own sampling, not the sub-analysts' SMARTOPS_ANALYST_* settings.
        _model = AnalystModel(temperature=0.0, top_p=0.95, max_gen_len=MAX_GEN_LEN)
    r = _model.invoke(system, user)
    reasoning, think, answer = r.generation.partition("</think>")
    if not think:
        reasoning, answer = "", r.generation
    result = {"reasoning": reasoning.strip(), "answer": answer.strip(), "think_closed": bool(think),
              "prompt_tokens": r.prompt_tokens, "generation_tokens": r.generation_tokens, "stop_reason": r.stop_reason}
    if r.stop_reason == "length":
        raise CutOff(stage, _model.max_gen_len, result)
    return result


def investigate(run_id: str, alert_context: dict, max_loops: int, q, checkpoint, ctrl: dict) -> None:
    """One investigation, start to end: plan, then Broker round and synthesis until
    the gate passes, the follow-ups run out, or `max_loops`. Every stage is an event
    on `q`, ending with done, error or stopped. `checkpoint()` raises `RunStopped`
    at a stage boundary; `ctrl["cancel"]` cancels a Broker round in flight."""
    system_prompt = load_system_prompt()
    at_loop = 1  # where a stop landed, for the run record
    try:
        # LOOP 1: Analyst
        emit(q, "analyst", {}, message="Loop 1 — Analyst planning...")
        # Strip prior analyst/synthesis keys so the model starts in planning mode.
        _STRIP_KEYS = {"planning_template", "analyst_plan", "synthesis",
                       "verdict", "status", "hypothesis_scores",
                       "verdict_confidence", "verdict_reasoning", "evidence_gaps"}
        clean_context = {k: v for k, v in alert_context.items() if k not in _STRIP_KEYS}
        user_msg = "[ALERT CONTEXT]\n" + json.dumps(clean_context, indent=2)
        checkpoint()
        r1 = _ask(system_prompt, user_msg, "planning")
        plan = extract_json(r1["answer"]) or {}
        plan["reasoning"] = r1["reasoning"]
        tokens1 = {"prompt_tokens": r1["prompt_tokens"], "generation_tokens": r1["generation_tokens"], "stop_reason": r1["stop_reason"]}
        emit(q, "analyst", plan, message="Loop 1 complete", tokens=tokens1)
        telemetry.record(run_id, "analyst_plan", 1, plan=plan, tokens=tokens1, context=clean_context)

        # LOOPS 2..N: Broker + Synthesis
        tasks = plan.get("tasks", [])
        # A verdict already in Loop 1 (the context was unambiguous) skips the broker.
        if not tasks and plan.get("status") == "VERDICT_REACHED":
            emit(q, "verdict", plan, message="VERDICT (direct): " + str(plan.get("verdict", "?")))
            q.put({"type": "done", "message": "Investigation complete"})
            return
        all_findings = {}
        all_runs = []  # every round's broker runs, for the verdict gate's step check
        evaluations = {}  # round label -> the gated synthesis that read it
        asked = []  # every task sent so far, so a repeat round is not sent (W10)
        for loop_num in range(2, max_loops + 2):
            at_loop = loop_num
            checkpoint()
            # Handoff -> broker log -> broker steps -> sub-analyst payload: each stage is
            # its own event, so the UI shows the handshake rather than a JSON dump.
            findings, link = _broker_round(
                tasks, run_id, loop_num, q, ctrl, alert_entities(alert_context),
                (alert_context.get("normalized_seed") or {}).get("event_time"))
            telemetry.record(run_id, "broker", loop_num, **link)
            if "broker_runs" in link:
                emit(q, "broker", {"runs": link["broker_runs"], "handshake": link["handshake"]},
                     loop=loop_num, message=f"Loop {loop_num}: Broker complete")
            if link.get("error"):
                # Never fall back to another run's artifacts: that is how eleven
                # loops were once judged on an unrelated alert's evidence.
                q.put({"type": "error", "message": f"Loop {loop_num} broker failed: {link['error']}", "trace": link})
                return
            all_findings[f"Round {loop_num}"] = findings
            all_runs += link.get("broker_runs", [])
            emit(q, "payload", findings, loop=loop_num, message=f"Loop {loop_num}: sub-analyst findings returned to the Analyst")

            # Synthesis — build accumulated findings sections
            emit(q, "synthesis", {}, loop=loop_num, message=f"Loop {loop_num} — Synthesis evaluating...")
            # The plan as context only, and the mode stated: with the whole plan the
            # model sometimes answered with another plan instead of an evaluation.
            plan_slim = {"hypotheses": plan.get("hypotheses", []), "tasks": tasks[:6],
                         "semantic_alignment": plan.get("semantic_alignment", "")}
            hyp_ids = [h.get("id", "") for h in plan_slim["hypotheses"]] or ["H1", "H2", "H3"]
            eval_header = (
                "YOU ARE NOW IN EVALUATION MODE.\n"
                f"The investigation has {len(hyp_ids)} hypotheses with IDs: {', '.join(hyp_ids)}.\n"
                "Output ONLY the EVALUATION JSON schema. Required fields:\n"
                "  hypothesis_scores: {" + ", ".join(f'"{h}": <0-100>' for h in hyp_ids) + "}\n"
                "  verdict: one of TRUE_POSITIVE / FALSE_POSITIVE / BENIGN / REQUIRES_INVESTIGATION\n"
                "  verdict_reasoning: string explanation\n"
                "  evidence_refs: the <task_id>:<domain> of each broker finding the verdict rests on\n"
                "  status: VERDICT_REACHED or REQUIRES_INVESTIGATION\n"
                "Do NOT output planning JSON (hypotheses list, tasks list).\n"
                "---\n"
            )
            sections = [eval_header + f"[INVESTIGATION PLAN (context only)]\n{json.dumps(plan_slim, indent=2)}"]
            # The last FULL_ROUNDS in full; older ones as a short record (W8): re-sending
            # every round outgrew the 32k window by round ~6. The gate still checks all rounds.
            labels = list(all_findings)
            for round_label in labels[:-FULL_ROUNDS]:
                record = compact_round(all_findings[round_label], evaluations.get(round_label, {}))
                sections.append(f"[EARLIER ROUND - {round_label}, summarised]\n{json.dumps(record, indent=2)}")
            for round_label in labels[-FULL_ROUNDS:]:
                slim = {k:v for k,v in all_findings[round_label].items() if k != "_raw_intel_dump"}
                sections.append(f"[BROKER FINDINGS - {round_label}]\n{json.dumps(slim, indent=2)}")
            checkpoint()
            rN = _ask(system_prompt, "\n\n".join(sections), "synthesis")
            raw_synth = extract_json(rN["answer"]) or {}
            synth = evaluations[f"Round {loop_num}"] = verdict_gate(raw_synth, plan, [p for r in all_findings.values() for p in r.get("payloads", [])], all_runs)
            emit(q, "synthesis", synth, loop=loop_num, reasoning=rN["reasoning"],
                 tokens={"prompt_tokens": rN["prompt_tokens"], "generation_tokens": rN["generation_tokens"]},
                 message=f"Loop {loop_num} — Synthesis complete: {synth.get('status','?')}")
            telemetry.record(run_id, "synthesis", loop_num, output=synth, model_status=raw_synth.get("status"),
                             reasoning=rN["reasoning"],
                             tokens={"prompt_tokens": rN["prompt_tokens"], "generation_tokens": rN["generation_tokens"]})

            status  = synth.get("status", "")
            verdict = synth.get("verdict", "")

            if status == "VERDICT_REACHED":
                emit(q, "verdict", synth, message=f"VERDICT: {verdict}")
                break
            if loop_num == max_loops + 1:
                emit(q, "verdict", {**synth, "verdict": verdict or "REQUIRES_INVESTIGATION"}, message="Max loops reached")
                break
            asked += link["tasks"]
            tasks = follow_up_tasks(synth.get("follow_up_tasks", []), link["tasks"],
                                    synth.get("evidence_gaps"), asked)
            if not tasks:
                emit(q, "verdict", {**synth, "verdict": verdict or "REQUIRES_INVESTIGATION"},
                     message="No new follow-up tasks (none given, or all already asked)")
                break

        q.put({"type": "done", "message": "Investigation complete"})

    except CutOff as cut:
        # The full generation goes on the record: what the model looped on (T15).
        telemetry.record(run_id, "cut_off", at_loop, stage=cut.stage, max_gen_len=cut.max_gen_len, **cut.result)
        q.put({"type": "error", "message": f"Loop {at_loop} {cut}",
               "cut_off": {"stage": cut.stage, "loop": at_loop, "max_gen_len": cut.max_gen_len,
                           "prompt_tokens": cut.result["prompt_tokens"]}})
    except RunStopped:
        telemetry.record(run_id, "stopped", at_loop)
        q.put({"type": "stopped", "message": "Stopped by the analyst"})
    except Exception as exc:
        q.put({"type": "error", "message": str(exc)})


BROKER_TIMEOUT_S = 1800


def _broker_round(tasks: list, run_id: str, loop_num: int, q, ctrl: dict,
                  alert_scope: list | None = None, event_time: str | None = None) -> tuple[dict, dict]:
    """Send the Analyst's tasks to the Tool Broker; return (payload, trace link).

    In process: `run_round` on this run's thread, on a loop of its own so Stop
    can cancel it. The Broker's progress lines go to the round's `broker.log` and
    the UI's log panel. The link says where everything for this round lives; it
    has an `error` key when there is nothing to judge.
    """
    # One folder per investigation (O5): runs/<run_id>/L<n>/ holds the round's task
    # file, Broker log, payload and one folder per task.
    round_dir = runs_root().resolve() / run_id / f"L{loop_num}"
    round_dir.mkdir(parents=True, exist_ok=True)
    task_file, dropped = to_task_file(tasks, run_id, loop_num, alert_scope, event_time)
    task_path = round_dir / "tasks.json"
    task_path.write_text(json.dumps(task_file, indent=2), encoding="utf-8")  # the record, not the handoff
    task_ids = [t["task_id"] for t in task_file["tasks"]]
    link = {"task_file": str(task_path), "task_ids": task_ids, "tasks": task_file["tasks"], "dropped": dropped}
    # The Analyst -> Broker half of the handshake: exactly what was sent, and what was not.
    emit(q, "handoff", {"tasks": task_file["tasks"], "dropped": dropped, "task_file": str(task_path)},
         loop=loop_num, message=f"Loop {loop_num}: {len(task_ids)} task(s) handed to the Broker")
    if not task_ids:
        return {}, {**link, "error": "no task could be converted for the broker"}

    batch_id = f"{run_id}-L{loop_num}"
    log_path = round_dir / "broker.log"
    tasks_in = [(t.to_analyst_task(), t.question) for t in TaskInputFile.model_validate(task_file).tasks]

    async def one_round():
        round_dir_token = broker_round_dir.set(round_dir)
        try:
            with telemetry.round_span(batch_id, telemetry.traceparent(run_id, loop_num)):
                return await asyncio.wait_for(run_round(tasks_in, round_args(batch_id=batch_id)), BROKER_TIMEOUT_S)
        finally:
            broker_round_dir.reset(round_dir_token)

    loop = asyncio.new_event_loop()
    with log_path.open("w", encoding="utf-8", buffering=1) as log:  # line-buffered: live on disk (O3)
        def line(text: str) -> None:
            log.write(text + "\n")
            emit(q, "broker_log", {"line": text}, loop=loop_num)

        with telemetry.print_to(line):
            round_task = loop.create_task(one_round())
            ctrl["cancel"] = lambda: loop.call_soon_threadsafe(round_task.cancel)  # the stop endpoint
            try:
                result = loop.run_until_complete(round_task)
            except asyncio.CancelledError:
                raise RunStopped()  # cancelled on purpose: not a broker failure
            except TimeoutError:
                return {}, {**link, "log": str(log_path),
                            "error": f"broker timed out after {BROKER_TIMEOUT_S // 60} minutes, see {log_path}"}
            except Exception as exc:
                return {}, {**link, "log": str(log_path), "error": f"broker failed: {exc} (log: {log_path})"}
            finally:
                ctrl["cancel"] = None
                loop.close()
    link["log"] = str(log_path)

    link["broker_runs"] = broker_runs(task_ids, result.fetched)
    payload = result.payload.model_dump(mode="json") if result.payload else None
    link["payload"] = str(round_dir / "analyst-payload.json")
    link["handshake"] = handshake(task_ids, link["broker_runs"], payload)
    if result.failures:
        return {}, {**link, "error": f"broker: {result.failures} task(s) failed (log: {log_path})"}
    if payload is None:
        return {}, {**link, "error": f"broker wrote no analyst payload (analyst model configured?), see {log_path}"}
    return payload, link
