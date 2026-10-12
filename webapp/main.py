"""
main.py - SmartOps SOC Unified Web Application
FastAPI server wiring the Web UI to the SmartOps Engine (Broker + Subagents)
using Foundation-Sec-8B-Reasoning on AWS Bedrock (invoke_model, NOT Converse).
"""
import copy
import json
import os
import re
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty, Queue

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add engine to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine", "src"))

# Before the service imports: llm_service reads its model settings at import time.
# override=False, so a variable already set by the shell or container wins.
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env", override=False)

from webapp.services.llm_service import call_llm
from smartops import analyst, context, telemetry
from smartops.broker import runs_root
from smartops.analyst import FULL_ROUNDS, extract_json


app = FastAPI(title="SmartOps SOC")

# â”€â”€ Static files & index route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# The React frontend (frontend/, `npm run build`) when built; the old static page otherwise.
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
HAS_FRONTEND = os.path.isfile(os.path.join(FRONTEND_DIST, "index.html"))
if HAS_FRONTEND:
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/favicon.svg")
    def favicon():
        return FileResponse(os.path.join(FRONTEND_DIST, "favicon.svg"))

# Index route MUST be declared before the static mount so it wins on "/"
@app.get("/")
def index():
    resp = FileResponse(os.path.join(FRONTEND_DIST if HAS_FRONTEND else STATIC_DIR, "index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# Mount static files AFTER the route (html=False so StaticFiles never auto-serves / # )
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=False), name="static")

# ── Alert context (smartops.context) ─────────────────────────────────────────
class ESCURequest(BaseModel):
    rule_name: str

class OpenCTIRequest(BaseModel):
    observables: list[str]


@app.get("/api/import-from-splunk")
def import_from_splunk(index: int = 0, rule_name: str = None):
    return context.import_notable(index, rule_name)


@app.get("/api/incident-queue")
def get_incident_queue():
    return context.incident_queue()


@app.post("/api/opencti")
def opencti_endpoint(req: OpenCTIRequest):
    return context.opencti(req.observables)


@app.post("/api/escu")
def escu_endpoint(req: ESCURequest):
    return context.escu(req.rule_name)



# â”€â”€ Run queue for SSE debug streaming â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_run_queues: dict[str, Queue] = {}

class RunRequest(BaseModel):
    alert_name: str = "Potential Cryptomining Activity Detected"
    host: str = "BSTOLL-L"
    domain: str = "coinhive.com"
    event_time: str = "2018-08-20T12:00:00Z"
    max_loops: int = 15  # headroom to finish; older rounds are compacted (FULL_ROUNDS)
    context_contract: dict = None

@app.get("/debug")
def debug_page():
    return FileResponse(os.path.join(STATIC_DIR, "debug.html"))

@app.post("/api/run")
def start_run(req: RunRequest):
    run_id = str(uuid.uuid4())[:8]
    q: Queue = Queue()
    _run_queues[run_id] = q
    go = threading.Event()
    go.set()
    _run_ctrl[run_id] = {"stop": threading.Event(), "go": go, "proc": None}
    threading.Thread(target=_run_investigation, args=(run_id, req, q), daemon=True).start()
    return {"run_id": run_id}

# ── Run control: stop, pause, resume ─────────────────────────────────────────
# Pause and stop land at the next stage boundary (_checkpoint): a model call in
# flight cannot be interrupted. Stop also kills a running broker at once.
_run_ctrl: dict[str, dict] = {}

class RunStopped(Exception):
    pass

def _checkpoint(run_id: str, q: Queue) -> None:
    c = _run_ctrl.get(run_id)
    if not c:
        return
    if not c["go"].is_set():
        _emit(q, "paused", {}, message="Paused at a stage boundary")
        while not c["go"].wait(0.5):
            if c["stop"].is_set():
                break
        if not c["stop"].is_set():
            _emit(q, "resumed", {}, message="Resumed")
    if c["stop"].is_set():
        raise RunStopped()

def _ctrl_or_404(run_id: str):
    c = _run_ctrl.get(run_id)
    if not c:
        return None, Response(status_code=404, content='{"status":"error","message":"run not found or finished"}',
                              media_type="application/json")
    return c, None

@app.post("/api/run/{run_id}/stop")
def stop_run(run_id: str):
    c, err = _ctrl_or_404(run_id)
    if err:
        return err
    c["stop"].set()
    c["go"].set()  # a paused run wakes up only to stop
    if c["proc"] is not None and c["proc"].poll() is None:
        c["proc"].kill()
    return {"status": "ok"}

@app.post("/api/run/{run_id}/pause")
def pause_run(run_id: str):
    c, err = _ctrl_or_404(run_id)
    if err:
        return err
    c["go"].clear()
    return {"status": "ok"}

@app.post("/api/run/{run_id}/resume")
def resume_run(run_id: str):
    c, err = _ctrl_or_404(run_id)
    if err:
        return err
    c["go"].set()
    return {"status": "ok"}

@app.get("/api/run/stream/{run_id}")
def stream_run(run_id: str):
    q = _run_queues.get(run_id)
    if not q:
        return {"error": "run not found"}
    def event_gen():
        while True:
            try:
                item = q.get(timeout=300)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") in ("done", "error", "stopped"):
                    break
            except Empty:
                # Silence is not failure: a cold model or a long broker round can go
                # minutes without an event. The worker always ends with done/error.
                yield ": keepalive\n\n"
    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

def _emit(q: Queue, event_type: str, data: dict, **extra):
    q.put({"type": event_type, "data": data, "message": extra.get("message",""), **{k:v for k,v in extra.items() if k != "message"}})

def _run_investigation(run_id: str, req: RunRequest, q: Queue):
    system_prompt = analyst.load_system_prompt()
    at_loop = 1  # where a stop landed, for the run record
    try:
        # â”€â”€ Build alert context â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if req.context_contract:
            alert_context = req.context_contract
        else:
            alert_context = {
                "normalized_seed": {
                    "alert_name": req.alert_name,
                    "event_time": req.event_time,
                    "severity": "high",
                    "entities": {"host": req.host, "domain": req.domain}
                },
                "escu_context": {
                    "rule_name": req.alert_name,
                    "deployed_spl": f"index=network sourcetype=stream:dns query={req.domain}",
                    "reference_spl": f"index=network sourcetype=stream:dns (query={req.domain} OR query=*mining*)",
                    "mitre": "T1496"
                },
                "goal": f"Investigate {req.domain} activity on host {req.host}"
            }

        # â”€â”€ LOOP 1: Analyst â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        _emit(q, "analyst", {}, message="Loop 1 â€” Analyst planning...")
        # Strip prior analyst/synthesis keys so the model starts in planning mode.
        _STRIP_KEYS = {"planning_template", "analyst_plan", "synthesis",
                       "verdict", "status", "hypothesis_scores",
                       "verdict_confidence", "verdict_reasoning", "evidence_gaps"}
        clean_context = {k: v for k, v in alert_context.items() if k not in _STRIP_KEYS}
        user_msg = "[ALERT CONTEXT]\n" + json.dumps(clean_context, indent=2)
        _checkpoint(run_id, q)
        r1 = call_llm(system_prompt, user_msg)
        plan = extract_json(r1["answer"]) or {}
        plan["reasoning"] = r1["reasoning"]
        tokens1 = {"prompt_tokens": r1["prompt_tokens"], "generation_tokens": r1["generation_tokens"], "stop_reason": r1["stop_reason"]}
        _emit(q, "analyst", plan, message="Loop 1 complete", tokens=tokens1)
        telemetry.record(run_id, "analyst_plan", 1, plan=plan, tokens=tokens1, context=clean_context)

        # â”€â”€ LOOPS 2..N: Broker + Synthesis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        tasks = plan.get("tasks", [])
        # A verdict already in Loop 1 (the context was unambiguous) skips the broker.
        if not tasks and plan.get("status") == "VERDICT_REACHED":
            _emit(q, "verdict", plan, message="VERDICT (direct): " + str(plan.get("verdict", "?")))
            q.put({"type": "done", "message": "Investigation complete"})
            return
        all_findings = {}
        all_runs = []  # every round's broker runs, for the verdict gate's step check
        evaluations = {}  # round label -> the gated synthesis that read it
        asked = []  # every task sent so far, so a repeat round is not sent (W10)
        for loop_num in range(2, req.max_loops + 2):
            at_loop = loop_num
            _checkpoint(run_id, q)
            # Handoff -> broker log -> broker steps -> sub-analyst payload: each stage is
            # its own event, so the UI shows the handshake rather than a JSON dump.
            findings, link = _run_broker_proc_streaming(
                tasks, run_id, loop_num, q, context.alert_entities(alert_context),
                (alert_context.get("normalized_seed") or {}).get("event_time"))
            telemetry.record(run_id, "broker", loop_num, **link)
            if "broker_runs" in link:
                _emit(q, "broker", {"runs": link["broker_runs"], "handshake": link["handshake"]},
                      loop=loop_num, message=f"Loop {loop_num}: Broker complete")
            if link.get("error"):
                # Never fall back to another run's artifacts: that is how eleven
                # loops were once judged on an unrelated alert's evidence.
                q.put({"type": "error", "message": f"Loop {loop_num} broker failed: {link['error']}", "trace": link})
                return
            all_findings[f"Round {loop_num}"] = findings
            all_runs += link.get("broker_runs", [])
            _emit(q, "payload", findings, loop=loop_num, message=f"Loop {loop_num}: sub-analyst findings returned to the Analyst")

            # Synthesis â€” build accumulated findings sections
            _emit(q, "synthesis", {}, loop=loop_num, message=f"Loop {loop_num} â€” Synthesis evaluating...")
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
                record = analyst.compact_round(all_findings[round_label], evaluations.get(round_label, {}))
                sections.append(f"[EARLIER ROUND - {round_label}, summarised]\n{json.dumps(record, indent=2)}")
            for round_label in labels[-FULL_ROUNDS:]:
                slim = {k:v for k,v in all_findings[round_label].items() if k != "_raw_intel_dump"}
                sections.append(f"[BROKER FINDINGS - {round_label}]\n{json.dumps(slim, indent=2)}")
            _checkpoint(run_id, q)
            rN = call_llm(system_prompt,"\n\n".join(sections))
            raw_synth = extract_json(rN["answer"]) or {}
            synth = evaluations[f"Round {loop_num}"] = analyst.verdict_gate(raw_synth, plan, [p for r in all_findings.values() for p in r.get("payloads", [])], all_runs)
            _emit(q, "synthesis", synth, loop=loop_num, reasoning=rN["reasoning"],
                  tokens={"prompt_tokens": rN["prompt_tokens"], "generation_tokens": rN["generation_tokens"]},
                  message=f"Loop {loop_num} â€” Synthesis complete: {synth.get('status','?')}")
            telemetry.record(run_id, "synthesis", loop_num, output=synth, model_status=raw_synth.get("status"),
                             reasoning=rN["reasoning"],
                             tokens={"prompt_tokens": rN["prompt_tokens"], "generation_tokens": rN["generation_tokens"]})

            status  = synth.get("status", "")
            verdict = synth.get("verdict", "")

            if status == "VERDICT_REACHED":
                _emit(q, "verdict", synth, message=f"VERDICT: {verdict}")
                break
            if loop_num == req.max_loops + 1:
                _emit(q, "verdict", {**synth, "verdict": verdict or "REQUIRES_INVESTIGATION"}, message="Max loops reached")
                break
            asked += link["tasks"]
            tasks = analyst.follow_up_tasks(synth.get("follow_up_tasks", []), link["tasks"],
                                              synth.get("evidence_gaps"), asked)
            if not tasks:
                _emit(q, "verdict", {**synth, "verdict": verdict or "REQUIRES_INVESTIGATION"},
                      message="No new follow-up tasks (none given, or all already asked)")
                break

        q.put({"type": "done", "message": "Investigation complete"})

    except RunStopped:
        telemetry.record(run_id, "stopped", at_loop)
        q.put({"type": "stopped", "message": "Stopped by the analyst"})
    except Exception as exc:
        q.put({"type": "error", "message": str(exc)})
    finally:
        _run_queues.pop(run_id, None)
        _run_ctrl.pop(run_id, None)


def _run_broker_proc_streaming(tasks: list, run_id: str, loop_num: int, q: Queue,
                               alert_scope: list | None = None, event_time: str | None = None) -> tuple[dict, dict]:
    """Send the Analyst's tasks to the Tool Broker; return (payload, trace link).

    The tasks go as a `task-input.v1` file (`--task-file`), and what comes back is
    the batch `analyst-payload.json` the sub-analysts wrote -- read from the batch
    id this call named, never from "the newest run on disk". The link says where
    everything for this round lives; it has an `error` key when there is nothing
    to judge.
    """
    # One folder per investigation (O5): runs/<run_id>/L<n>/ holds the round's task
    # file, Broker log, payload and one folder per task.
    round_dir = runs_root().resolve() / run_id / f"L{loop_num}"
    round_dir.mkdir(parents=True, exist_ok=True)
    task_file, dropped = analyst.to_task_file(tasks, run_id, loop_num, alert_scope, event_time)
    task_path = round_dir / "tasks.json"
    task_path.write_text(json.dumps(task_file, indent=2), encoding="utf-8")
    task_ids = [t["task_id"] for t in task_file["tasks"]]
    link = {"task_file": str(task_path), "task_ids": task_ids, "tasks": task_file["tasks"], "dropped": dropped}
    # The Analyst -> Broker half of the handshake: exactly what was sent, and what was not.
    _emit(q, "handoff", {"tasks": task_file["tasks"], "dropped": dropped, "task_file": str(task_path)},
          loop=loop_num, message=f"Loop {loop_num}: {len(task_ids)} task(s) handed to the Broker")
    if not task_ids:
        return {}, {**link, "error": "no task could be converted for the broker"}

    repo = Path(__file__).parent.parent
    batch_id = f"{run_id}-L{loop_num}"
    log_path = round_dir / "broker.log"
    env = {
        **os.environ,
        # contracts lives beside the engine, not inside engine/src.
        "PYTHONPATH": os.pathsep.join([str(repo / "engine" / "src"), str(repo / "engine" / "contracts" / "src")]),
        "PYTHONIOENCODING": "utf-8",
        # Piped stdout is block-buffered; without this the "live" log arrives at exit.
        "PYTHONUNBUFFERED": "1",
        "SMARTOPS_OUT_DIR": str(round_dir),
        # Every span of this round joins the run's one trace (O5).
        "TRACEPARENT": telemetry.traceparent(run_id, loop_num),
    }
    cmd = [sys.executable, "-m", "smartops.main",
           "--task-file", str(task_path),
           "--batch-id", batch_id,
           "--mcp-config", str(repo / "mcp_servers.json")]
    # Streamed line by line: it fills the UI's log panel, and it keeps the SSE
    # queue alive -- a silent 30-minute subprocess tripped the stream's 300 s
    # timeout and the UI reported a failure while the broker was still working.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", env=env, cwd=str(repo))
    ctrl = _run_ctrl.get(run_id) or {}
    ctrl["proc"] = proc  # the stop endpoint kills it
    timed_out = threading.Event()
    cli_errors: list[str] = []
    prev_was_error = False

    def _kill():
        timed_out.set()
        proc.kill()

    killer = threading.Timer(1800, _kill)
    killer.start()
    try:
        with log_path.open("w", encoding="utf-8", buffering=1) as log:  # line-buffered: live on disk (O3)
            log.write(f"$ {' '.join(cmd)}\n\n")
            for line in proc.stdout:
                log.write(line)
                # The CLI's own `error:` lines and their 7-space continuations (main.py return-2 paths).
                if line.startswith("error:") or (cli_errors and re.match(r" {7}\S", line) and prev_was_error):
                    cli_errors.append(line.strip())
                prev_was_error = bool(cli_errors) and cli_errors[-1] == line.strip()
                _emit(q, "broker_log", {"line": line.rstrip()}, loop=loop_num)
        returncode = proc.wait()
    finally:
        killer.cancel()
        ctrl["proc"] = None
    if ctrl.get("stop") and ctrl["stop"].is_set():
        raise RunStopped()  # killed on purpose: not a broker failure
    link.update(exit_code=returncode, log=str(log_path))

    link["broker_runs"] = analyst.broker_runs(task_ids, round_dir)
    payload_path = round_dir / "analyst-payload.json"
    link["payload"] = str(payload_path)
    payload = json.loads(payload_path.read_text(encoding="utf-8")) if payload_path.is_file() else None
    link["handshake"] = analyst.handshake(task_ids, link["broker_runs"], payload)
    if timed_out.is_set():
        return {}, {**link, "error": f"broker timed out after 30 minutes, see {log_path}"}
    if returncode != 0:
        said = " ".join(cli_errors[-4:]) or "no error line printed"
        return {}, {**link, "error": f"broker exited {returncode}: {said} (log: {log_path})"}
    if payload is None:
        return {}, {**link, "error": f"broker wrote no analyst payload (analyst model configured?), see {log_path}"}
    return payload, link

