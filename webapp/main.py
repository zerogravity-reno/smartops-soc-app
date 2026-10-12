"""
main.py - SmartOps SOC Unified Web Application
FastAPI server wiring the Web UI to the SmartOps Engine (Broker + Subagents)
using Foundation-Sec-8B-Reasoning on AWS Bedrock (invoke_model, NOT Converse).
"""
import json
import os
import sys
import threading
import uuid
from contextlib import asynccontextmanager
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

from smartops import analyst, context, telemetry
from smartops.main import _neutralise_aws_profile, configure_logging, start
from smartops.telemetry import configure_telemetry


REPO = Path(__file__).parent.parent


@asynccontextmanager
async def lifespan(app):
    # Once per server, not per round: the Broker's MCP clients are built and warmed here.
    telemetry.route_output()
    configure_logging()
    _neutralise_aws_profile()
    configure_telemetry()
    await start(str(REPO / "mcp_servers.json"))
    yield


app = FastAPI(title="SmartOps SOC", lifespan=lifespan)

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
    max_loops: int = 15  # headroom to finish; older rounds are compacted (analyst.FULL_ROUNDS)
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
    _run_ctrl[run_id] = {"stop": threading.Event(), "go": go, "cancel": None}
    threading.Thread(target=_run_investigation, args=(run_id, req, q), daemon=True).start()
    return {"run_id": run_id}

# ── Run control: stop, pause, resume ─────────────────────────────────────────
# Pause and stop land at the next stage boundary (_checkpoint): a model call in
# flight cannot be interrupted. Stop also cancels a running broker round at once.
_run_ctrl: dict[str, dict] = {}

def _checkpoint(run_id: str, q: Queue) -> None:
    c = _run_ctrl.get(run_id)
    if not c:
        return
    if not c["go"].is_set():
        analyst.emit(q, "paused", {}, message="Paused at a stage boundary")
        while not c["go"].wait(0.5):
            if c["stop"].is_set():
                break
        if not c["stop"].is_set():
            analyst.emit(q, "resumed", {}, message="Resumed")
    if c["stop"].is_set():
        raise analyst.RunStopped()

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
    if c.get("cancel"):
        c["cancel"]()
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

def _run_investigation(run_id: str, req: RunRequest, q: Queue):
    try:
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

        analyst.investigate(run_id, alert_context, req.max_loops, q,
                            lambda: _checkpoint(run_id, q), _run_ctrl.get(run_id) or {})
    finally:
        _run_queues.pop(run_id, None)
        _run_ctrl.pop(run_id, None)
