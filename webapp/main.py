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

from webapp.services.llm_service import call_llm, extract_json


app = FastAPI(title="SmartOps SOC")

# â”€â”€ Static files & index route â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Index route MUST be declared before the static mount so it wins on "/"
@app.get("/")
def index():
    resp = FileResponse(os.path.join(STATIC_DIR, "index.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# Mount static files AFTER the route (html=False so StaticFiles never auto-serves / # )
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=False), name="static")

# â”€â”€ Load ESCU corpus â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CORPUS_PATH = os.path.join(os.path.dirname(__file__), "..", "bm25_corpus.json")
try:
    with open(CORPUS_PATH, "r", encoding="utf-8") as f:
        bm25_corpus = json.load(f)
except Exception as e:
    bm25_corpus = {}
    print(f"Warning: Could not load bm25_corpus.json: {e}")

# â”€â”€ Load unified system prompt â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "system_prompt.txt")

def _load_system_prompt():
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        return f.read()

# â”€â”€ Pydantic models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class AnalystRequest(BaseModel):
    context_contract: dict
    hypotheses: list[str] = []

class SynthesisRequest(BaseModel):
    hypothesis: str = ""
    findings: dict
    planning_template: dict | None = None

class ESCURequest(BaseModel):
    rule_name: str

class OpenCTIRequest(BaseModel):
    observables: list[str]

# â”€â”€ OpenCTI config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
import requests as _http_requests
OPENCTI_URL   = os.environ.get("OPENCTI_URL",   "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN",  "607c0c8e-ba29-4e00-9d6b-8e33e33d0f92")
OPENCTI_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type":  "application/json",
}

def _gql(query: str, variables: dict = {}):
    """Execute a GraphQL query against OpenCTI."""
    try:
        resp = _http_requests.post(
            OPENCTI_URL, headers=OPENCTI_HEADERS,
            json={"query": query, "variables": variables}, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"error": str(exc)}

def _search_stix_observable(value: str):
    return _gql("""
    query SearchObservable($search: String) {
      stixCyberObservables(search: $search, first: 5) {
        edges { node {
            id entity_type observable_value
            ... on IPv4Addr { value }
            ... on DomainName { value }
            ... on StixFile { name hashes { algorithm hash } }
            objectLabel { value color }
            indicators { edges { node { name description } } }
        }}
      }
    }""", {"search": value})

def _search_attack_pattern(value: str):
    return _gql("""
    query SearchAttackPattern($search: String) {
      attackPatterns(search: $search, first: 5) {
        edges { node {
            id name x_mitre_id description
            killChainPhases { kill_chain_name phase_name }
            objectLabel { value color }
        }}
      }
    }""", {"search": value})

def _search_malware(value: str):
    return _gql("""
    query SearchMalware($search: String) {
      malwares(search: $search, first: 5) {
        edges { node { id name description malware_types objectLabel { value color } } }
      }
    }""", {"search": value})

def _classify_observable(value: str) -> str:
    import re as _re
    v = value.strip()
    if _re.match(r'^T\d{4}(\.\d{3})?$', v, _re.IGNORECASE): return "technique"
    if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):            return "ip"
    if _re.match(r'^[a-fA-F0-9]{32,64}$', v):               return "hash"
    if "." in v and not v[0].isdigit():                      return "domain"
    return "general"

# â”€â”€ Import from Splunk ES Mission Control â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/api/import-from-splunk")
def import_from_splunk():
    """Pull the latest notable event from Splunk ES Mission Control and
    enrich it with the matching detection rule SPL from Content Management."""
    import httpx, time as _time

    base_url = os.environ.get("SPLUNK_WEB_URL", "https://wobbly-erased-starter.ngrok-free.dev")
    user = os.environ.get("SPLUNK_USER", "ysalah")
    pwd  = os.environ.get("SPLUNK_PASS", "12345679")
    skip = {"ngrok-skip-browser-warning": "true"}

    try:
        # --- Auth ---
        client = httpx.Client(verify=False, follow_redirects=True)
        client.get(f"{base_url}/en-US/account/login", headers=skip, timeout=60)
        cval = client.cookies.get("cval", "")
        client.post(f"{base_url}/en-US/account/login", headers=skip,
                    data={"username": user, "password": pwd, "cval": cval, "return_to": "/en-US/"}, timeout=60)
        csrf = client.cookies.get("splunkweb_csrf_token_8000", "")
        client.headers.update({**skip, "X-Splunk-Form-Key": csrf, "X-Requested-With": "XMLHttpRequest"})

        # --- Step 1: Get latest notable event ---
        spl_notable = (
            "search index=notable earliest=-30d"
            " | sort -_time"
            " | head 1"
            " | table _time rule_name urgency status src dest user src_ip rule_id search_name *")
        r = client.post(f"{base_url}/en-US/splunkd/__raw/services/search/jobs?output_mode=json",
                        data={"search": spl_notable, "exec_mode": "normal", "splunk_form_key": csrf}, timeout=60)
        r.raise_for_status()
        sid = r.json()["sid"]
        for _ in range(60):
            sr = client.get(f"{base_url}/en-US/splunkd/__raw/services/search/jobs/{sid}?output_mode=json", timeout=60)
            if sr.status_code != 200: break
            if sr.json()["entry"][0]["content"]["dispatchState"] in ("DONE", "FAILED"): break
            _time.sleep(1)
        rr = client.get(f"{base_url}/en-US/splunkd/__raw/services/search/jobs/{sid}/results?output_mode=json&count=1", timeout=60)
        events = rr.json().get("results", [])
        if not events:
            return {"status": "empty", "message": "No notable events found in the last 72 hours."}

        ev = events[0]
        
        def _get_val(keys):
            for k in keys:
                if k in ev:
                    v = ev[k]
                    if isinstance(v, list) and len(v) > 0 and v[0]:
                        return v[0]
                    elif isinstance(v, str) and v.strip():
                        return v.strip()
            return ""

        rule_name = _get_val(["rule_name", "search_name"])
        src        = _get_val(["src", "src_ip"])
        dest       = _get_val(["dest", "Registry.dest"])
        user_field = _get_val(["user", "Registry.user"])
        urgency    = _get_val(["urgency"])
        event_time = _get_val(["_time", "time"])
        
        # Try to extract additional context if present in the raw event
        file_hash = _get_val(["file_hash", "hash", "md5", "sha256"])
        domain    = _get_val(["domain", "url"])
        mitre     = _get_val(["mitre_attack_id", "mitre_technique_id", "annotations.mitre_attack"])
        sig       = _get_val(["signature", "action", "category", "registry_path"])
        
        # Capture the entire raw dictionary to send as context
        raw_full = {k: v for k, v in ev.items() if k not in ["_bkt", "_cd", "_si", "_indextime", "_kv"]}


        # --- Step 2: Find matching detection rule SPL ---
        deployed_spl = ""
        if rule_name:
            import urllib.parse
            encoded = urllib.parse.quote(rule_name)
            ru = client.get(
                f"{base_url}/en-US/splunkd/__raw/servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches"
                f"?output_mode=json&count=1&f=name&f=search"
                f"&search=name%3D%22{encoded}%22",
                timeout=60,)
            if ru.status_code == 200:
                entries = ru.json().get("entry", [])
                if entries:
                    deployed_spl = entries[0].get("content", {}).get("search", "")

        client.close()
        return {
            "status": "ok",
            "event_time": event_time,
            "rule_name": rule_name,
            "urgency": urgency,
            "src": src,
            "dest": dest,
            "user": user_field,
            "file_hash": file_hash,
            "domain": domain,
            "mitre": mitre,
            "sig": sig,
            "deployed_spl": deployed_spl,
            "raw_event_data": raw_full
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


@app.post("/api/opencti")

def opencti_endpoint(req: OpenCTIRequest):
    results = {}
    for obs in req.observables:
        t = _classify_observable(obs)
        if t == "technique":
            r = _search_attack_pattern(obs); r["_queried_as"] = "AttackPattern (MITRE)"
        elif t in ("ip", "hash", "domain"):
            r = _search_stix_observable(obs); r["_queried_as"] = f"StixCyberObservable ({t})"
        else:
            r = {"_queried_as": "Observable + Malware search",
                 "observable_result": _search_stix_observable(obs),
                 "malware_result":    _search_malware(obs)}
        results[obs] = r
    return {"status": "success", "source": f"OpenCTI Live API ({OPENCTI_URL})",
            "total_observables": len(req.observables), "results": results}


# â”€â”€ ESCU endpoint (local BM25) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/escu")
def escu_endpoint(req: ESCURequest):
    from rank_bm25 import BM25Okapi
    import re
    
    if not bm25_corpus:
        return {"status": "error", "message": "ESCU corpus not loaded"}
        
    corpus_dict = bm25_corpus.get("doc_meta", bm25_corpus)
    rules_data = list(corpus_dict.values())
    names = [r.get("name", "") for r in rules_data]
    
    tokenized = [n.lower().split() for n in names]
    bm25 = BM25Okapi(tokenized)
    
    # Clean the incoming rule name from common ES prefixes/suffixes to improve BM25 score
    clean_name = req.rule_name.lower()
    clean_name = re.sub(r'^(endpoint|network|cloud|web)\s*-\s*', '', clean_name)
    clean_name = re.sub(r'sama\s*-\s*', '', clean_name)
    clean_name = re.sub(r'escu\s*-\s*', '', clean_name)
    clean_name = re.sub(r'\s*-\s*rule(\s*-\s*rule)?$', '', clean_name)
    
    query_tokens = clean_name.split()
    scores = bm25.get_scores(query_tokens)
    top_idx = scores.argsort()[::-1][:3]
    
    results = [{"rule": names[i], "score": float(scores[i]), "data": rules_data[i]} for i in top_idx if scores[i] > 0]
    return {"status": "success", "matches": results}

# â”€â”€ Analyst job store (non-blocking pattern) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_analyst_jobs: dict = {}   # job_id â†’ {"status": "pending"|"done", "result": ...}

@app.post("/api/analyst/start")
def analyst_start(req: AnalystRequest):
    """Start analyst in background, return job_id immediately â€” no timeout."""
    job_id = str(uuid.uuid4())[:8]
    _analyst_jobs[job_id] = {"status": "pending", "result": None}
    threading.Thread(target=_run_analyst_job, args=(job_id, req), daemon=True).start()
    return {"job_id": job_id}

@app.get("/api/analyst/result/{job_id}")
def analyst_result(job_id: str):
    """Poll for analyst result â€” returns {status:'pending'} until ready."""
    job = _analyst_jobs.get(job_id)
    if not job:
        return {"status": "error", "message": "Job not found"}
    if job["status"] == "pending":
        return {"status": "pending"}
    _analyst_jobs.pop(job_id, None)
    return job["result"]

def _run_analyst_job(job_id: str, req: AnalystRequest):
    try:
        result = _do_analyst(req)
        _analyst_jobs[job_id] = {"status": "done", "result": result}
    except Exception as exc:
        _analyst_jobs[job_id] = {"status": "done", "result": {
            "status": "error", "message": str(exc), "planning_template": None}}

# â”€â”€ Analyst endpoint (Loop 1) â€” backward compat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/analyst")
def analyst_endpoint(req: AnalystRequest):
    return _do_analyst(req)

def _do_analyst(req: AnalystRequest):
    contract  = req.context_contract
    slim      = copy.deepcopy(contract)

    if "escu_context" in slim:
        slim["escu_context"].pop("full_metadata", None)
        slim["escu_context"].pop("reference_spl", None)
    if "opencti_threat_intelligence" in slim:
        slim["opencti_threat_intelligence"].pop("_raw_intel_dump", None)

    seed           = slim.get("normalized_seed", {})
    event_time     = seed.get("event_time", "unknown")
    entities       = seed.get("entities", {})
    host           = entities.get("hostname", entities.get("host", "unknown"))
    user           = entities.get("user", "unknown")
    src_ip         = entities.get("src_ip", "unknown")

    system_prompt  = _load_system_prompt()
    user_message   = f"""[ALERT CONTEXT]
{json.dumps(slim, indent=2)}

OUTPUT exactly this JSON structure:
{{
  "model_reasoning": "What are the possible explanations for this alert?",
  "semantic_alignment": "ALIGNED or NOT_ALIGNED",
  "alignment_reasoning": "Why the deployed SPL matches or deviates from the reference SPL intent",
  "hypotheses": [
    {{"id": "H1", "verdict": "TRUE_POSITIVE",  "description": "Specific description for this alert"}},
    {{"id": "H2", "verdict": "FALSE_POSITIVE", "description": "Specific description for this alert"}},
    {{"id": "H3", "verdict": "BENIGN",         "description": "Specific description for this alert"}}
  ],
  "tasks": [
    {{"task_id": "T1", "question": "<atomic investigation question>", "entity": {{"type": "host|ip|user", "value": "<value>"}}, "time_window": {{"start": "REPLACE_START", "end": "REPLACE_END"}}}},
    "... add as many tasks as the investigation requires ..."
  ]
}}

RULES:
- Decide how many tasks the investigation needs.
- TASK RULE 1: Each question must be atomic (one idea, no and/or).
- TASK RULE 2: Tasks must collectively differentiate between TRUE_POSITIVE, FALSE_POSITIVE, and BENIGN.
- TASK RULE 3: The 'question' field is a PURE INVESTIGATION QUESTION -- what the analyst wants to know, not HOW to find it.
  Never mention tools, data sources, or search methods inside the question.
  GOOD: "Was the encoded command executed under a legitimate administrative context?"
  BAD:  "Search Splunk for encoded PowerShell under Administrator."
- Replace REPLACE_START / REPLACE_END with one hour before/after {event_time} in ISO8601."""

    try:
        result = call_llm(system_prompt, user_message)
        raw_output = result["answer"]  # answer is after </think>
        reasoning  = result["reasoning"]

        # â”€â”€ Robust JSON extraction (same logic as before) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        def _extract_all_objects(text):
            objects, i = [], 0
            while i < len(text):
                if text[i] == "{":
                    depth, start = 0, i
                    for j in range(i, len(text)):
                        if text[j] == "{": depth += 1
                        elif text[j] == "}":
                            depth -= 1
                            if depth == 0:
                                try:
                                    objects.append(json.loads(text[start:j+1]))
                                except json.JSONDecodeError:
                                    pass
                                i = j
                                break
                i += 1
            return objects

        all_objects    = _extract_all_objects(raw_output)
        main_plan      = None
        task_items     = []

        for obj in all_objects:
            if isinstance(obj, dict):
                if "task_id" in obj:
                    task_items.append(obj)
                elif any(k in obj for k in ("model_reasoning", "hypotheses", "semantic_alignment")):
                    if main_plan is None:
                        main_plan = obj

        if main_plan is None and task_items:
            main_plan = {}

        if main_plan is not None:
            existing = main_plan.get("tasks", [])
            seen_ids = {t.get("task_id") for t in existing}
            for t in task_items:
                if t.get("task_id") not in seen_ids:
                    existing.append(t)
                    seen_ids.add(t.get("task_id"))
            main_plan["tasks"] = existing

        planning_template = main_plan or {"parse_error": "Model did not return valid JSON", "_raw": raw_output[:500]}

        return {
            "status": "success",
            "source": "Analyst Agent (Foundation-Sec-8B-Reasoning on Bedrock)",
            "planning_template": planning_template,
            "reasoning": reasoning or "(No reasoning provided)",
            "tokens": {
                "prompt": result["prompt_tokens"],
                "generation": result["generation_tokens"],
                "stop_reason": result["stop_reason"],
            }
        }

    except Exception as e:
        return {"status": "error", "message": f"LLM call failed: {str(e)}", "planning_template": None}


# â”€â”€ Synthesis endpoint (Loop 2+ â€” Evaluation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/synthesis")
def synthesis_endpoint(req: SynthesisRequest):
    system_prompt = _load_system_prompt()

    # Strip heavy fields
    slim_findings = {k: v for k, v in req.findings.items() if k != "_raw_intel_dump"} \
        if isinstance(req.findings, dict) else req.findings

    # Build User Message â€” sections appear only when data is available
    sections = []
    if req.planning_template:
        sections.append(f"[INVESTIGATION PLAN]\n{json.dumps(req.planning_template, indent=2)}")
    sections.append(f"[BROKER FINDINGS - Round 2]\n{json.dumps(slim_findings, indent=2)}")

    user_message = "\n\n".join(sections)

    try:
        result     = call_llm(system_prompt, user_message)
        raw_output = result["answer"]
        reasoning  = result["reasoning"]

        # Robust JSON extraction
        parsed_json = extract_json(raw_output)

        if parsed_json:
            with open("debug_synthesis.json", "w") as df:
                json.dump(parsed_json, df, indent=2)

        return {
            "status": "success",
            "raw_output": raw_output,
            "reasoning": reasoning or "(No reasoning provided)",
            "synthesis_report": parsed_json or {"error": "No JSON found", "_raw": raw_output[:500]},
            "tokens": {
                "prompt": result["prompt_tokens"],
                "generation": result["generation_tokens"],
                "stop_reason": result["stop_reason"],
            }
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


# â”€â”€ Run queue for SSE debug streaming â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_run_queues: dict[str, Queue] = {}

class RunRequest(BaseModel):
    alert_name: str = "Potential Cryptomining Activity Detected"
    host: str = "BSTOLL-L"
    domain: str = "coinhive.com"
    event_time: str = "2018-08-20T12:00:00Z"
    max_loops: int = 3
    context_contract: dict = None

@app.get("/debug")
def debug_page():
    return FileResponse(os.path.join(STATIC_DIR, "debug.html"))

@app.post("/api/run")
def start_run(req: RunRequest):
    run_id = str(uuid.uuid4())[:8]
    q: Queue = Queue()
    _run_queues[run_id] = q
    threading.Thread(target=_run_investigation, args=(run_id, req, q), daemon=True).start()
    return {"run_id": run_id}

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
                if item.get("type") in ("done", "error"):
                    break
            except Empty:
                yield "data: {\"type\":\"error\",\"message\":\"timeout\"}\n\n"
                break
    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

def _emit(q: Queue, event_type: str, data: dict, **extra):
    q.put({"type": event_type, "data": data, "message": extra.get("message",""), **{k:v for k,v in extra.items() if k != "message"}})

def _run_investigation(run_id: str, req: RunRequest, q: Queue):
    system_prompt = _load_system_prompt()
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
        user_msg = f"[ALERT CONTEXT]\n{json.dumps(alert_context, indent=2)}"
        r1 = call_llm(system_prompt, user_msg)
        plan = extract_json(r1["answer"]) or {}
        plan["reasoning"] = r1["reasoning"]
        _emit(q, "analyst", plan, message="Loop 1 complete",
              tokens={"prompt_tokens": r1["prompt_tokens"], "generation_tokens": r1["generation_tokens"], "stop_reason": r1["stop_reason"]})

        # â”€â”€ LOOPS 2..N: Broker + Synthesis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        all_findings = {}
        for loop_num in range(2, req.max_loops + 2):
            # Broker â€” stream each CLI output line as broker_log event
            _emit(q, "broker", {}, loop=loop_num, message=f"Loop {loop_num} â€” Broker starting...")
            findings = _run_broker_proc_streaming(req, alert_context, q, loop_num)
            all_findings[f"Round {loop_num}"] = findings
            _emit(q, "broker", findings, loop=loop_num, message=f"Loop {loop_num} â€” Broker complete")

            # Synthesis â€” build accumulated findings sections
            _emit(q, "synthesis", {}, loop=loop_num, message=f"Loop {loop_num} â€” Synthesis evaluating...")
            sections = [f"[INVESTIGATION PLAN]\n{json.dumps(plan, indent=2)}"]
            for round_label, round_findings in all_findings.items():
                slim = {k:v for k,v in round_findings.items() if k != "_raw_intel_dump"}
                sections.append(f"[BROKER FINDINGS - {round_label}]\n{json.dumps(slim, indent=2)}")
            rN = call_llm(system_prompt, "\n\n".join(sections))
            synth = extract_json(rN["answer"]) or {}
            _emit(q, "synthesis", synth, loop=loop_num, reasoning=rN["reasoning"],
                  tokens={"prompt_tokens": rN["prompt_tokens"], "generation_tokens": rN["generation_tokens"]},
                  message=f"Loop {loop_num} â€” Synthesis complete: {synth.get('status','?')}")

            status  = synth.get("status", "")
            verdict = synth.get("verdict", "")

            if status == "VERDICT_REACHED":
                _emit(q, "verdict", synth, message=f"VERDICT: {verdict}")
                break
            if loop_num == req.max_loops + 1:
                _emit(q, "verdict", {**synth, "verdict": verdict or "REQUIRES_INVESTIGATION"}, message="Max loops reached")
                break

        q.put({"type": "done", "message": "Investigation complete"})

    except Exception as exc:
        q.put({"type": "error", "message": str(exc)})
    finally:
        _run_queues.pop(run_id, None)


def _run_broker_proc_streaming(req: "RunRequest", alert_context: dict, q: Queue, loop_num: int) -> dict:
    """Run SmartOps Engine CLI. Stream every stdout/stderr line to UI as broker_log SSE. Return findings JSON."""
    from pathlib import Path as _Path
    import subprocess

    event_time = alert_context.get("normalized_seed", {}).get("event_time", "")
    since_arg: list[str] = []
    if event_time:
        try:
            from datetime import datetime as _dt, timedelta as _td
            dt = _dt.fromisoformat(event_time.replace("Z", "+00:00"))
            since = (dt - _td(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            until = (dt + _td(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            since_arg = ["--since", since, "--until", until]
        except Exception:
            since_arg = ["--hours", "24"]
    else:
        since_arg = ["--hours", "24"]

    engine_src = str(Path(__file__).parent.parent / "engine" / "src")
    mcp_config = str(Path(__file__).parent.parent / "mcp_servers.json")
    env = {
        **os.environ,
        "PYTHONPATH": engine_src,
        "PYTHONIOENCODING": "utf-8",
        "SMARTOPS_MCP_TLS_NO_VERIFY": "splunk",  # skip TLS verify for ngrok tunnel
    }

    # Extract dynamic goal and entities from alert_context
    goal = alert_context.get("goal", req.alert_name)
    alert_name = alert_context.get("normalized_seed", {}).get("alert_name", req.alert_name)
    
    cmd = [sys.executable, "-m", "smartops.main",
           "--goal", goal,
           "--hypothesis", f"Investigate alert: {alert_name}",
           "--mcp-config", mcp_config,
           *since_arg, "--budget-usd", "10"]
           
    entities = alert_context.get("normalized_seed", {}).get("entities", {})
    if entities:
        for kind, value in entities.items():
            if value:
                cmd.extend(["--entity", f"{kind}:{value}"])
    else:
        # Fallback if somehow missing
        cmd.extend(["--entity", f"host:{req.host}", "--entity", f"domain:{req.domain}"])

    try:
        subprocess.run(cmd, capture_output=True, text=True, env=env,
                       cwd=str(Path(__file__).parent.parent), timeout=300)
    except Exception:
        pass

    runs_dir = Path(__file__).parent.parent / ".smartops" / "runs"
    if runs_dir.exists():
        for pattern in ("findings.json", "report.json"):
            hits = sorted(runs_dir.rglob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
            if hits:
                return json.loads(hits[0].read_text(encoding="utf-8"))
    return {"_note": "No findings returned"}

