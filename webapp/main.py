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

from webapp.services.llm_service import call_llm, extract_json
from webapp.services import run_trace, splunk_mcp


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
CORPUS_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "corpus", "bm25_corpus.json")
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
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN",  "")
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
def _first(ev: dict, keys: list) -> str:
    """The first non-empty value among `keys` in a Splunk row (multivalue -> first value)."""
    for k in keys:
        v = ev.get(k)
        if isinstance(v, list):
            v = v[0] if v else ""
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _spl_escape(value: str) -> str:
    # The quote escape keeps an attacker-influenced name from closing an SPL string.
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _rule_of(ev: dict) -> str:
    rule = _first(ev, ["rule_name", "search_name", "source"])
    return rule[:-len(" - Rule")] if rule.endswith(" - Rule - Rule") else rule


@app.get("/api/import-from-splunk")
def import_from_splunk(index: int = 0, rule_name: str = None):
    """Pull a notable event from Splunk ES Mission Control and enrich it with the
    matching detection rule SPL from Content Management. `index=0` is the latest;
    `rule_name` keeps only that rule's notables."""
    try:
        # --- Step 1: Get notable events ---
        fetch_count = max(index + 1, 10)
        spl = "search index=notable"
        if rule_name:
            clean_rule = rule_name.replace(" - Rule - Rule", "").replace(" - Rule", "")
            pattern = _spl_escape(f"*{clean_rule}*")
            spl += f' (search_name="{pattern}" OR source="{pattern}")'
        events = splunk_mcp.run_query(
            f"{spl} | sort -_time | head {fetch_count}"
            " | table _time rule_name urgency status src dest user src_ip rule_id search_name *",
            earliest_time="-30d", latest_time="now", row_limit=fetch_count)
        if not events:
            return {"status": "empty", "message": "No notable events found in the last 30 days."}
        if not 0 <= index < len(events):
            return {"status": "error", "message": f"index={index} out of range: {len(events)} events found.",
                    "available": len(events)}

        ev = events[index]

        rule_name  = _rule_of(ev)
        src        = _first(ev, ["src", "src_ip"])
        dest       = _first(ev, ["dest", "Registry.dest", "dest_host"])
        user_field = _first(ev, ["user", "Registry.user", "user_name"])
        urgency    = _first(ev, ["urgency"])
        event_time = _first(ev, ["_time", "time"])

        # Try to extract additional context if present in the raw event
        file_hash = _first(ev, ["file_hash", "hash", "md5", "sha256", "process_hash"])
        domain    = _first(ev, ["domain", "url", "domain_query"])
        mitre     = _first(ev, ["mitre_attack_id", "mitre_technique_id", "annotations.mitre_attack"])
        sig       = _first(ev, ["signature", "action", "category", "registry_path",
                              "registry_key_name", "process_name", "process"])

        # Capture the entire raw dictionary to send as context
        raw_full = {k: v for k, v in ev.items() if k not in ["_bkt", "_cd", "_si", "_indextime", "_kv"]}


        # --- Step 2: Find matching detection rule SPL ---
        deployed_spl = ""
        # Look up by the saved search's real name: ES doubles the suffix ("... - Rule - Rule"),
        # and `rule_name` is the cleaned display name, which matches no saved search.
        saved_name = _first(ev, ["search_name", "source"]) or rule_name
        if saved_name:
            # `| rest` is read-only.
            escaped = _spl_escape(saved_name)
            rules = splunk_mcp.run_query(
                "| rest /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches splunk_server=local"
                f' search="name=\\"{escaped}\\"" | head 1 | fields search',
                row_limit=1)
            if rules:
                deployed_spl = rules[0].get("search", "")

        return {
            "status": "ok",
            "selected_index": index,
            "total_available": len(events),
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


@app.get("/api/incident-queue")
def get_incident_queue():
    """The latest notable events, for the Incident Queue."""
    try:
        events = splunk_mcp.run_query(
            "search index=notable | sort -_time | head 10"
            " | table _time rule_name urgency status src dest user src_ip rule_id search_name source dest_host user_name",
            earliest_time="-30d", latest_time="now", row_limit=10)
        return {"status": "ok", "events": [
            {"index": i, "time": _first(ev, ["_time", "time"]), "rule_name": _rule_of(ev),
             "urgency": _first(ev, ["urgency"]), "src": _first(ev, ["src", "src_ip"]),
             "dest": _first(ev, ["dest", "dest_host"]), "user": _first(ev, ["user", "user_name"])}
            for i, ev in enumerate(events)]}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


@app.get("/api/list-detection-rules")
def list_detection_rules():
    """Every enabled detection rule ("... - Rule") in Content Management."""
    try:
        rows = splunk_mcp.run_query(
            "| rest /servicesNS/-/-/saved/searches splunk_server=local count=0"
            " | search disabled=0 | fields title search", row_limit=10000)
        skip = ("Group Similar", "Lookup Gen", "Model Gen", "Swimlane")
        rules = [{"name": r["title"], "spl": r.get("search", "")} for r in rows
                 if r.get("title", "").endswith("- Rule") and not any(k in r["title"] for k in skip)]
        return {"status": "ok", "rules": rules, "total": len(rules)}
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

    # A Windows alert must not match a Linux or macOS rule (and so on).
    os_words = {"windows": ("windows",), "linux": ("linux",), "macos": ("macos", "mac ")}
    alert_os = next((os for os, words in os_words.items() if any(w in clean_name for w in words)), None)
    if alert_os:
        others = [os for os in os_words if os != alert_os]
        for i, name in enumerate(names):
            if any(w in name.lower() for w in others):
                scores[i] *= 0.1

    # One best match: the runners-up only added noise to the context.
    best = int(scores.argmax())
    if scores[best] <= 0:
        return {"status": "success", "matches": []}
    return {"status": "success", "matches": [{"rule": names[best], "score": float(scores[best]), "data": rules_data[best]}]}

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
                # Silence is not failure: a cold model or a long broker round can go
                # minutes without an event. The worker always ends with done/error.
                yield ": keepalive\n\n"
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
        tokens1 = {"prompt_tokens": r1["prompt_tokens"], "generation_tokens": r1["generation_tokens"], "stop_reason": r1["stop_reason"]}
        _emit(q, "analyst", plan, message="Loop 1 complete", tokens=tokens1)
        run_trace.record(run_id, "analyst_plan", 1, plan=plan, tokens=tokens1, context=alert_context)

        # â”€â”€ LOOPS 2..N: Broker + Synthesis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        all_findings = {}
        tasks = plan.get("tasks", [])
        for loop_num in range(2, req.max_loops + 2):
            # Handoff -> broker log -> broker steps -> sub-analyst payload: each stage is
            # its own event, so the UI shows the handshake rather than a JSON dump.
            findings, link = _run_broker_proc_streaming(tasks, run_id, loop_num, q, run_trace.alert_entities(alert_context))
            run_trace.record(run_id, "broker", loop_num, **link)
            if "broker_runs" in link:
                _emit(q, "broker", {"runs": link["broker_runs"], "handshake": link["handshake"]},
                      loop=loop_num, message=f"Loop {loop_num}: Broker complete")
            if link.get("error"):
                # Never fall back to another run's artifacts: that is how eleven
                # loops were once judged on an unrelated alert's evidence.
                q.put({"type": "error", "message": f"Loop {loop_num} broker failed: {link['error']}", "trace": link})
                return
            all_findings[f"Round {loop_num}"] = findings
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
            for round_label, round_findings in all_findings.items():
                slim = {k:v for k,v in round_findings.items() if k != "_raw_intel_dump"}
                sections.append(f"[BROKER FINDINGS - {round_label}]\n{json.dumps(slim, indent=2)}")
            rN = call_llm(system_prompt, "\n\n".join(sections))
            raw_synth = extract_json(rN["answer"]) or {}
            synth = run_trace.verdict_gate(raw_synth, plan)
            _emit(q, "synthesis", synth, loop=loop_num, reasoning=rN["reasoning"],
                  tokens={"prompt_tokens": rN["prompt_tokens"], "generation_tokens": rN["generation_tokens"]},
                  message=f"Loop {loop_num} â€” Synthesis complete: {synth.get('status','?')}")
            run_trace.record(run_id, "synthesis", loop_num, output=synth, model_status=raw_synth.get("status"),
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
            tasks = run_trace.follow_up_tasks(synth.get("follow_up_tasks", []), link["tasks"])
            if not tasks:
                _emit(q, "verdict", {**synth, "verdict": verdict or "REQUIRES_INVESTIGATION"},
                      message="No actionable follow-up tasks")
                break

        q.put({"type": "done", "message": "Investigation complete"})

    except Exception as exc:
        q.put({"type": "error", "message": str(exc)})
    finally:
        _run_queues.pop(run_id, None)


def _run_broker_proc_streaming(tasks: list, run_id: str, loop_num: int, q: Queue,
                               alert_scope: list | None = None) -> tuple[dict, dict]:
    """Send the Analyst's tasks to the Tool Broker; return (payload, trace link).

    The tasks go as a `task-input.v1` file (`--task-file`), and what comes back is
    the batch `analyst-payload.json` the sub-analysts wrote -- read from the batch
    id this call named, never from "the newest run on disk". The link says where
    everything for this round lives; it has an `error` key when there is nothing
    to judge.
    """
    run_dir = run_trace.runs_dir() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    task_file, dropped = run_trace.to_task_file(tasks, run_id, loop_num, alert_scope)
    task_path = run_dir / f"tasks-L{loop_num}.json"
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
    log_path = run_dir / f"broker-L{loop_num}.log"
    env = {
        **os.environ,
        # contracts lives beside the engine, not inside engine/src.
        "PYTHONPATH": os.pathsep.join([str(repo / "engine" / "src"), str(repo / "engine" / "contracts" / "src")]),
        "PYTHONIOENCODING": "utf-8",
        # Piped stdout is block-buffered; without this the "live" log arrives at exit.
        "PYTHONUNBUFFERED": "1",
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
    link.update(exit_code=returncode, log=str(log_path))

    link["broker_runs"] = run_trace.broker_runs(task_ids)
    payload_path = run_trace.runs_dir() / batch_id / "analyst-payload.json"
    link["payload"] = str(payload_path)
    payload = json.loads(payload_path.read_text(encoding="utf-8")) if payload_path.is_file() else None
    link["handshake"] = run_trace.handshake(task_ids, link["broker_runs"], payload)
    if timed_out.is_set():
        return {}, {**link, "error": f"broker timed out after 30 minutes, see {log_path}"}
    if returncode != 0:
        said = " ".join(cli_errors[-4:]) or "no error line printed"
        return {}, {**link, "error": f"broker exited {returncode}: {said} (log: {log_path})"}
    if payload is None:
        return {}, {**link, "error": f"broker wrote no analyst payload (analyst model configured?), see {log_path}"}
    return payload, link

