#!/usr/bin/env python3
"""
orchestrator.py — SmartOps SOC 3-Loop Auto Investigator
========================================================
Loop 1: Analyst (Foundation-Sec-8B on Bedrock) builds hypotheses + tasks.
Loop N: Broker (SmartOps Engine) dispatches tasks to real Subagents (Splunk/VT).
         Synthesis (Foundation-Sec-8B) evaluates findings.
         If REQUIRES_INVESTIGATION and loops remain -> repeat Broker + Synthesis.
Max loops: 3 (configurable).
"""

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# ── Load .env ──────────────────────────────────────────────────────────────
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

# ── Add engine to path ─────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent / "engine" / "src"))

from webapp.services.llm_service import call_llm, extract_json

MAX_LOOPS    = 3
SYSTEM_PROMPT_PATH = Path(__file__).parent / "webapp" / "prompts" / "system_prompt.txt"

def _load_system_prompt():
    return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")

def _separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ──────────────────────────────────────────────────────────────────────────
# LOOP 1: Analyst (Planning Mode)
# ──────────────────────────────────────────────────────────────────────────
def run_analyst(alert_context: dict) -> dict:
    _separator("LOOP 1 — ANALYST (Planning Mode)")
    system_prompt = _load_system_prompt()
    user_message = f"[ALERT CONTEXT]\n{json.dumps(alert_context, indent=2)}"

    print("Calling Foundation-Sec-8B on Bedrock (may warm up ~4 min on first call)...")
    result = call_llm(system_prompt, user_message)
    print(f"Stop reason: {result['stop_reason']} | Tokens: {result['prompt_tokens']}p + {result['generation_tokens']}g")
    print(f"\n--- REASONING (first 500 chars) ---\n{result['reasoning'][:500]}...")

    parsed = extract_json(result["answer"])
    if not parsed:
        print("WARNING: Could not parse JSON from Analyst. Raw output:")
        print(result["answer"][:800])
        return {}

    parsed["_architecture_note"] = (
        "Tasks and hypotheses are no longer mapped 1:1. "
        "Evidence gathered holistically, scored independently."
    )
    print(f"\nHypotheses: {[h.get('verdict') for h in parsed.get('hypotheses', [])]}")
    print(f"Tasks generated: {len(parsed.get('tasks', []))}")
    for t in parsed.get("tasks", []):
        if isinstance(t, dict):
            print(f"  [{t.get('task_id', '?')}] {t.get('question', str(t))[:80]}")
        else:
            print(f"  [task] {str(t)[:80]}")
    return parsed


# ──────────────────────────────────────────────────────────────────────────
# LOOP N: Broker (Subagents via Engine CLI)
# ──────────────────────────────────────────────────────────────────────────
def run_broker(planning_template: dict, alert_context: dict, loop_num: int) -> dict:
    _separator(f"LOOP {loop_num} — BROKER (Subagents: Splunk + VirusTotal)")

    # Build CLI args from alert context + tasks
    goal = alert_context.get("normalized_seed", {}).get("alert_name",
           alert_context.get("goal", "Investigate the alert"))

    entities = alert_context.get("normalized_seed", {}).get("entities", {})
    entity_args = []
    for kind, value in entities.items():
        if kind == "hostname" or kind == "host":
            entity_args += ["--entity", f"host:{value}"]
        elif kind == "src_ip" or kind == "ip":
            entity_args += ["--entity", f"ip:{value}"]
        elif kind == "user":
            entity_args += ["--entity", f"user:{value}"]
        elif kind == "domain":
            entity_args += ["--entity", f"domain:{value}"]

    if not entity_args:
        entity_args = ["--entity", "host:UNKNOWN"]

    # Time window from alert
    event_time = alert_context.get("normalized_seed", {}).get("event_time", "")
    since_arg = []
    if event_time:
        try:
            dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            since = (dt - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            until = (dt + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            since_arg = ["--since", since, "--until", until]
        except Exception:
            since_arg = ["--hours", "24"]
    else:
        since_arg = ["--hours", "24"]

    # Include hypothesis for blind analyst tier
    hypothesis_text = "; ".join(
        f"{h.get('verdict')}: {h.get('description','')}"
        for h in planning_template.get("hypotheses", [])
    )

    cmd = [
        sys.executable, "-m", "smartops.main",
        "--goal", goal,
        *entity_args,
        *since_arg,
        "--hypothesis", hypothesis_text,
        "--budget-usd", "10",
        "--verbose",
    ]

    # Check if Splunk is configured
    if not os.environ.get("SPLUNK_MCP_URL"):
        print("WARNING: SPLUNK_MCP_URL not set — siem subagent will report 'no MCP server'")
        print("         VT subagent will still run if VT_API_KEY is set.")

    print(f"Running Engine: smartops-broker --goal \"{goal[:60]}...\"")
    print(f"Entities: {entity_args}")

    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent / "engine" / "src")}

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            cwd=str(Path(__file__).parent),
            env=env,
            timeout=600,
        )
        print(proc.stdout[-3000:] if len(proc.stdout) > 3000 else proc.stdout)
        if proc.returncode != 0:
            print(f"Broker stderr: {proc.stderr[-1000:]}")
    except subprocess.TimeoutExpired:
        print("ERROR: Broker timed out after 10 minutes.")
        return {}

    # Read the latest findings.json from .smartops/runs/
    runs_dir = Path(".smartops/runs")
    findings = {}
    if runs_dir.exists():
        all_runs = sorted(runs_dir.rglob("findings.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if all_runs:
            latest = all_runs[0]
            print(f"\nLoading findings from: {latest}")
            findings = json.loads(latest.read_text(encoding="utf-8"))
        else:
            # Fall back to report.json
            all_reports = sorted(runs_dir.rglob("report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if all_reports:
                latest = all_reports[0]
                print(f"\nLoading report from: {latest}")
                findings = json.loads(latest.read_text(encoding="utf-8"))
    else:
        print("No .smartops/runs directory found — using empty findings.")

    return findings


# ──────────────────────────────────────────────────────────────────────────
# LOOP N: Synthesis (Evaluation Mode)
# ──────────────────────────────────────────────────────────────────────────
def run_synthesis(planning_template: dict, all_findings: dict, loop_num: int) -> dict:
    _separator(f"LOOP {loop_num} — SYNTHESIS (Evaluation Mode)")
    system_prompt = _load_system_prompt()

    # [INVESTIGATION PLAN] = analyst's original hypotheses + tasks (never changes)
    sections = [f"[INVESTIGATION PLAN]\n{json.dumps(planning_template, indent=2)}"]

    # One labeled section per broker round — model sees ALL accumulated evidence
    for round_label, round_findings in all_findings.items():
        slim = {k: v for k, v in round_findings.items() if k != "_raw_intel_dump"}
        sections.append(f"[BROKER FINDINGS - {round_label}]\n{json.dumps(slim, indent=2)}")

    user_message = "\n\n".join(sections)

    print(f"Calling Foundation-Sec-8B on Bedrock for Synthesis (rounds seen: {list(all_findings.keys())})...")
    result = call_llm(system_prompt, user_message)
    print(f"Stop reason: {result['stop_reason']} | Tokens: {result['prompt_tokens']}p + {result['generation_tokens']}g")
    print(f"\n--- REASONING (first 500 chars) ---\n{result['reasoning'][:500]}...")

    parsed = extract_json(result["answer"])
    if not parsed:
        print("WARNING: Could not parse JSON from Synthesis. Raw:")
        print(result["answer"][:800])
        return {"status": "parse_error", "raw": result["answer"]}

    print(f"\nStatus:  {parsed.get('status', 'unknown')}")
    print(f"Verdict: {parsed.get('verdict', 'N/A')}")
    scores = parsed.get("hypothesis_scores", {})
    if scores:
        print("Scores:")
        for hid, score in scores.items():
            print(f"  {hid}: {score}")

    return parsed


# ──────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────
def main():
    # ── Example alert (BOTSv3 coinhive case) ──────────────────────────────
    alert_context = {
        "normalized_seed": {
            "alert_name": "Potential Cryptomining Activity Detected",
            "event_time": "2018-08-20T12:00:00Z",
            "severity": "high",
            "entities": {
                "host": "BSTOLL-L",
                "domain": "coinhive.com",
            }
        },
        "escu_context": {
            "rule_name": "Detect Outbound SMTP Traffic",
            "deployed_spl": "index=network sourcetype=stream:dns query=coinhive.com",
            "reference_spl": "index=network sourcetype=stream:dns (query=coinhive.com OR query=*mining*)",
            "mitre": "T1496"
        },
        "goal": "Is coinhive.com known-malicious, and what did host BSTOLL-L do with it?"
    }

    print("\nSTARTING SmartOps SOC — 3-Loop Auto Investigator")
    print(f"Alert: {alert_context['normalized_seed']['alert_name']}")
    print(f"Entities: {alert_context['normalized_seed']['entities']}")

    # LOOP 1: Analyst
    planning_template = run_analyst(alert_context)
    if not planning_template:
        print("\nERROR: Analyst returned no planning template. Aborting.")
        return

    # Save Loop 1 output
    Path("loop1_output.json").write_text(json.dumps(planning_template, indent=2), encoding="utf-8")
    print("\nLoop 1 output saved to loop1_output.json")

    # LOOPS 2 to MAX_LOOPS+1: Broker + Synthesis
    all_findings = {}   # accumulates findings from every round
    for loop_num in range(2, MAX_LOOPS + 2):
        findings = run_broker(planning_template, alert_context, loop_num)

        if not findings:
            print(f"\nLoop {loop_num}: No findings returned. Using empty dict.")
            findings = {"_note": "Broker returned no findings", "loop": loop_num}

        # Accumulate — each round stored under its own key
        all_findings[f"Round {loop_num}"] = findings

        synthesis = run_synthesis(planning_template, all_findings, loop_num)


        # Save loop output
        out_file = f"loop{loop_num}_output.json"
        Path(out_file).write_text(json.dumps({
            "findings": findings,
            "synthesis": synthesis,
        }, indent=2), encoding="utf-8")
        print(f"\nLoop {loop_num} output saved to {out_file}")

        status = synthesis.get("status", "")
        verdict = synthesis.get("verdict", "")

        if status == "VERDICT_REACHED":
            _separator(f"INVESTIGATION COMPLETE — {verdict}")
            print(f"Confidence: {synthesis.get('verdict_confidence', 'N/A')}")
            print(f"Reasoning:  {synthesis.get('verdict_reasoning', 'N/A')[:300]}")
            return

        if loop_num == MAX_LOOPS + 1:
            _separator(f"MAX LOOPS ({MAX_LOOPS}) REACHED — FINAL VERDICT: {verdict or 'REQUIRES_INVESTIGATION'}")
            print("Follow-up tasks recommended:")
            for t in synthesis.get("follow_up_tasks", []):
                if isinstance(t, dict):
                    print(f"  - {t.get('question', str(t))}")
                else:
                    print(f"  - {t}")
            return

        print(f"\nStatus: REQUIRES_INVESTIGATION — continuing to loop {loop_num + 1}...")

    print("\nDone.")

if __name__ == "__main__":
    main()

