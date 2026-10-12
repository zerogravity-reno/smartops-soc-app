"""The alert's context, before any agent sees it: the Splunk notable queue and
import, OpenCTI threat intel, the ESCU reference rule, and the alert's own
entities and event time. Not an agent: no model call happens here.
"""

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import requests as _http_requests

from smartops.tools.registry import call_tool

REPO = Path(__file__).resolve().parents[3]


# ── Splunk, through the backend's MCP client (`smartops.tools`) ───────────────
def run_query(query: str, earliest_time: str = "", latest_time: str = "", row_limit: int = 100) -> list[dict]:
    """`splunk_run_query`'s rows. Raises on a tool error rather than returning it as data."""
    args = {"query": query, "row_limit": row_limit}
    if earliest_time:
        args["earliest_time"] = earliest_time
    if latest_time:
        args["latest_time"] = latest_time
    return call_tool("siem", "splunk_run_query", args).get("results", [])


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


def import_notable(index: int = 0, rule_name: str = None) -> dict:
    """Pull a notable event from Splunk ES Mission Control and enrich it with the
    matching detection rule SPL from Content Management. `index=0` is the latest;
    `rule_name` keeps only that rule's notables."""
    try:
        # --- Step 1: Get notable events ---
        fetch_count = max(index + 1, 10)
        pattern = None
        if rule_name:
            clean_rule = rule_name.replace(" - Rule - Rule", "").replace(" - Rule", "")
            pattern = _spl_escape(f"*{clean_rule}*")
        events = run_query(
            f"{notables_spl(pattern)} | head {fetch_count}"
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
        event_time = notable_event_time(ev)

        # Try to extract additional context if present in the raw event
        file_hash = _first(ev, ["file_hash", "hash", "md5", "sha256", "process_hash"])
        domain    = _first(ev, ["domain", "url", "domain_query"])
        mitre     = _first(ev, ["mitre_attack_id", "mitre_technique_id", "annotations.mitre_attack"])
        sig       = _first(ev, ["signature", "process", "process_name", "registry_path",
                              "registry_key_name", "category", "action"])

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
            rules = run_query(
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


def incident_queue() -> dict:
    """The latest alert events for the Incident Queue, one per event (see
    `notables_spl`), grouped by rule and host."""
    try:
        events = run_query(
            notables_spl() + " | head 50"
            " | table _time rule_name urgency status src dest user src_ip rule_id search_name source dest_host user_name",
            earliest_time="-30d", latest_time="now", row_limit=50)
        return {"status": "ok", "groups": group_notables([
            {"index": i, "time": _first(ev, ["_time", "time"]), "rule_name": _rule_of(ev),
             "urgency": _first(ev, ["urgency"]), "src": _first(ev, ["src", "src_ip"]),
             "dest": _first(ev, ["dest", "dest_host"]), "user": _first(ev, ["user", "user_name"])}
            for i, ev in enumerate(events)])}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


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


# ── The alert's own entities and time ────────────────────────────────────────
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


# ── OpenCTI ───────────────────────────────────────────────────────────────────
OPENCTI_URL   = os.environ.get("OPENCTI_URL",   "http://localhost:8080/graphql")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN",  "")
OPENCTI_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type":  "application/json",
}

# Seconds per OpenCTI request. A server that accepts and never answers made each
# observable wait out a 10s read, one after another, before the run could start.
OPENCTI_TIMEOUT = float(os.environ.get("OPENCTI_TIMEOUT", "5"))


def _gql(query: str, variables: dict = {}):
    """Execute a GraphQL query against OpenCTI."""
    try:
        resp = _http_requests.post(
            OPENCTI_URL, headers=OPENCTI_HEADERS,
            json={"query": query, "variables": variables}, timeout=OPENCTI_TIMEOUT)
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
    v = value.strip()
    if re.match(r'^T\d{4}(\.\d{3})?$', v, re.IGNORECASE): return "technique"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):            return "ip"
    if re.match(r'^[a-fA-F0-9]{32,64}$', v):               return "hash"
    if "." in v and not v[0].isdigit():                    return "domain"
    return "general"


def opencti(observables: list[str]) -> dict:
    # One probe first: unreachable OpenCTI costs one timeout, not one per observable.
    probe = _gql("{ about { version } }")
    if "error" in probe:
        return {"status": "unavailable", "source": f"OpenCTI ({OPENCTI_URL})", "message": probe["error"],
                "total_observables": len(observables), "results": {}}
    results = {}
    for obs in observables:
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
        if "error" in r or "error" in r.get("observable_result", {}):
            break  # it went down mid-request: the rest would each wait out a timeout
    return {"status": "success", "source": f"OpenCTI Live API ({OPENCTI_URL})",
            "total_observables": len(observables), "results": results}


# ── ESCU reference rule (local BM25) ─────────────────────────────────────────
CORPUS_PATH = REPO / "docs" / "corpus" / "bm25_corpus.json"
try:
    with open(CORPUS_PATH, "r", encoding="utf-8") as f:
        bm25_corpus = json.load(f)
except Exception as e:
    bm25_corpus = {}
    print(f"Warning: Could not load bm25_corpus.json: {e}")


def escu(rule_name: str) -> dict:
    from rank_bm25 import BM25Okapi

    if not bm25_corpus:
        return {"status": "error", "message": "ESCU corpus not loaded"}

    corpus_dict = bm25_corpus.get("doc_meta", bm25_corpus)
    rules_data = list(corpus_dict.values())
    names = [r.get("name", "") for r in rules_data]

    tokenized = [n.lower().split() for n in names]
    bm25 = BM25Okapi(tokenized)

    # Clean the incoming rule name from common ES prefixes/suffixes to improve BM25 score
    clean_name = rule_name.lower()
    clean_name = re.sub(r'^(endpoint|network|cloud|web)\s*-\s*', '', clean_name)
    clean_name = re.sub(r'sama\s*-\s*', '', clean_name)
    clean_name = re.sub(r'escu\s*-\s*', '', clean_name)
    clean_name = re.sub(r'\s*-\s*rule(\s*-\s*rule)?$', '', clean_name)

    query_tokens = clean_name.split()
    scores = bm25.get_scores(query_tokens)

    # The alert's OS boosts a rule naming it; another OS halves it.
    os_keywords = ["windows", "linux", "mac", "macos", "aws", "azure", "gcp"]
    present_os = [o for o in os_keywords if o in rule_name.lower()]
    if present_os:
        for i, name in enumerate(names):
            name_lower = name.lower()
            for o in os_keywords:
                if o in name_lower:
                    scores[i] *= 1.5 if o in present_os else 0.5

    top_idx = scores.argsort()[::-1][:3]
    return {"status": "success", "matches": [
        {"rule": names[i], "score": float(scores[i]), "data": rules_data[i]} for i in top_idx if scores[i] > 0]}
