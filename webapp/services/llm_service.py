"""
llm_service.py - Foundation-Sec-8B-Reasoning on AWS Bedrock
Uses invoke_model via httpx directly (bypasses boto3 Windows socket issues).
Bearer token auth via Authorization header.
"""
import json, os, time
import httpx

MODEL_ARN = os.environ.get("FS8B_MODEL_ARN", "")
API_KEY   = os.environ.get("FS8B_API_KEY", "")
REGION    = MODEL_ARN.split(":")[3] if MODEL_ARN and len(MODEL_ARN.split(":")) > 3 else os.environ.get("AWS_REGION", "us-east-1")

DEFAULT_TEMPERATURE = 0.0
DEFAULT_TOP_P       = 0.95
DEFAULT_MAX_GEN_LEN = 4096
COLD_START_RETRIES  = 10
COLD_START_WAIT     = 30.0

PROMPT_TEMPLATE = (
    "<|begin_of_text|><|system|>\n{system}\n"
    "<|user|>\n{user}\n"
    "<|assistant|>\n<think>\n"
)

def _get_endpoint():
    model_id_encoded = MODEL_ARN.replace(":", "%3A").replace("/", "%2F")
    return f"https://bedrock-runtime.{REGION}.amazonaws.com/model/{model_id_encoded}/invoke"

def call_llm(system_prompt, user_message, *, temperature=DEFAULT_TEMPERATURE,
             top_p=DEFAULT_TOP_P, max_gen_len=DEFAULT_MAX_GEN_LEN):
    if not MODEL_ARN:
        raise RuntimeError("FS8B_MODEL_ARN is not set. Check your .env file.")
    if not API_KEY:
        raise RuntimeError("FS8B_API_KEY is not set. Check your .env file.")

    payload = json.dumps({
        "prompt":      PROMPT_TEMPLATE.format(system=system_prompt, user=user_message),
        "max_gen_len": max_gen_len,
        "temperature": temperature,
        "top_p":       top_p,
    })

    url = _get_endpoint()
    headers = {
        "Content-Type":  "application/json",
        "Accept":        "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }

    last_exc = None
    for attempt in range(COLD_START_RETRIES + 1):
        try:
            resp = httpx.post(
                url, content=payload, headers=headers,
                timeout=httpx.Timeout(connect=15.0, read=600.0, write=30.0, pool=15.0),
                verify=True,
            )
            if resp.status_code == 200:
                break
            if resp.status_code in (503, 429) and attempt < COLD_START_RETRIES:
                print(f"  [Bedrock] Cold start (HTTP {resp.status_code}) attempt {attempt+1}/{COLD_START_RETRIES}, waiting {int(COLD_START_WAIT)}s...", flush=True)
                time.sleep(COLD_START_WAIT)
                continue
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout,
                httpx.RemoteProtocolError, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt < COLD_START_RETRIES:
                wait = COLD_START_WAIT if attempt > 0 else 5
                print(f"  [Bedrock] Connection error ({type(exc).__name__}: {exc}), retry {attempt+1}/{COLD_START_RETRIES}, waiting {int(wait)}s...", flush=True)
                time.sleep(wait)
                continue
            raise RuntimeError(f"Bedrock unreachable after {COLD_START_RETRIES} retries: {exc}") from exc
        except Exception as exc:
            last_exc = exc
            exc_str = str(exc)
            if attempt < COLD_START_RETRIES and (
                "[Errno 22]" in exc_str or "Invalid argument" in exc_str or
                "Connection" in exc_str or "timeout" in exc_str.lower()
            ):
                print(f"  [Bedrock] Error ({exc}), retry {attempt+1}/{COLD_START_RETRIES}, waiting 5s...", flush=True)
                time.sleep(5)
                continue
            raise RuntimeError(f"Bedrock call failed: {exc}") from exc
    else:
        raise RuntimeError(f"Bedrock failed after {COLD_START_RETRIES} retries. Last error: {last_exc}")

    out = resp.json()
    raw = out.get("generation", "")
    if "</think>" in raw:
        reasoning, _, answer = raw.partition("</think>")
    else:
        reasoning, answer = "", raw
    return {
        "reasoning": reasoning.strip(), "answer": answer.strip(), "raw": raw,
        "prompt_tokens": out.get("prompt_token_count", 0),
        "generation_tokens": out.get("generation_token_count", 0),
        "stop_reason": out.get("stop_reason", "unknown"),
    }

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
