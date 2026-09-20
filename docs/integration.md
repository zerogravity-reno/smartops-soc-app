# SmartOps SOC — Integration Architecture

## What Was Merged

| Before | After |
|---|---|
| `rs/webapp/` — FastAPI UI calling **Ollama** locally | `smartops-soc/webapp/` — same UI, now calls **AWS Bedrock** |
| `smartops-soc-app-task-broker-agent/` — CLI-only engine | `smartops-soc/engine/` — importable Python package |
| Two separate folders, no connection | One unified repo, UI drives the Engine |

---

## Folder Structure

```
smartops-soc/
├── .env                          # Credentials (Bedrock, Splunk, VT)
├── .env.example                  # Template
├── pyproject.toml                # Combined dependencies (uv workspace)
├── mcp_servers.json              # Splunk MCP config
├── bm25_corpus.json              # ESCU local search corpus
│
├── engine/                       # SmartOps Engine (moved as-is, untouched)
│   └── src/smartops/
│       ├── broker.py             # Task Broker (Strands Agent)
│       ├── subagents/            # SIEM / VT domain subagents
│       ├── subagent_analysts/    # 3 blind domain analysts (Foundation-Sec-8B)
│       └── main.py               # run_investigation() entry point
│
└── webapp/                       # Web UI (refactored)
    ├── main.py                   # FastAPI app + all endpoints
    ├── prompts/
    │   └── system_prompt.txt     # Unified system prompt (PLANNING + EVALUATION)
    ├── services/
    │   └── llm_service.py        # Bedrock client (call_llm + extract_json)
    └── static/
        ├── index.html
        ├── style.css
        └── app.js
```

---

## The Key Change: Ollama → Bedrock

### Before (Ollama)
```python
# Old app.py
payload = json.dumps({
    "model": "foundation-sec-reasoning",
    "messages": [{"role": "system", ...}, {"role": "user", ...}],
    "format": "json",
    "think": False,
    "stream": False
})
with urlreq.urlopen("http://localhost:11434/api/chat", data=payload, timeout=900) as r:
    result = json.loads(r.read())
    raw_output = result["message"]["content"]
```

### After (Bedrock via `llm_service.py`)
```python
# New webapp/services/llm_service.py
from webapp.services.llm_service import call_llm

result = call_llm(system_prompt, user_message)
reasoning  = result["reasoning"]   # content inside <think>...</think>
raw_output = result["answer"]      # content after </think>
```

### Why the client is built this way
Foundation-Sec-8B uses an **ABSK bearer token** (not AWS access keys).
The naive approach of setting `AWS_BEARER_TOKEN_BEDROCK` in `os.environ` fails silently because
botocore re-reads the environment on every request. The token must be injected via
`ScopedEnvTokenProvider` with a **private dict**, and `auth_scheme_preference="httpBearerAuth"`
must be set on the client — otherwise botocore falls back to SigV4 and the token is never used.
The error you get is `AccessDeniedException: resource ARN from different account`, which is misleading.

```python
session = botocore.session.get_session()
session.register_component(
    "token_provider",
    ScopedEnvTokenProvider(session, environ={"AWS_BEARER_TOKEN_BEDROCK": API_KEY}),
)
client = boto3.Session(botocore_session=session).client(
    "bedrock-runtime",
    region_name=REGION,
    config=Config(auth_scheme_preference="httpBearerAuth"),
)
```

---

## The Prompt Shape

Foundation-Sec-8B does NOT use the Converse API or OpenAI-style messages.
It requires a raw string in its own Llama-style chat template:

```
<|begin_of_text|><|system|>
{system_prompt}
<|user|>
{user_message}
<|assistant|>
<think>
```

The seeded `<think>` at the end is the generation cue. The model responds with:
```
...reasoning trace...
</think>
...final answer / JSON...
```

We split on `</think>` to separate:
- `reasoning` — the model's internal chain-of-thought (kept for audit)
- `answer` — the actual output we parse for JSON

---

## Cold Start Behaviour

An idle imported model on Bedrock gets evicted and must reload (~1–4 minutes).
The first call raises `ModelNotReadyException` repeatedly until it is warm.
`call_llm()` retries up to 8 times at 30-second intervals automatically.

```
loading, attempt 1/8... (30s)
loading, attempt 2/8... (30s)
...
[model answers in seconds once warm]
```

This is **not a bug** — it is expected and not billed. Do not build a keep-alive ping
loop (it bills per copy-minute, not per token, so a keep-alive loop costs continuously).

---

## Loop Architecture (How the Two Projects Connect)

```
[Web UI — index.html]
      |
      | POST /api/analyst
      v
[webapp/main.py — Analyst endpoint]
      | call_llm(system_prompt, [ALERT CONTEXT])
      v
[Foundation-Sec-8B on Bedrock]
      | returns PlanningTemplate (H1/H2/H3 + Tasks)
      v
[sessionStorage in Browser]  ← Loop 1 Memory saved here
      |
      | (Next: user pastes Broker Findings, or /api/broker dispatches Engine)
      |
      | POST /api/synthesis
      v
[webapp/main.py — Synthesis endpoint]
      | call_llm(system_prompt, [LOOP 1 MEMORY] + [BROKER FINDINGS])
      v
[Foundation-Sec-8B on Bedrock]
      | returns Verdict (VERDICT_REACHED or REQUIRES_INVESTIGATION)
      v
[Web UI — Synthesis Report displayed]
```

---

## Running the Unified App

```bash
# 1. Install dependencies
cd smartops-soc
uv sync

# 2. Set credentials
cp .env.example .env
# Fill in FS8B_MODEL_ARN, FS8B_API_KEY, AWS_REGION

# 3. Start the server
uv run uvicorn webapp.main:app --port 8001 --reload

# 4. Open browser
# http://localhost:8001
```

---

## Environment Variables Reference

| Variable | Required | Purpose |
|---|---|---|
| `FS8B_MODEL_ARN` | ✅ | Full ARN of imported Foundation-Sec-8B model |
| `FS8B_API_KEY` | ✅ | ABSK bearer token (starts with ABSK...) |
| `AWS_REGION` | ✅ | Must match region in the ARN (field 4) |
| `AWS_BEDROCK_MODEL_ID` | For Broker | Claude Sonnet model ID for the Task Broker |
| `SPLUNK_MCP_URL` | For Broker | Splunk management port with MCP |
| `SPLUNK_TOKEN` | For Broker | Splunk bearer token |
| `VT_API_KEY` | For Broker | VirusTotal API key |
