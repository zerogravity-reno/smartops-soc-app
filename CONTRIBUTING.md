# Contributing

Use this guide for a repeatable local setup. Run commands from the repository root unless a different directory is shown. The commands work in a POSIX shell or PowerShell; the environment-variable examples below use POSIX syntax.

## Install

Use Python 3.13, [uv](https://docs.astral.sh/uv/), and Node.js 24 with npm. Python is pinned by `.python-version` and `pyproject.toml`; uv can install the required interpreter. Node 24 was verified during cloud onboarding.

Use your existing checkout. Cloud tasks already provide an isolated checkout under `/workspace/smartops-soc-app`; no additional Git worktree is needed unless requested.

In the managed cloud environment, set writable cache locations before installing. Local machines can use the default cache locations instead:

```sh
export UV_CACHE_DIR=/workspace/.cache/uv
export UV_PYTHON_INSTALL_DIR=/workspace/.local/share/uv/python
```

For npm installs there, use `npm ci --cache /workspace/.cache/npm`. Installed dependencies and build outputs can be retained in an environment snapshot; running servers must be restarted after restore.

Install from the repository root:

```sh
uv sync --frozen
cd frontend
npm ci
npm run build
cd ..
```

These commands install the backend, shared contracts, Python test tools, and frontend dependencies using the committed lockfiles. Build the frontend before starting the API: asset routes are registered when the application is imported.

## Run and check the app

No credentials or `.env` file are needed to serve the UI, search the local ESCU corpus, or run the test suites.

```sh
uv run --frozen uvicorn smartops.main:app --host 0.0.0.0 --port 8013
```

Wait for `Application startup complete`. The API serves the built UI at `/`. From another terminal, verify that both the server and the local corpus work:

```sh
uv run --frozen python -c '
import json
from urllib.request import Request, urlopen

base = "http://127.0.0.1:8013"
with urlopen(base + "/", timeout=10) as page:
    assert page.status == 200 and b"id=\"root\"" in page.read()
request = Request(
    base + "/api/escu",
    data=json.dumps({"rule_name": "Windows PowerShell DownloadString"}).encode(),
    headers={"Content-Type": "application/json"},
)
with urlopen(request, timeout=10) as response:
    result = json.load(response)
assert result["status"] == "success" and result["matches"]
print("UI and ESCU lookup passed")
'
```

Without Splunk configuration, `/api/incident-queue` reports `no MCP server configured for siem`. This is expected for local development; it does not validate a live integration.

For frontend editing, keep the API running and start Vite in another terminal:

```sh
cd frontend
npm run dev
```

Vite uses port 5173 by default and proxies `/api` to the backend on port 8013. `SMARTOPS_API` can override the proxy target. Rebuild with `npm run build` to update the UI served by the API.

Stop a server with Ctrl+C in its terminal. Avoid backend `--reload` during investigations: restarting the process loses in-memory runs. The existing Windows `start.ps1` convenience launcher installs dependencies and starts with reload; the explicit commands above use frozen installs.

## Test before sharing changes

From the repository root:

```sh
uv run --frozen pytest -q -ra
```

From `frontend/`:

```sh
npm test
npm run build
```

The Python suite covers `engine/contracts/tests`, `engine/tests`, and `tests`. The frontend build includes TypeScript checking. These checks do not require service credentials or model calls. There is no configured `npm run e2e` command.

Report the command, result, and any skips or failures in your pull request. The UTC artifact check can skip when no stored investigation exists; a skip is not a passing integration test. A successful local suite does not establish that Splunk or live models work.

For a targeted Python check, pass its path to pytest, for example `uv run --frozen pytest -q engine/contracts/tests/test_published_schema.py`. Run the broader checks above before sharing changes affecting multiple components.

## Configure live services

See the [README environment-variable reference](README.md#environment-variables-env) for the complete settings. Live investigations need a model ARN and Bedrock authentication, an Anthropic API key, and the actual Splunk MCP endpoint and token. VirusTotal and OpenCTI are additional integrations.

Use secure environment settings or a local, git-ignored `.env` in the repository root. Existing shell variables take precedence over `.env`. Treat `.env.example` as a reference: it includes placeholders and a TLS bypass that should not be copied into a working configuration. Keep TLS verification enabled and configure trusted certificates for private services.

Cloud network access must allow the actual integration hosts as well as the package registries. Reuse existing credentials and bindings before requesting new ones. Never paste credentials into issues, pull requests, logs, or setup scripts.

Live investigations incur API charges. `--scripted` disables model calls in the Broker CLI, but configured domain services can still receive requests. `SMARTOPS_LLM_PROVIDER=none` disables Broker models only; it does not disable the web Analyst's Bedrock calls.

## Keep collaboration clean

- Create a dedicated branch for every change before editing, for example `git switch -c docs/update-setup-guide`. Commit and push that branch, then open a pull request targeting `main`. Merge through pull request review; do not commit or push changes directly to `main`.
- Check `git status --short` before starting and before handing work over. Preserve other developers' changes and keep each change focused.
- Keep `.venv/`, `frontend/node_modules/`, `frontend/dist/`, `.env`, logs, and investigation outputs out of commits. These paths are already ignored. Review staged files rather than adding the entire checkout blindly.
- Direct exploratory Broker output to a scratch location with `SMARTOPS_RUNS_DIR`; keep runs separate from committed examples and test fixtures. Use the task files in [docs/examples](docs/examples/README.md) as inputs.
- Use `uv sync --frozen` and `npm ci` for routine setup. Change dependency declarations and regenerate the relevant lockfile together only for an intentional dependency update; describe and test that update in the pull request.
- When changing published contract models, regenerate schemas from the repository root with `uv run --frozen python engine/contracts/schemas/generate.py`, inspect the generated diff, and run the contract tests. Breaking changes need a new schema version so existing consumers retain their contract.
- Describe the behavior changed, validation performed, and remaining limitations in pull requests. Include reproduction steps for bugs and coordinate changes to shared API contracts using [docs/frontend-api-contract.md](docs/frontend-api-contract.md).
- Update this guide and the README in the same change when installation, commands, ports, required variables, or supported tool versions change. Check commands from their documented directories and use a local functional request when startup behavior changes. Keep credential-free checks separate from live service validation.

Coding agents must also follow [AGENTS.md](AGENTS.md). New pull requests use the repository's [review template](.github/pull_request_template.md).

## Enforce the pull request workflow on GitHub

Documentation describes the policy; GitHub branch protection or a branch ruleset enforces it. A repository administrator should configure an active rule targeting `main` in **Settings → Rules → Rulesets** (or **Settings → Branches** for branch protection):

- Require a pull request before merging and at least one approval from another developer.
- Dismiss stale approvals when new commits are pushed.
- Block force pushes and branch deletion.
- Apply the rule to administrators as well, with no routine bypass actors.

Developers push topic branches and merge through reviewed pull requests. Required status checks should name actual CI jobs once those jobs exist; the local test commands in this guide do not themselves create GitHub checks. An administrator must verify that the rule is active and supported by the repository's GitHub plan before treating direct pushes as blocked.
