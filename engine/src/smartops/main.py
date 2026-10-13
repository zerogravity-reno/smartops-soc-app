"""The backend's one entry point: the API server (`app`, served by uvicorn) and the
CLI (`run`), which runs the Task Broker over one or more investigative tasks.

Both are deliberately thin. The Analyst is `smartops.analyst`, the Tool Broker
`smartops.broker`, the alert context `smartops.context`; the frontend is
`frontend/`, served from its build at `/`.

**Two ways a task arrives, one execution path.** `--task-file` reads the JSON
contract the Analyst side produces (`contracts.TaskInputFile`, one entry per
hypothesis); the older `--goal`/`--entity`/`--since` flags build a single task
by hand. Both are normalised to a list of `(AnalystTask, hypothesis)` pairs by
`_tasks_from_args()`, so nothing downstream has two cases to handle -- the flag
path is simply a list of one.

**Fetch is sequential, analysis is one parallel burst.** With several tasks the
Brokers run one at a time and every analyst call is deferred to the end. Both
halves of that are deliberate; see `_run` for the reasoning, which is about
Splunk's search quotas on one side and the analyst model's 5-minute billing
windows on the other.

**When this calls a model, and when it does not.** `broker.default_broker_invoker()`
builds a real Strands `Agent`, and `broker_task()` uses it whenever
`model_choices_from_env()` resolves a configured provider. Only when none is
configured (or `--scripted` is passed) does this CLI fall back to
`_scripted_invoker()` instead: a deterministic stand-in that dispatches exactly
the families named by `--families` -- a flag that does nothing on the model
path, where the tool gate (`available_broker_tools()`) decides what is
available instead. Everything downstream of the dispatch decision -- mission
construction, the entity gate, tool resolution, result collection, budget
settlement -- is the real code path either way.

Splunk is configured and returns real rows for `siem`; whether a family is
accepted or rejected depends on which MCP servers `--mcp-config` (or its
defaults) resolve, not on a blanket "nothing is configured yet".
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args

from pydantic import ValidationError

from contracts import (
    AnalystTask,
    Entity,
    EntityKind,
    Scope,
    TaskInputFile,
)
from smartops.broker import (
    AWS_PROFILE_ENV_VAR,
    DEFAULT_BUDGET_USD_PER_TASK,
    DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK,
    _name_the_task,
    run_round,
    start,
)
from smartops.domains import ALL_FAMILIES
from smartops import telemetry
from smartops.telemetry import configure_telemetry, round_span
from smartops.tools.registry import mcp_clients

_ENTITY_KINDS = get_args(EntityKind)


def _parse_entity(raw: str) -> Entity:
    """Parse a `kind:value` argument.

    Splits on the *first* colon only, so values containing colons -- IPv6
    addresses, URLs -- survive intact.
    """
    kind, separator, value = raw.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError(
            f"entity {raw!r} must be in kind:value form, e.g. ip:10.2.4.9 or host:web01"
        )
    if kind not in _ENTITY_KINDS:
        raise argparse.ArgumentTypeError(
            f"unknown entity kind {kind!r} -- expected one of {', '.join(sorted(_ENTITY_KINDS))}"
        )
    if not value.strip():
        raise argparse.ArgumentTypeError(f"entity {raw!r} has an empty value")
    return Entity(kind=kind, value=value)


def _parse_instant(raw: str) -> datetime:
    """Parse an ISO 8601 instant, treating a naive value as UTC.

    `Scope` requires timezone-aware datetimes, so a naive string would otherwise
    fail validation with a message about tzinfo rather than about the argument.
    `Z` is accepted because it is what people paste, and `fromisoformat` only
    learned it in 3.11.
    """
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{raw!r} is not an ISO 8601 instant (e.g. 2018-08-20T00:00:00Z): {exc}"
        ) from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _resolve_window(args) -> tuple[datetime, datetime]:
    """The investigation's time window, from either absolute or relative args.

    `--since` wins over `--hours` because it is the more specific statement. With
    only `--since`, the window runs forward by `--hours` rather than to `now`:
    for historical data "from 2018-08-20 for 24 hours" is almost always what is
    meant, and running to now would sweep eight years of empty index.
    """
    now = datetime.now(UTC)
    span = timedelta(hours=args.hours)

    if args.since is not None:
        return args.since, args.until if args.until is not None else args.since + span
    end = args.until if args.until is not None else now
    return end - span, end


def _load_task_file(path: str, task_ids: list[str] | None) -> list[tuple[AnalystTask, str]]:
    """Read a task file and return its `(task, hypothesis)` pairs in file order.

    Every error is raised as a `ValueError` naming the path, because all three
    failure modes here look identical to an operator holding a file that "doesn't
    work" -- unreadable, not JSON, or well-formed JSON that is not a task file --
    and the distinction is exactly what they need to know.

    The hypothesis returned for each task is its `question`. That is the same
    string as `AnalystTask.goal`, and both destinations are deliberate: as `goal`
    it tells the Broker and its subagents what to retrieve, and as the hypothesis
    it is recorded on `HypothesisFindings` as the claim the analysts formed their
    judgements *without* seeing. It is returned separately rather than read back
    off the task at the point of use, so that the analysis call site keeps taking
    the hypothesis as its own argument and cannot quietly start sourcing it from
    the task object -- see `_analyse_one`.
    """
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not read task file {path!r}: {exc}") from exc
    try:
        parsed = TaskInputFile.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"{path!r} is not a valid task file: {exc}") from exc

    selected = parsed.select(task_ids)
    return [(task.to_analyst_task(), task.question) for task in selected]


def _tasks_from_args(args) -> list[tuple[AnalystTask, str | None]]:
    """Every task to investigate, from whichever input mode was used.

    Returns `(task, hypothesis)` pairs so that the rest of the CLI has one shape
    to handle: the flag path is a list of one, and its hypothesis is optional
    because `--hypothesis` always was. A task file's hypothesis is never None --
    `TaskInput.question` is required by the contract -- which is why file input
    runs the analysis tier unconditionally.

    Refuses the two input modes together rather than picking a winner. A run
    given both a file and a `--goal` has been asked for two different
    investigations, and silently honouring one of them is how someone spends a
    live run on the task they did not mean.
    """
    flag_args = {
        "--goal": args.goal,
        "--entity": args.entities,
        "--hypothesis": args.hypothesis,
        "--since": args.since,
        "--until": args.until,
    }
    supplied = sorted(name for name, value in flag_args.items() if value is not None)

    if args.task_file:
        if supplied:
            raise ValueError(
                f"--task-file cannot be combined with {', '.join(supplied)} -- the file "
                "already carries the goal, hypothesis, entities and time window for "
                "every task. Drop the flags, or drop --task-file and pass the whole "
                "task on the command line"
            )
        return _load_task_file(args.task_file, args.task_ids)

    if args.task_ids:
        raise ValueError("--task-id selects a task from --task-file, which was not given")
    if not args.goal and not args.entities:
        raise ValueError(
            "nothing to investigate -- pass either --task-file PATH (a task file from "
            "the Analyst side) or both --goal and at least one --entity KIND:VALUE"
        )
    # Named separately from the nothing-at-all case above: someone who supplied
    # one of the pair has chosen the flag path and needs to know which half is
    # missing, not to be told again that there are two input modes.
    if not args.goal:
        raise ValueError("--goal is required when not using --task-file")
    if not args.entities:
        raise ValueError(
            "at least one --entity KIND:VALUE is required when not using --task-file"
        )

    # `_resolve_window` reads `--hours` too, so the window is always resolvable
    # here even with neither --since nor --until.
    try:
        scope = Scope(entities=args.entities, time_window=_resolve_window(args))
    except ValidationError as exc:
        # Most likely `--hours 0`, or `--until` at or before `--since`, either of
        # which makes start >= end. Re-raised as a ValueError so that every way
        # of failing to produce a task list reaches the caller as one type.
        raise ValueError(f"invalid scope: {exc.errors()[0]['msg']}") from exc
    now = datetime.now(UTC)
    return [(
        AnalystTask(
            task_id=f"cli-{now:%Y%m%dT%H%M%S}",
            # The stub the task file replaces. Kept for the flag path, which has
            # nowhere else to get one: a hypothesis id is the join key between a
            # task and the findings produced for it, and inventing a literal is
            # honest only because this path has no upstream Analyst to supply it.
            hypothesis_id="cli-hypothesis",
            goal=args.goal,
            scope=scope,
        ),
        args.hypothesis,
    )]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smartops-broker",
        description="Run the Task Broker over one investigative task.",
        epilog=(
            "A real model runs whenever a provider is configured (see "
            "model_choices_from_env()); --families only drives the scripted path "
            "(--scripted, or no provider configured) -- on the model path the "
            "tool gate decides what's available instead. Splunk is configured, "
            "so siem dispatches return real rows."
        ),
    )
    parser.add_argument(
        "--task-file",
        default=None,
        metavar="PATH",
        help=(
            "path to a JSON task file from the Analyst side (contracts.TaskInputFile: "
            '{"tasks": [{task_id, hypothesis_id, question, entity, time_window}, ...]}). '
            "Each task is investigated in turn and every one carries its own hypothesis, "
            "so --goal/--hypothesis/--entity/--since are neither needed nor accepted with it"
        ),
    )
    parser.add_argument(
        "--task-id",
        action="append",
        dest="task_ids",
        default=None,
        metavar="ID",
        help=(
            "run only this task from --task-file, repeatable. Selected tasks are "
            "always reported in file order. Useful for proving a task file end to "
            "end on one hypothesis before paying for all of them"
        ),
    )
    parser.add_argument(
        "--batch-id",
        default=None,
        metavar="ID",
        help=(
            "name for the batch payload directory (<runs>/<ID>/analyst-payload.json) "
            "written for --task-file runs. Defaults to batch-<timestamp>; a caller "
            "that needs to find the payload again passes its own id"
        ),
    )
    # Not `required=True` any more: a task file supplies both, and argparse
    # cannot express "required unless --task-file". `_tasks_from_args()` enforces
    # exactly-one-of, and names both forms when neither is given -- which is a
    # better message than argparse's for a CLI that now has two input modes.
    parser.add_argument("--goal", help="what to find out, in plain language (without --task-file)")
    parser.add_argument(
        "--hypothesis",
        default=None,
        metavar="TEXT",
        help=(
            "the hypothesis to test, in plain language. When given AND "
            "SMARTOPS_ANALYST_MODEL_ARN is configured, the identity/network/endpoint "
            "subagent-analysts translate the fetched evidence into a plain-English "
            "narrative with cited observations. They are never shown this hypothesis "
            "and take no position on it -- whether the evidence supports or refutes "
            "it is the upstream Analyst agent's call. Stub for that agent"
        ),
    )
    parser.add_argument(
        "--entity",
        action="append",
        dest="entities",
        type=_parse_entity,
        metavar="KIND:VALUE",
        help=(
            "an observable in scope, repeatable (without --task-file). KIND is one of: "
            f"{', '.join(sorted(_ENTITY_KINDS))}"
        ),
    )
    parser.add_argument(
        "--hours", type=int, default=24, help="how far back the time window reaches (default: 24)"
    )
    parser.add_argument(
        "--since",
        type=_parse_instant,
        metavar="ISO8601",
        help=(
            "absolute window start, e.g. 2018-08-20T00:00:00Z (naive values are read as UTC). "
            "Overrides --hours. Needed for any dataset that is not recent: a relative window "
            "over historical data returns nothing and looks exactly like an empty domain"
        ),
    )
    parser.add_argument(
        "--until",
        type=_parse_instant,
        metavar="ISO8601",
        help="absolute window end (default: now, or --since plus --hours when --since is given)",
    )
    parser.add_argument(
        "--families",
        default=None,
        help=(
            f"comma-separated families to dispatch, --scripted only (default: the "
            f"configured ones among {','.join(ALL_FAMILIES)}). On the model path this "
            "does nothing -- the tool gate (available_broker_tools()) decides what is "
            "available instead"
        ),
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help=(
            f"investigation budget in USD. Default: ${DEFAULT_BUDGET_USD_PER_TASK:.2f} per "
            "task, so a 3-task file gets $30.00. Passed explicitly, the value is a "
            "ceiling for the WHOLE run however many tasks it holds"
        ),
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help=(
            f"hard ceiling on total output tokens. Default: "
            f"{DEFAULT_MAX_OUTPUT_TOKENS_PER_TASK} per task; passed explicitly, it "
            "covers the whole run"
        ),
    )
    parser.add_argument(
        # The Broker's cumulative output-token ceiling for one run. Unset, it follows
        # the planner's effort (`budget.loop_output_tokens`, K4), else 16000: the
        # library default (4000) ran out on Sonnet 4.6 while authoring the fetch
        # plan, before a single dispatch.
        "--broker-output-tokens",
        type=int,
        default=None,
        help="cumulative output-token ceiling for the Broker's run "
        "(default: turns x the planner effort's allowance, else 16000)",
    )
    parser.add_argument(
        "--subagent-turns",
        type=int,
        default=25,
        help="turn ceiling for domain subagents (default: 25)",
    )
    parser.add_argument(
        "--mcp-config",
        default=None,
        metavar="PATH",
        help=(
            "path to an mcpServers JSON config (default: $SMARTOPS_MCP_CONFIG, "
            "else mcp_servers.json in the working directory, else no MCP servers)"
        ),
    )
    parser.add_argument(
        "--scripted",
        action="store_true",
        help=(
            "force the scripted invoker even when a provider is configured, so "
            "--families drives dispatch and NO MODEL is called. Note this governs "
            "the model only -- domain lookups still run, so a configured VT_API_KEY "
            "means real VirusTotal requests"
        ),
    )
    parser.add_argument(
        "--skills",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable the reference skill pack (superman-splunk) for siem (default: $SMARTOPS_SKILLS_ENABLED)",
    )
    parser.add_argument(
        "--console-traces",
        action="store_true",
        help="export OpenTelemetry spans to stdout (off by default: spans can carry SOC data)",
    )
    parser.add_argument("--verbose", action="store_true", help="show INFO/WARNING logs")
    return parser



def _neutralise_aws_profile() -> str | None:
    """Drop `AWS_PROFILE` when explicit credentials make it irrelevant.

    Returns the value dropped, or `None`. Call AFTER `_load_env_file()` so that
    credentials from `.env` count, and before anything constructs a boto3 client.

    **Why this is code and not a note in the README.** It was a note in the
    README -- three of them, across the handovers: "clear any shell `AWS_PROFILE`
    before a live probe". A workaround documented three times is a defect with
    good manners. The failure it prevents is also badly disguised: an unusable
    profile surfaces as `The config profile (...) could not be found` from deep
    inside botocore, at model-construction time, which reads as "your Bedrock
    setup is wrong" rather than "an unrelated shell variable is set".

    Two cases, both unambiguous:

    - **Empty.** `AWS_PROFILE=""` is what `env AWS_PROFILE= ...` produces, and
      botocore takes it literally -- it looks for a profile *named* empty string
      and fails. An empty profile name is never valid, so it can only mean unset.
    - **Set, with explicit keys also present.** `AWS_ACCESS_KEY_ID` +
      `AWS_SECRET_ACCESS_KEY` in the environment are a direct statement of which
      credentials to use. A profile named alongside them is the ambient leftover,
      not the intent -- and it does not merely lose the race, it can break the run
      outright, because botocore resolves the profile for *config* before it ever
      reaches the credential chain the keys would win.

    Logged at WARNING, never silent: overriding an operator's environment
    variable without saying so is its own confusing failure.
    """
    profile = os.environ.get(AWS_PROFILE_ENV_VAR)
    if profile is None:
        return None

    if not profile.strip():
        del os.environ[AWS_PROFILE_ENV_VAR]
        logging.getLogger(__name__).warning(
            "%s was set to an empty value and has been unset -- botocore reads "
            "that as a profile literally named '', which never exists",
            AWS_PROFILE_ENV_VAR,
        )
        return profile

    has_explicit_keys = all(
        os.environ.get(name, "").strip()
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    )
    if not has_explicit_keys:
        # Nothing else to authenticate with, so the profile is the intent.
        return None

    del os.environ[AWS_PROFILE_ENV_VAR]
    logging.getLogger(__name__).warning(
        "%s=%s ignored: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are set and are "
        "what this run will authenticate with. Unset the keys if you meant to use "
        "the profile.",
        AWS_PROFILE_ENV_VAR,
        profile,
    )
    return profile


def _load_env_file() -> str | None:
    """Load `.env` into the environment, if there is one. Returns its path.

    Every setting in this project is read from `os.environ`, so without this a
    `.env` file is inert and `cp .env.example .env` -- what the template tells
    you to do -- would appear to do nothing.

    `override=False` on purpose: a variable already set in the shell, CI, or a
    container's environment wins over the file. A stale local `.env` silently
    overriding a deployment's real credentials is the worse failure.

    Searches upward from the working directory, so it works whether you run from
    the repo root or from `backend/`.
    """
    from dotenv import find_dotenv, load_dotenv

    path = find_dotenv(usecwd=True)
    if not path:
        return None
    load_dotenv(path, override=False)
    return path


def _force_utf8_output() -> None:
    """Make stdout/stderr able to carry any answer a model produces.

    Windows consoles default to cp1252, which cannot encode a great deal of what
    an LLM writes -- arrows, dashes, box drawing. Printing such an answer raised
    `UnicodeEncodeError` from `_print_outcome`, *after* the investigation had run
    and been billed: the work succeeded and the report threw it away, with a
    stack trace instead of findings.

    `errors="replace"` as well as UTF-8, because a terminal that still cannot
    represent a character must degrade it to `?` rather than lose the report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                # A redirected or already-detached stream. Not worth failing the
                # run over -- worst case we are back to the old behaviour.
                logging.getLogger(__name__).debug("could not reconfigure %r", stream)



async def _run(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    args = _build_parser().parse_args(argv)

    # Before anything reads os.environ.
    env_file = _load_env_file()

    configure_logging(args.verbose)
    # After logging is configured, so its warning is visible, and after the .env
    # load, so credentials from the file count as explicit.
    _neutralise_aws_profile()
    configure_telemetry(console=args.console_traces)
    with round_span(args.batch_id):
        return await _run_round(args, env_file)


def configure_logging(verbose: bool = False) -> None:
    """The engine's log format and levels, for the CLI and the server alike."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.ERROR,
        format="%(levelname)s %(name)s: %(task)s%(message)s",
    )
    for handler in logging.getLogger().handlers:
        handler.addFilter(_name_the_task)
    if not verbose:
        # The analyst gates log every sentence, figure and domain they drop as a
        # warning; at ERROR the run's log never showed what the Analyst lost (N3).
        # `contracts` too: its packer's over-budget warning was invisible (O6).
        logging.getLogger("smartops.subagent_analysts").setLevel(logging.WARNING)
        logging.getLogger("contracts").setLevel(logging.WARNING)



async def _run_round(args: argparse.Namespace, env_file) -> int:
    try:
        await start(args.mcp_config)
    except Exception as exc:
        # A malformed config is a deployment error, distinct from an absent one.
        print(f"error: could not load MCP config: {exc}", file=sys.stderr)
        return 2
    if args.verbose:
        # Which file supplied the settings is the first thing you want when a
        # credential "isn't being picked up".
        print(f"env file:    {env_file or '(none found)'}")
        print(f"mcp servers: {len(mcp_clients())} built")

    try:
        result = await run_round(_tasks_from_args(args), args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1 if result.failures else 0



# ── The API server: uvicorn smartops.main:app ────────────────────────────────
from contextlib import asynccontextmanager  # noqa: E402
from queue import Empty, Queue  # noqa: E402
import threading  # noqa: E402
import uuid  # noqa: E402

from fastapi import FastAPI, Response  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from smartops import analyst, context  # noqa: E402

REPO = Path(__file__).resolve().parents[3]


@asynccontextmanager
async def lifespan(app):
    # Once per server, not per round: settings, logging, and the Broker's MCP
    # clients, built and warmed here.
    _load_env_file()
    telemetry.route_output()
    configure_logging()
    _neutralise_aws_profile()
    configure_telemetry()
    await start(str(REPO / "mcp_servers.json"))
    yield


app = FastAPI(title="SmartOps SOC", lifespan=lifespan)

# The React frontend (frontend/, `npm run build`).
FRONTEND_DIST = REPO / "frontend" / "dist"
if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/favicon.svg")
def favicon():
    return FileResponse(FRONTEND_DIST / "favicon.svg")


@app.get("/")
def index():
    if not (FRONTEND_DIST / "index.html").is_file():
        return JSONResponse({"status": "error", "message": "frontend not built: npm run build in frontend/"}, 404)
    resp = FileResponse(FRONTEND_DIST / "index.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


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


# ── Runs: one investigation per run, streamed over SSE ───────────────────────
_run_queues: dict[str, Queue] = {}


class RunRequest(BaseModel):
    alert_name: str = "Potential Cryptomining Activity Detected"
    host: str = "BSTOLL-L"
    domain: str = "coinhive.com"
    event_time: str = "2018-08-20T12:00:00Z"
    max_loops: int = 15  # headroom to finish; older rounds are compacted (analyst.FULL_ROUNDS)
    context_contract: dict = None


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


# Run control: stop, pause, resume. Pause and stop land at the next stage boundary
# (_checkpoint): a model call in flight cannot be interrupted. Stop also cancels a
# running broker round at once.
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


def run() -> None:
    """Console-script entry point."""
    raise SystemExit(asyncio.run(_run()))


if __name__ == "__main__":
    run()
