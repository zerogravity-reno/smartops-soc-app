"""Offline Replay Harness for SmartOps SOC App.

Replays recorded tool calls and evidence logs (from
`.smartops/runs/<task_id>/<stamp>/evidence.json` or `_EvidenceCollector`) offline
without live network or Splunk MCP calls.

Enables zero-cost, zero-latency prompt tuning, offline evaluation, and regression testing.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, get_args

from strands import tool

from contracts import Evidence, SubagentMission, SubtaskResult, ToolFamily, answer_tool_name
from smartops.broker import DEFAULT_RUNS_DIR, RUNS_DIR_ENV_VAR, SubagentRunner
from smartops.budget import Budget, ModelChoice
from smartops.subagents import (
    DEFAULT_MAX_OUTPUT_TOKENS as _SUBAGENT_OUTPUT_TOKENS,
)
from smartops.subagents import (
    DEFAULT_TURNS as _SUBAGENT_TURNS,
)

logger = logging.getLogger(__name__)

_ANSWER_TOOL_NAMES = frozenset(answer_tool_name(family) for family in get_args(ToolFamily))
"""The structured-output tool names, derived rather than listed.

`answer_tool_name()` is the one formula for these (Strands derives the tool name
from the answer model's `__name__`), and `_EvidenceCollector` already skips them
at capture time by comparing against it. Deriving here too means the read-side
filter cannot drift out of step with the write-side skip -- two hand-written
copies of "SiemAnswer", "VtAnswer", ... is exactly how that drift starts.
"""


def is_model_authored(tool_name: Any) -> bool:
    """Whether a recorded call is the model's own structured answer, not a tool result.

    Strands implements `structured_output_model` as a tool, so the model's answer
    arrives at `AfterToolCallEvent` indistinguishable in shape from a real tool
    result. `_EvidenceCollector` skips it at capture now, but 22 of the 26 runs
    saved under `.smartops/runs/` predate that skip and hold 60 such records
    between them -- so the read side has to know them too.
    """
    return tool_name in _ANSWER_TOOL_NAMES


def load_evidence_from_file(
    path: Path | str, *, include_model_answers: bool = False
) -> list[Evidence]:
    """Load captured evidence records from a JSON file (e.g. `evidence.json`).

    **Model-authored answers are filtered out by default.** `contracts.Evidence`
    is raw tool output, assembled by code and never authored by a model, and
    `_EvidenceCollector` enforces that at capture time -- but only since the
    `answer_tool` skip landed. 22 of the 26 runs on disk predate it and hold 60
    `SiemAnswer`/`VtAnswer` records between them, and they do not sit there
    harmlessly: `ReplayToolset` indexes by tool name, so
    `get_replay_tools_for_family` minted a replay tool literally called
    `VtAnswer` that handed a subagent the model's own prior answer as though a
    tool had returned it, and `evidence_by_id()` would resolve a citation to the
    model quoting itself.

    **Filtered on read, never deleted from the artifact**, and that is the whole
    design. `evidence_id()` is `f"{task_id}:{index}"`, so removing a record from
    `evidence.json` renumbers every record after it and silently re-targets every
    stored citation -- the precise failure the evidence-link contract exists to
    prevent. Ids travel inside each record and are never recomputed from
    position, so dropping one on read re-targets nothing.

    Pass `include_model_answers=True` for a forensic read of exactly what is on
    disk. Nothing in the analysis or replay path should.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    raw_data = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(raw_data, list):
        raise ValueError(f"Expected evidence file to contain a list, got {type(raw_data).__name__}")

    evidence_items: list[Evidence] = []
    skipped: list[str] = []
    for item in raw_data:
        if not isinstance(item, dict):
            continue
        record = Evidence.model_validate(item)
        raw = record.raw if isinstance(record.raw, dict) else {}
        if not include_model_answers and is_model_authored(raw.get("tool")):
            skipped.append(record.id)
            continue
        evidence_items.append(record)

    if skipped:
        # Named, not silent: this is a property of the artifact, and an operator
        # comparing a record count against `report.json` needs to know why they
        # differ.
        logger.warning(
            "%s | dropped %d model-authored answer record(s) on read, not evidence: %s",
            file_path,
            len(skipped),
            ", ".join(skipped),
        )
    return evidence_items


def load_evidence_from_run(
    run_id_or_path: Path | str, base_dir: Path | str | None = None
) -> list[Evidence]:
    """Load evidence for one run, given a case id, a `<case>/<stamp>` pair, or a path.

    `save_run_artifacts()` writes `<base>/<task_id>/<stamp>/evidence.json` and a
    sibling `latest.txt` naming the newest stamp -- one directory per run, so
    that a second run of a case stops overwriting the first. A bare case id
    therefore names a directory of runs, not a run, and is resolved here:
    `latest.txt` if it is there, otherwise the highest stamp, which sorts
    correctly because the stamps are zero-padded `%Y%m%dT%H%M%S%f`.

    `base_dir` defaults through `$SMARTOPS_RUNS_DIR` exactly as the writer does.
    Hardcoding `.smartops/runs` here meant that with that variable set, the
    reader and the writer looked in different trees.
    """
    if base_dir is None:
        base_dir = os.environ.get(RUNS_DIR_ENV_VAR, "").strip() or DEFAULT_RUNS_DIR

    path = Path(run_id_or_path)
    if not path.is_absolute() and not path.exists():
        path = Path(base_dir) / run_id_or_path

    if path.is_dir() and not (path / "evidence.json").is_file():
        path = _newest_run_in(path)

    if path.is_dir():
        path = path / "evidence.json"

    return load_evidence_from_file(path)


def evidence_by_id(
    run_id_or_path: Path | str, base_dir: Path | str | None = None
) -> dict[str, Evidence]:
    """One run's evidence keyed by `Evidence.id`, for resolving a citation.

    `load_evidence_from_run` returns a list, so every consumer wanting the rows
    behind one `ResultSet.evidence_id` or `Exhibit.evidence_ids` entry scanned it
    itself. Those ids are the whole point of the link contract
    (`docs/superpowers/specs/2026-08-25-evidence-link-contract-design.md`) and
    the store had no way to answer one directly.

    A later record wins on a duplicate id. `SubtaskResult` already forbids
    duplicates within one result (`_evidence_ids_are_unique`) and `evidence_id()`
    namespaces by mission `task_id`, so a collision across a run means two
    missions shared a `toolUseId` -- worth logging, not worth raising over, since
    the caller wants the rows for the one id it asked about.
    """
    by_id: dict[str, Evidence] = {}
    for item in load_evidence_from_run(run_id_or_path, base_dir):
        if item.id in by_id:
            logger.warning(
                "evidence id %s appears more than once in %s; keeping the later record",
                item.id,
                run_id_or_path,
            )
        by_id[item.id] = item
    return by_id


def _newest_run_in(case_dir: Path) -> Path:
    """The most recent run directory under a case directory."""
    latest = case_dir / "latest.txt"
    if latest.is_file():
        stamp = latest.read_text(encoding="utf-8").strip()
        if stamp and (case_dir / stamp).is_dir():
            return case_dir / stamp

    stamps = sorted(d for d in case_dir.iterdir() if d.is_dir())
    if not stamps:
        raise FileNotFoundError(
            f"No runs recorded under {case_dir}: it holds no run directory. "
            "Run the case first, or name a run directory directly."
        )
    return stamps[-1]


def _normalize_query(query: str | None) -> str:
    """Normalize SPL or query strings for matching by removing redundant whitespace and case differences."""
    if not query:
        return ""
    # Normalize internal whitespace
    cleaned = re.sub(r"\s+", " ", query.strip().lower())
    return cleaned


def _extract_query_from_kwargs(kwargs: dict[str, Any]) -> str | None:
    """Extract search query string from tool kwargs."""
    for key in ("query", "search", "spl", "domain", "ip", "hash", "url", "indicator"):
        if key in kwargs and isinstance(kwargs[key], str):
            return kwargs[key]
    for val in kwargs.values():
        if isinstance(val, str) and ("index=" in val.lower() or "search " in val.lower()):
            return val
    return None


class ReplayToolset:
    """Indexed cache of captured tool outputs supporting exact and fuzzy offline matching."""

    def __init__(self, evidence: Sequence[Evidence] | Any = ()) -> None:
        self.records: list[dict[str, Any]] = []

        if hasattr(evidence, "calls"):
            # Captured from _EvidenceCollector
            for call in getattr(evidence, "calls", []):
                self.records.append({
                    "tool": getattr(call, "tool", "unknown"),
                    "query": getattr(call, "query", None),
                    "result": getattr(call, "payload", None),
                })
        elif isinstance(evidence, (list, tuple)):
            for item in evidence:
                if isinstance(item, Evidence):
                    raw = item.raw or {}
                    self.records.append({
                        "tool": raw.get("tool", "unknown"),
                        "query": raw.get("query"),
                        "result": raw.get("result"),
                        "family": item.tool_family,
                    })
                elif isinstance(item, dict):
                    self.records.append(item)

        # Filtered here as well as in `load_evidence_from_file`, and the two are
        # not redundant: they guard different doors. The loader covers everything
        # read off disk; this covers a caller that built the toolset from raw
        # dicts or from a collector, which never touches the loader at all. It
        # matters most for THIS class, because `get_replay_tools_for_family` mints one
        # replay tool per recorded tool name -- so an unfiltered `VtAnswer`
        # record does not merely sit in the index, it becomes a tool a replayed
        # subagent can call and be handed the model's own prior answer. One
        # shared predicate rather than two copies of the name list.
        answers = [r for r in self.records if is_model_authored(r.get("tool"))]
        if answers:
            logger.warning(
                "dropped %d model-authored answer record(s) from the replay index, "
                "not tool output: %s",
                len(answers),
                ", ".join(sorted({str(r.get("tool")) for r in answers})),
            )
            self.records = [r for r in self.records if not is_model_authored(r.get("tool"))]

    def match(self, tool_name: str, query: str | None = None, **kwargs: Any) -> Any:
        """Find the best recorded tool result for a given tool name and query/args.

        Returns recorded result payload if matched, or a fallback cache miss payload.
        """
        if not query:
            query = _extract_query_from_kwargs(kwargs)

        norm_query = _normalize_query(query)
        clean_tool = tool_name.lower().split("__")[-1]  # strip MCP prefix if present

        # 1. Exact match on tool name and normalized query
        for rec in self.records:
            rec_tool = str(rec.get("tool", "")).lower().split("__")[-1]
            rec_query = _normalize_query(rec.get("query"))
            if rec_tool == clean_tool and norm_query and rec_query == norm_query:
                logger.info("Replay exact match for tool=%s query=%s", tool_name, query)
                return rec.get("result")

        # 2. Fuzzy match on tool name and query containment
        for rec in self.records:
            rec_tool = str(rec.get("tool", "")).lower().split("__")[-1]
            rec_query = _normalize_query(rec.get("query"))
            if rec_tool == clean_tool and norm_query and rec_query and (norm_query in rec_query or rec_query in norm_query):
                logger.info("Replay fuzzy match for tool=%s query=%s", tool_name, query)
                return rec.get("result")

        # 3. Match on tool name alone if only one recorded for tool
        tool_matches = [
            rec for rec in self.records
            if str(rec.get("tool", "")).lower().split("__")[-1] == clean_tool
        ]
        if tool_matches:
            logger.info("Replay tool-only match for tool=%s (selected first of %d)", tool_name, len(tool_matches))
            return tool_matches[0].get("result")

        # 4. Cache miss fallback
        logger.warning("Replay cache miss for tool=%s query=%s", tool_name, query)
        return {
            "status": "no_data",
            "message": f"Offline replay cache miss: no recorded result for tool '{tool_name}' with query '{query}'",
            "replay": True,
        }


def make_replay_tool(
    name: str,
    description: str,
    replayer: ReplayToolset,
) -> Any:
    """Construct an offline `@tool` wrapper that replays recorded tool outputs."""

    @tool(name=name, description=description)
    async def replayed_tool(**kwargs: Any) -> Any:
        query = _extract_query_from_kwargs(kwargs)
        extra_kwargs = {k: v for k, v in kwargs.items() if k != "query"}
        return replayer.match(name, query=query, **extra_kwargs)

    return replayed_tool


def get_replay_tools_for_family(family: ToolFamily | str, replayer: ReplayToolset) -> list:
    """Build a list of replayed `@tool` functions for a specific domain family from recorded evidence."""
    tools: list = []

    # Identify tool names recorded for this family
    recorded_tools: set[str] = set()
    for rec in replayer.records:
        rec_family = rec.get("family")
        rec_tool = rec.get("tool")
        if rec_tool and (rec_family is None or rec_family == family):
            recorded_tools.add(rec_tool)

    if not recorded_tools:
        # Standard tool names fallback
        if family == "siem":
            recorded_tools.add("splunk__splunk_search")
        elif family == "vt":
            recorded_tools.add("vt_lookup_domain")

    for tool_name in sorted(recorded_tools):
        desc = f"Offline replayed tool for {family} domain: {tool_name}"
        tools.append(make_replay_tool(tool_name, desc, replayer))

    # Same switch as the routing table, which `investigate` injects into the
    # `siem` system prompt from behind `skills_enabled()`. Attaching the tool
    # unconditionally would have handed a replay the tool with no table telling
    # the model it exists -- half a skill pack, and a silent divergence from the
    # run being replayed. Replay follows the global default like every other
    # caller rather than opting itself in: the recorded evidence carries no note
    # of what the original run's flag was, so a replay-only opt-in would be a
    # different fabrication, not a restoration of fidelity.
    if family == "siem":
        from smartops.skills import read_reference, skills_enabled
        if skills_enabled() and read_reference not in tools:
            tools.append(read_reference)

    return tools


def create_replay_subagent_runner(
    replayer: ReplayToolset,
    *,
    model: ModelChoice,
    budget: Budget,
    turns: int = _SUBAGENT_TURNS,
    max_output_tokens: int = _SUBAGENT_OUTPUT_TOKENS,
) -> SubagentRunner:
    """Create a `SubagentRunner` that executes missions offline using replayed tool calls."""
    from smartops.subagents import investigate

    async def run(mission: SubagentMission) -> SubtaskResult:
        family = mission.tool_family
        tools = get_replay_tools_for_family(family, replayer)

        return await investigate(
            mission,
            model=model,
            budget=budget,
            tools=tools,
            turns=turns,
            max_output_tokens=max_output_tokens,
        )

    return run
