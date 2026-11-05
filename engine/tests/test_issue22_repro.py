"""Issue #22: each reported defect, reproduced offline before it is fixed.

A test here fails on the code the issue was filed against; the fix makes it pass.
"""

from __future__ import annotations

import asyncio

from contracts import DomainFinding, ResultSet, SubagentAnswer, SubtaskStatus

from smartops import subagents
from smartops.budget import Budget
from smartops.subagent_analysts import prompts
from smartops.subagent_analysts.analyze import _check_claims, translator_lines
from smartops.subagent_analysts.routing import DomainSlice
from smartops.subagent_analysts.verify import Verdict
from test_analyst_prompts import _scope
from test_mcp_session_and_result_size import _refused
from test_subagents import MODEL, _Result, mission

# 2.1 -- 1bcbf51c L2 T3/T4/T5/T6: code decodes this and hands it to the translator.
_ENCODED = "powershell.exe -NoProfile -EncodedCommand JABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQA="
DECODED_LINE = "Powershell runs an encoded command that decodes to $env:username [processes#1]"


def _encoded_slice() -> DomainSlice:
    rows = [{"host": "HOST-1", "process": _ENCODED}]
    return DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=1, rows=rows))])


class _SeeAll:
    def __init__(self):
        self.calls = []

    async def __call__(self, claims):
        self.calls.append(claims)
        return [Verdict(index=i, supported=True, reason="") for i in range(len(claims))]


def test_2_1_the_verifier_sees_the_decoded_command_the_translator_was_given():
    slice_ = _encoded_slice()
    assert any("$env:username" in line for line in translator_lines(slice_)), "precondition: code decodes it"
    verifier = _SeeAll()
    finding = DomainFinding(domain="endpoint", observations=[DECODED_LINE], citations=["processes#1"])

    asyncio.run(_check_claims(finding, slice_, None, verifier))

    [(line, evidence)] = verifier.calls[0]
    assert "$env:username" in evidence


def test_2_2_the_citation_footer_names_no_set_the_evidence_may_not_hold():
    # 1bcbf51c invented reputation#1, connections#1 and uncategorised#1, each named here.
    for invented in ("reputation#1", "connections#1", "uncategorised#3"):
        assert invented not in prompts._ANSWER_FOOTER
    turn = prompts.build_facts_user_turn(_scope(), "# processes#1 · rows=1", ids=["processes#1"])
    assert "the only ones you may cite: processes#1" in turn


async def test_3_3_rows_fetched_before_a_missing_answer_are_kept(monkeypatch):
    class _Call:
        tool_use = {"name": "splunk_run_query", "toolUseId": "tu-1", "input": {"query": "search index=x"}}
        result = {"status": "success", "content": [{"text": "{}"}], "structuredContent": {"results": [{"a": 1}]}}
        exception = None

    async def fake(*args, **kwargs):
        kwargs["collector"]._record(_Call())
        return _Result(None)

    monkeypatch.setattr(subagents, "_build_agent_and_invoke", fake)

    result = await subagents.investigate(mission("siem"), model=MODEL, budget=Budget.from_usd(1.0), tools=["t"])

    assert result.status == SubtaskStatus.ERROR
    assert len(result.evidence) == 1


async def test_1_1_a_lost_session_is_retried_and_the_retry_answers(monkeypatch):
    calls = []

    async def fake(*args, **kwargs):
        calls.append(1)
        if len(calls) < 3:
            [watch] = [g for g in kwargs["guards"] if isinstance(g, subagents._SessionWatch)]
            watch._check(_refused())
            return _Result(None)
        return _Result(SubagentAnswer(status=SubtaskStatus.OK))

    async def tools(family):
        return ["t"]

    monkeypatch.setattr(subagents, "_build_agent_and_invoke", fake)
    monkeypatch.setattr(subagents, "tools_for", tools)
    run = subagents.domain_runner(model=MODEL, budget=Budget.from_usd(5.0))

    result = await run(mission("siem"))

    assert len(calls) == 3
    assert result.status != SubtaskStatus.ERROR


async def test_1_1_a_session_that_stays_dead_ends_as_error_after_the_retries(monkeypatch):
    calls = []

    async def fake(*args, **kwargs):
        calls.append(1)
        [watch] = [g for g in kwargs["guards"] if isinstance(g, subagents._SessionWatch)]
        watch._check(_refused())
        return _Result(None)

    async def tools(family):
        return ["t"]

    monkeypatch.setattr(subagents, "_build_agent_and_invoke", fake)
    monkeypatch.setattr(subagents, "tools_for", tools)

    result = await subagents.domain_runner(model=MODEL, budget=Budget.from_usd(5.0))(mission("siem"))

    assert len(calls) == 1 + subagents.SESSION_RETRIES
    assert result.status == SubtaskStatus.ERROR
    assert result.reason.startswith(subagents.SESSION_LOST_REASON)


async def test_2_3_an_mcp_call_that_never_answers_is_bounded_per_call(monkeypatch):
    """4b95662c L2 T1-T3, c9611aa4 L3 FU2: an MCP call that never got a response
    ran until the 900 s mission cap. Strands builds MCP tools with timeout=None,
    so the call itself had no bound."""
    from datetime import timedelta

    from mcp.types import Tool as MCPTool
    from strands.tools.mcp import MCPAgentTool

    from smartops.tools import registry

    seen = {}

    class _Client:
        async def load_tools(self):
            return self.tools

        async def call_tool_async(self, **kwargs):
            seen.update(kwargs)
            return {"status": "success", "toolUseId": "t", "content": []}

    client = _Client()
    client.tools = [MCPAgentTool(MCPTool(name="splunk_run_query", inputSchema={"type": "object"}), client)]
    monkeypatch.setattr(registry, "_clients_by_family", {"siem": [client]})

    (tool,) = await registry.tools_for("siem")
    async for _ in tool.stream({"toolUseId": "t", "name": "splunk_run_query", "input": {}}, {}):
        pass

    assert seen["read_timeout_seconds"] == timedelta(seconds=registry.MCP_CALL_TIMEOUT_SECONDS)
    assert registry.MCP_CALL_TIMEOUT_SECONDS < subagents.MISSION_TIMEOUT_SECONDS
