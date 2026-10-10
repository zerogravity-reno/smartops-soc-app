"""B24 (a dead MCP session ends the step and reconnects) and B27 (result size caps).

Shapes from run `89674d75`: round 5 lost its Splunk session after FU1, every later
call was refused with "the client session is not running" and the round hung;
FU1's script-block step returned rows of ~12 KB each.
"""

import asyncio
import json
import logging

import pytest
import smartops.tools.registry as registry_module
from smartops import subagents
from smartops.budget import Budget
from smartops.guards import RowLimitCap
from smartops.subagents import investigate
from smartops.tools.registry import tools_for

from contracts import SubagentAnswer, SubtaskStatus
from test_subagents import MODEL, _Result, mission

REFUSAL = "the client session is not running. Ensure the agent is used within the MCP client context manager."


class DyingClient:
    """An `MCPClient` whose session ended after it connected.

    Mirrors the SDK: `_tool_provider_started` stays true, `_is_session_active()`
    goes false, and `stop()` resets state and then raises `RuntimeError` from what
    killed the session (`mcp_client.py:563-566`).
    """

    def __init__(self):
        self._tool_provider_started = True
        self.alive = False
        self.stops = 0
        self.consumers: set = set()

    def _is_session_active(self):
        return self.alive

    def stop(self, exc_type=None, exc_val=None, exc_tb=None):
        self.stops += 1
        self._tool_provider_started = False
        self.consumers = set()
        raise RuntimeError("Connection to the MCP server was closed") from ConnectionError("reply size")

    def add_consumer(self, consumer_id, **kwargs):
        self.consumers.add(consumer_id)

    async def load_tools(self):
        self._tool_provider_started = True
        self.alive = True
        return ["splunk_run_query"]


@pytest.fixture(autouse=True)
def _clean_registry(monkeypatch):
    monkeypatch.setattr(registry_module, "_clients_by_family", {})
    registry_module._resolve_locks.clear()
    yield
    registry_module._resolve_locks.clear()


class TestADeadSessionIsReconnected:
    async def test_the_next_step_resets_the_client_and_gets_tools(self, monkeypatch, caplog):
        client = DyingClient()
        monkeypatch.setattr(registry_module, "_clients_by_family", {"siem": [client]})

        with caplog.at_level(logging.WARNING, logger="smartops.tools.registry"):
            tools = await tools_for("siem")

        assert tools == ["splunk_run_query"]
        assert client.stops == 1
        assert registry_module.PROCESS_CONSUMER in client.consumers  # re-claimed despite stop() raising
        assert "reply size" in caplog.text  # the cause Strands logs only at DEBUG

    async def test_a_live_session_is_not_reset(self, monkeypatch):
        client = DyingClient()
        client.alive = True
        monkeypatch.setattr(registry_module, "_clients_by_family", {"siem": [client]})

        await tools_for("siem")

        assert client.stops == 0


class _AfterCall:
    def __init__(self, result, exception=None):
        self.tool_use = {"name": "splunk_run_query", "toolUseId": "tu-1", "input": {}}
        self.result = result
        self.exception = exception


class _AfterTools:
    end_turn: bool | str = False


def _refused():
    return _AfterCall(
        {"status": "error", "toolUseId": "tu-1", "content": [{"text": f"Error: {REFUSAL}"}]},
        exception=RuntimeError(REFUSAL),
    )


class TestARefusedCallEndsTheStep:
    def test_the_batch_after_a_refusal_ends_the_loop(self):
        watch = subagents._SessionWatch()
        watch._check(_refused())
        after = _AfterTools()

        watch._halt(after)

        assert watch.refused == 1
        assert after.end_turn

    def test_an_ordinary_error_does_not(self):
        watch = subagents._SessionWatch()
        watch._check(_AfterCall({"status": "error", "content": [{"text": "Error: bad SPL"}]}))
        after = _AfterTools()

        watch._halt(after)

        assert not after.end_turn

    async def test_an_answer_after_a_refusal_is_reported_as_error(self, monkeypatch):
        async def fake(*args, **kwargs):
            [watch] = [g for g in kwargs["guards"] if isinstance(g, subagents._SessionWatch)]
            watch._check(_refused())
            return _Result(SubagentAnswer(status=SubtaskStatus.OK))

        monkeypatch.setattr(subagents, "_build_agent_and_invoke", fake)

        result = await investigate(mission("siem"), model=MODEL, budget=Budget.from_usd(1.0), tools=["t"])

        assert result.status == SubtaskStatus.ERROR
        assert "MCP session lost" in result.reason


class TestAStuckStepTimesOut:
    async def test_a_hung_call_ends_as_error_and_releases_the_budget(self, monkeypatch):
        async def hang(*args, **kwargs):
            await asyncio.Event().wait()

        monkeypatch.setattr(subagents, "_build_agent_and_invoke", hang)
        monkeypatch.setattr(subagents, "MISSION_TIMEOUT_SECONDS", 0.05)
        budget = Budget.from_usd(1.0)
        before = budget.remaining

        result = await investigate(mission("siem"), model=MODEL, budget=budget, tools=["t"])

        assert result.status == SubtaskStatus.ERROR
        assert "timed out" in result.reason
        assert budget.remaining == before


class _Tool:
    def __init__(self, *params):
        self.tool_spec = {"inputSchema": {"json": {"properties": {p: {} for p in params}}}}


class _BeforeCall:
    def __init__(self, tool, tool_input):
        self.selected_tool = tool
        self.tool_use = {"name": "splunk_run_query", "toolUseId": "tu-1", "input": tool_input}


class TestRowLimitCap:
    @pytest.mark.parametrize(("asked", "sent"), [(200, 100), (50, 50), (None, 100), ("x", 100), (0, 1)])
    def test_row_limit_is_capped_at_the_tool_default(self, asked, sent):
        args = {"query": "index=windows_lab EventCode=4104"}
        if asked is not None:
            args["row_limit"] = asked
        RowLimitCap("siem")._cap(_BeforeCall(_Tool("query", "row_limit"), args))
        assert args["row_limit"] == sent

    def test_a_tool_without_row_limit_is_left_alone(self):
        args = {"query": "x"}
        RowLimitCap("siem")._cap(_BeforeCall(_Tool("query"), args))
        assert args == {"query": "x"}


class TestCellCap:
    def test_a_long_cell_is_cut_and_the_text_copy_still_parses(self):
        script = "A" * 12_000
        structured = {"results": [{"ScriptBlockText": script, "EventCode": "4104"}], "truncated": False}
        payload = {"status": "success", "content": [{"text": json.dumps(structured)}], "structuredContent": structured}

        capped = subagents._capped(payload)

        cell = capped["structuredContent"]["results"][0]["ScriptBlockText"]
        assert cell.startswith("A" * subagents.CELL_CHAR_CAP)
        assert cell.endswith(f"[+{12_000 - subagents.CELL_CHAR_CAP} chars]")
        assert json.loads(capped["content"][0]["text"]) == capped["structuredContent"]
        assert capped["structuredContent"]["results"][0]["EventCode"] == "4104"

    def test_a_command_line_at_the_windows_limit_survives_whole(self):
        command = "powershell.exe -EncodedCommand " + "J" * 8_160
        assert len(command) <= 8_191
        payload = {"content": [], "structuredContent": {"results": [{"CommandLine": command}]}}

        assert subagents._capped(payload)["structuredContent"]["results"][0]["CommandLine"] == command

    def test_a_text_only_result_passes_through(self):
        payload = {"status": "success", "content": [{"text": "x" * 20_000}]}
        assert subagents._capped(payload) is payload
