"""The Broker's decoder tool: encoded PowerShell in a dispatched step's rows (B10)."""

from types import SimpleNamespace

from contracts import FetchStep, ResultSet, SiemFindings, StepOutcome, SubtaskResult, SubtaskStatus

from smartops.tools.native.decoder import decode_encoded_commands, decode_powershell

BLOB = "JABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQA="  # $env:username, from run e1461da6


def test_decodes_encoded_command_and_ignores_lookalikes():
    assert decode_powershell(f"powershell.exe -EncodedCommand {BLOB}") == ["$env:username"]
    assert decode_powershell(f"pwsh /enc {BLOB} -e Bypass -ExecutionPolicy Bypass") == ["$env:username"]
    assert decode_powershell("powershell.exe -ExecutionPolicy Bypass -C Get-Process") == []


def test_the_tool_annotates_the_named_steps_rows_and_returns_only_counts():
    rows = [{"process": f"powershell.exe -EncodedCommand {BLOB}"}, {"process": "cmd.exe"}]
    result = SubtaskResult(
        task_id="t:siem:tu-1", status=SubtaskStatus.OK,
        findings=SiemFindings(processes=[ResultSet(query="q", row_count=2, rows=rows)]),
    )
    step = FetchStep(step_id="procs", family="siem", objective="process command lines")
    req = SimpleNamespace(step_outcomes={"procs": StepOutcome(step=step, result_ids=["t:siem:tu-1"])},
                          collected=[result])
    ctx = SimpleNamespace(tool_use={"toolUseId": "tu-d"}, invocation_state={"smartops": req})

    reply = decode_encoded_commands(step_id="procs", tool_context=ctx)

    assert reply == "status=ok | step=procs rows=2 decoded=1"
    assert "username" not in reply  # counts, not content: the Broker never reads rows
    assert result.findings.processes[0].rows[0]["decoded_command"] == "$env:username"
    assert "status=refused" in decode_encoded_commands(step_id="nope", tool_context=ctx)
