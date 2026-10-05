"""Encoded PowerShell: tagged by signature on arrival, decoded by reference on request (B10)."""

from types import SimpleNamespace

from contracts import DomainFinding, ResultSet, SiemFindings, SubtaskResult, SubtaskStatus

from smartops.subagent_analysts.analyze import DECODED_FOOTER, _as_judgement
from smartops.subagent_analysts.routing import DomainSlice
from smartops.tools.native.decoder import decode_encoded_commands, encoded, load, record, signature

BLOB = "JABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQA="  # $env:username, from run e1461da6
DESKTOP = r"C:\Users\Administrator\Desktop\splunkd.exe"
ROW = {"CommandLine": f'powershell.exe -ExecutionPolicy Bypass -C "powershell.exe -EncodedCommand {BLOB}"',
       "ParentImage": DESKTOP, "count": "4"}


def _result(*rows):
    return SubtaskResult(
        task_id="t:siem:tu-1", status=SubtaskStatus.OK,
        findings=SiemFindings(processes=[ResultSet(query="q", row_count=len(rows), rows=list(rows))]),
    )


def test_decodes_encoded_command_and_ignores_lookalikes():
    assert encoded(f"powershell.exe -EncodedCommand {BLOB}") == {BLOB: "$env:username"}
    assert list(encoded(f"pwsh /enc {BLOB} -e Bypass -ExecutionPolicy Bypass").values()) == ["$env:username"]
    assert encoded("powershell.exe -ExecutionPolicy Bypass -C Get-Process") == {}
    assert signature(BLOB) == signature(BLOB) and signature(BLOB).startswith("enc#")


def test_record_merges_parents_across_tasks_without_counting_refetches(tmp_path):
    path = tmp_path / "run" / "encoded.json"
    assert record(path, [_result(ROW, {"CommandLine": "cmd.exe"})]) == 1
    assert record(path, [_result({**ROW, "ParentImage": "powershell.exe"})]) == 0
    assert load(path) == {signature(BLOB): {"blob": BLOB, "parents": [DESKTOP, "powershell.exe"]}}


def test_the_tool_decodes_by_reference_and_returns_only_counts(tmp_path):
    path = tmp_path / "encoded.json"
    record(path, [_result(ROW)])
    req = SimpleNamespace(encoded_registry=path, decoded=[])
    ctx = SimpleNamespace(tool_use={"toolUseId": "tu-d"}, invocation_state={"smartops": req})
    sig = signature(BLOB)

    reply = decode_encoded_commands(refs=[sig, "enc#000000"], tool_context=ctx)

    assert reply == "status=ok | refs=1 decoded=1 | unknown=enc#000000"
    assert "username" not in reply  # counts, not content: the Broker never reads rows
    assert req.decoded == [f"~ {sig} (parent {DESKTOP}) decodes to: $env:username"]
    decode_encoded_commands(refs=[], tool_context=ctx)  # empty = all; no duplicate line
    assert len(req.decoded) == 1
    assert "status=refused" in decode_encoded_commands(refs=["enc#000000"], tool_context=ctx)


def test_the_handoff_names_the_reference_then_carries_what_it_decoded_to():
    slice_ = DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=1, rows=[ROW]))])
    finding = DomainFinding(domain="endpoint", narrative="PowerShell ran an encoded command.")

    loop_n = _as_judgement(finding, slice_).narrative
    assert f"~ encoded command {signature(BLOB)}: 4 events, parent {DESKTOP}=4" in loop_n
    assert "username" not in loop_n  # tagged, not decoded, until a task asks

    empty = DomainFinding(domain="endpoint", narrative="")
    loop_n1 = _as_judgement(empty, DomainSlice(domain="endpoint"), ["~ enc#x decodes to: $env:username"]).narrative
    assert loop_n1 == f"{DECODED_FOOTER}\n~ enc#x decodes to: $env:username"
