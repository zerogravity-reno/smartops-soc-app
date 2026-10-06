"""Encoded PowerShell: decoded by code in the handoff of the loop that sees it (B10)."""

from contracts import DomainFinding, ResultSet

from smartops.subagent_analysts.analyze import _as_judgement
from smartops.subagent_analysts.routing import DomainSlice
from smartops.tools.native.decoder import encoded, signature

BLOB = "JABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQA="  # $env:username, from run e1461da6
DESKTOP = r"C:\Users\Administrator\Desktop\splunkd.exe"
ROW = {"CommandLine": f'powershell.exe -ExecutionPolicy Bypass -C "powershell.exe -EncodedCommand {BLOB}"',
       "ParentImage": DESKTOP, "count": "4"}


def test_decodes_encoded_command_and_ignores_lookalikes():
    assert encoded(f"powershell.exe -EncodedCommand {BLOB}") == {BLOB: "$env:username"}
    assert list(encoded(f"pwsh /enc {BLOB} -e Bypass -ExecutionPolicy Bypass").values()) == ["$env:username"]
    assert encoded("powershell.exe -ExecutionPolicy Bypass -C Get-Process") == {}
    assert signature(BLOB) == signature(BLOB) and signature(BLOB).startswith("enc#")


def test_the_handoff_carries_reference_parents_and_plain_text_in_the_same_loop():
    slice_ = DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=1, rows=[ROW]))])
    finding = DomainFinding(domain="endpoint", narrative="PowerShell ran an encoded command.")

    narrative = _as_judgement(finding, slice_).narrative

    assert (
        f"~ encoded command {signature(BLOB)}: 4 events, parent {DESKTOP}=4; decodes to: $env:username"
        in narrative
    )
