"""Tests for the per-record-type evidence projectors."""

from __future__ import annotations

from smartops.subagent_analysts.formatting import (
    format_result_set,
    format_row,
    format_vt_verdicts,
)

from contracts import ResultSet, VtVerdict


class TestFieldProjection:
    def test_auth_event_projects_salient_fields(self):
        line = format_row(
            "auth_events",
            {"_time": "2018-08-20T13:05:01Z", "user": "bostoll", "src": "10.0.0.5",
             "dest": "BSTOLL-L", "action": "failure", "app": "win:auth"},
        )
        assert "user=bostoll" in line
        assert "action=failure" in line
        assert "dest=BSTOLL-L" in line

    def test_missing_field_renders_dash_not_dropped(self):
        line = format_row("auth_events", {"user": "bostoll"})
        assert "user=bostoll" in line
        assert "src=-" in line  # absent field kept as a placeholder column

    def test_case_insensitive_field_lookup(self):
        line = format_row("auth_events", {"User": "bostoll", "Action": "success"})
        assert "user=bostoll" in line
        assert "action=success" in line

    def test_auth_event_carries_eventcode_and_logon_type(self):
        # The one discriminating pair of fields that tells a CachedInteractive
        # unlock (EventCode 4624, Logon_Type 11) apart from a password spray:
        # dropping them left both the old and new analyst reasoning over six
        # near-identical rows with the actual signal stripped out.
        line = format_row(
            "auth_events",
            {"_time": "2018-08-20T13:05:01Z", "user": "bostoll",
             "EventCode": "4624", "Logon_Type": "11"},
        )
        assert "code=4624" in line
        assert "logon_type=11" in line

    def test_connection_joins_host_and_port(self):
        line = format_row(
            "connections",
            {"src": "10.0.0.5", "src_port": "51000", "dest": "1.2.3.4", "dest_port": "443"},
        )
        assert "10.0.0.5:51000→1.2.3.4:443" in line

    def test_process_cmdline_is_truncated(self):
        line = format_row(
            "processes", {"process": "powershell.exe " + "A" * 500}
        )
        assert "…" in line
        assert len(line) < 400

    def test_uncategorised_falls_back_to_key_values(self):
        line = format_row("uncategorised", {"foo": "bar", "baz": "qux"})
        assert "foo=bar" in line


class TestRealSplunkFieldNames:
    """Rows taken verbatim from `.smartops/runs/*/report.json`.

    The candidate lists in `formatting.py` were written against CIM-normalised
    field names, but real BOTS v3 data overwhelmingly carries the raw source
    spellings -- Windows Security (`New_Process_Name`), Splunk Stream
    (`query{}`), and the `count` that `| stats count by ...` produces. Measured
    across all 22 saved runs, 1,648 of 1,887 `processes` rows carried data that
    never reached the rendered line, and the header above them still advertised
    `rows=N`, so the grounding gate accepted citations to blocks the analyst had
    been shown as blank.
    """

    def test_windows_process_creation_row_projects_its_real_field_names(self):
        # The dominant real `processes` shape. `New_Process_Name` and
        # `Process_Command_Line` are the two the old candidate lists missed --
        # `projection.py:_infer_cim_category` already matches on both to decide
        # this row IS a process event, so the categoriser and the projector
        # disagreed about what a process row looks like.
        line = format_row(
            "processes",
            {
                "user": "BudStoll",
                "New_Process_Name": "C:\\Windows\\System32\\backgroundTaskHost.exe",
                "Process_Command_Line": '"C:\\Windows\\system32\\backgroundTaskHost.exe" -ServerName:App.X',
                "count": "56",
            },
        )
        assert "backgroundTaskHost.exe" in line
        assert "process=-" not in line

    def test_parent_process_uses_the_windows_creator_spelling(self):
        line = format_row(
            "processes",
            {
                "Account_Name": "bostoll",
                "Creator_Process_Name": "C:\\Windows\\explorer.exe",
                "New_Process_Name": "C:\\Windows\\System32\\cmd.exe",
            },
        )
        assert "explorer.exe" in line
        assert "parent=-" not in line

    def test_stats_count_is_carried_into_the_line(self):
        # `| stats count by ...` is the dominant triage SPL shape: `count`
        # appears on 1,260 of 1,887 real process rows and 138 auth rows. The
        # identity prompt asks the model to spot "many failures for one account"
        # -- which is unanswerable once the quantity has been dropped.
        line = format_row(
            "auth_events",
            {"Account_Name": "BSTOLL-L$", "Logon_Type": "5", "count": "164"},
        )
        assert "count=164" in line

    def test_connection_renders_both_byte_directions(self):
        # Both fields co-occur on real rows. Rendering only one direction
        # inverts the exfil signal the network prompt asks the model to find.
        line = format_row(
            "connections",
            {
                "src_ip": "192.168.247.131", "src_port": "49844",
                "dest_ip": "37.187.167.47", "dest_port": "443",
                "bytes_in": "28170", "bytes_out": "21383",
            },
        )
        assert "28170" in line
        assert "21383" in line

    def test_lowercase_cmd_line_spelling_is_projected(self):
        # 102 real rows use `cmd_line` rather than `command_line`, and every one
        # of them is a PowerShell execution -- the single highest-signal record
        # the endpoint analyst can be shown. They rendered `cmdline=-`.
        line = format_row(
            "processes",
            {
                "account_name": "BudStoll",
                "new_process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "creator_process_name": "C:\\Windows\\System32\\browser_broker.exe",
                "cmd_line": "powershell.exe -enc SQBFAFgA",
            },
        )
        assert "-enc SQBFAFgA" in line
        assert "cmdline=-" not in line

    def test_a_row_with_no_recognised_field_falls_back_to_key_values(self):
        # The mechanism fix, and the reason this class of bug was silent: a
        # categorised row whose field names are all unknown produced a
        # structurally valid, entirely empty line rather than degrading to the
        # generic key=value renderer that already existed for `uncategorised`.
        line = format_row(
            "processes", {"reply_code": "NoError", "transport": "udp"}
        )
        assert "NoError" in line
        assert "udp" in line


class TestResultSetRendering:
    def test_header_is_citation_anchor(self):
        rs = ResultSet(query="sourcetype=stream:dns", row_count=1,
                       rows=[{"query": "coinhive.com", "answer": "1.2.3.4"}])
        out = format_result_set("dns_resolutions", rs, index=1)
        assert "# dns_resolutions#1" in out
        assert 'query="sourcetype=stream:dns"' in out
        assert "coinhive.com" in out

    def test_empty_result_set_is_still_reported(self):
        rs = ResultSet(query="sourcetype=x", row_count=0, rows=[])
        out = format_result_set("connections", rs, index=2)
        assert "rows=0" in out
        assert "no rows returned" in out

    def test_row_cap_reports_withheld_rows(self):
        rows = [{"user": f"u{i}"} for i in range(30)]
        rs = ResultSet(query="q", row_count=30, rows=rows)
        out = format_result_set("auth_events", rs, index=1, row_cap=10)
        assert "20 more rows not shown" in out


class TestVtRendering:
    def test_flagged_indicators_sort_first(self):
        verdicts = [
            VtVerdict(kind="domain", value="clean.com", found=True, malicious=0),
            VtVerdict(kind="domain", value="bad.com", found=True, malicious=11, suspicious=2),
        ]
        out = format_vt_verdicts(verdicts)
        assert out.index("bad.com") < out.index("clean.com")
        assert "mal=11" in out

    def test_no_indicators(self):
        out = format_vt_verdicts([])
        assert "no indicators looked up" in out

