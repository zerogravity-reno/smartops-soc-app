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
