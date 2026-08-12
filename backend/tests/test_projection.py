"""Projecting captured tool output into typed findings.

The two-layer payload only works if neither layer can forge the other: the model
says which category each query served, code supplies every row. These tests pin
that split, and the behaviour when the two disagree.
"""

from smartops.projection import project, project_siem
from smartops.subagents import _ToolCall

from contracts import QueryRun


def call(query, rows, tool="splunk_run_query"):
    return _ToolCall(tool=tool, query=query, payload={"results": rows})


class TestBucketing:
    def test_rows_land_in_the_category_the_model_tagged(self):
        findings = project_siem(
            [call("index=botsv3 sourcetype=dns", [{"q": "coinhive.com"}])],
            [QueryRun(query="index=botsv3 sourcetype=dns", category="dns_resolutions")],
        )

        assert findings.dns_resolutions[0].rows == [{"q": "coinhive.com"}]
        assert findings.dns_resolutions[0].row_count == 1
        assert findings.processes == []

    def test_the_result_set_is_keyed_by_the_query_that_produced_it(self):
        findings = project_siem(
            [call("index=botsv3 | stats count", [{"count": 4}])],
            [QueryRun(query="index=botsv3 | stats count", category="connections")],
        )

        assert findings.connections[0].query == "index=botsv3 | stats count"

    def test_whitespace_differences_still_match(self):
        """The model retypes its query into `queries_run`, and retyping changes
        spacing. Matching on the raw string would miss almost every time."""
        findings = project_siem(
            [call("index=botsv3   |  stats  count", [{"count": 1}])],
            [QueryRun(query="index=botsv3 | stats count", category="processes")],
        )

        assert findings.processes and findings.uncategorised == []


class TestNothingIsSilentlyDropped:
    def test_an_untagged_query_is_kept_not_discarded(self):
        """Rows were retrieved and paid for. Dropping them because attribution
        failed would be the worse error, and a full bucket here is a signal."""
        findings = project_siem([call("index=botsv3 | head 1", [{"a": 1}])], [])

        assert findings.uncategorised[0].rows == [{"a": 1}]
        assert findings.total_rows() == 1

    def test_a_query_the_model_never_reported_is_kept(self):
        # The model reported a different query than the one it actually ran.
        findings = project_siem(
            [call("index=botsv3 sourcetype=wineventlog", [{"a": 1}])],
            [QueryRun(query="something else entirely", category="processes")],
        )

        assert findings.processes == []
        assert findings.uncategorised[0].rows == [{"a": 1}]

    def test_a_call_with_no_recoverable_query_still_appears(self):
        findings = project_siem([_ToolCall("splunk_get_indexes", None, {"results": [{"i": "x"}]})], [])

        assert findings.uncategorised[0].row_count == 1
        assert "not recoverable" in findings.uncategorised[0].query


class TestRowExtraction:
    def test_common_envelopes_are_understood(self):
        for key in ("results", "rows", "records", "events"):
            findings = project_siem(
                [_ToolCall("t", "index=botsv3 | head 1", {key: [{"a": 1}, {"a": 2}]})], []
            )
            assert findings.uncategorised[0].row_count == 2, key

    def test_a_bare_list_is_understood(self):
        findings = project_siem([_ToolCall("t", "index=botsv3 | head 1", [{"a": 1}])], [])

        assert findings.uncategorised[0].row_count == 1

    def test_an_unrecognised_payload_reports_zero_rather_than_guessing(self):
        """Giving up honestly beats reshaping an unknown envelope into something
        wrong -- a zero-row result set is visible, a mangled one is not."""
        findings = project_siem([_ToolCall("t", "index=botsv3 | head 1", "some opaque string")], [])

        assert findings.uncategorised[0].row_count == 0
        assert findings.uncategorised[0].rows == []


class TestFamilies:
    def test_vt_has_no_projector_because_its_findings_are_built_upstream(self):
        # `enrich_mission()` builds VtFindings straight from parsed Verdicts, on
        # a path that calls no model at all.
        assert project("vt", [], []) is None

    def test_an_unknown_family_projects_nothing_rather_than_raising(self):
        assert project("edr", [call("index=x | head 1", [{"a": 1}])], []) is None
