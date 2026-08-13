"""Projecting captured tool output into typed findings.

The two-layer payload only works if neither layer can forge the other: the model
says which category each query served, code supplies every row. These tests pin
that split, and the behaviour when the two disagree.
"""

from smartops.projection import project, project_siem, project_vt
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


class TestVtProjection:
    """`project_vt` reads the summary string `Verdict.summary()` emits.

    The failure this class exists for was silent and wrong in the worst
    direction: on the live path a *malicious* domain projected as
    `value="unknown", found=False, malicious=0` while the subagent's own
    assessment correctly read "11 malicious / 1 suspicious of 91 engines".
    """

    ENRICHER_TEXT = "domain=coinhive.com: 11 malicious / 1 suspicious of 91 engines"

    @staticmethod
    def _wrapped(text: str) -> dict:
        """How a native @tool result comes back through a live `Agent`."""
        return {
            "status": "success",
            "toolUseId": "tooluse_abc",
            "content": [{"text": text}],
            "isError": False,
        }

    def test_the_enricher_path_still_parses(self):
        findings = project_vt([_ToolCall("vt_lookup_domain", "coinhive.com", self.ENRICHER_TEXT)])

        assert [v.value for v in findings.verdicts] == ["coinhive.com"]
        assert findings.verdicts[0].found is True
        assert findings.verdicts[0].malicious == 11

    def test_the_live_tool_envelope_parses_identically(self):
        """The regression. Both paths carry the same summary, so both must yield
        the same verdict -- an anchored pattern matched only the bare string."""
        findings = project_vt(
            [_ToolCall("vt_lookup_domain", "coinhive.com", self._wrapped(self.ENRICHER_TEXT))]
        )

        assert findings.verdicts[0].value == "coinhive.com"
        assert findings.verdicts[0].found is True
        assert findings.verdicts[0].malicious == 11
        assert findings.verdicts[0].suspicious == 1
        assert findings.verdicts[0].harmless == 79  # 91 engines - 11 - 1

    def test_an_unknown_indicator_is_recorded_as_unknown(self):
        findings = project_vt(
            [_ToolCall("vt_lookup_domain", "nope.example", self._wrapped("domain=nope.example: unknown to VirusTotal"))]
        )

        assert findings.verdicts[0].found is False
        assert findings.verdicts[0].malicious == 0

    def test_several_indicators_in_one_payload_all_survive(self):
        """`search` took the first and dropped the rest."""
        findings = project_vt(
            [
                _ToolCall(
                    "vt_lookup_domain",
                    None,
                    self._wrapped(
                        "domain=a.example: 3 malicious / 0 suspicious of 90 engines\n"
                        "domain=b.example: unknown to VirusTotal"
                    ),
                )
            ]
        )

        assert [v.value for v in findings.verdicts] == ["a.example", "b.example"]

    def test_an_unparseable_payload_yields_no_verdict_rather_than_a_clean_one(self):
        """The dangerous branch, and the reason this is a correctness fix.

        Synthesising `found=False, malicious=0` from the tool name reports "this
        indicator is unknown to VirusTotal" -- a real VT answer -- when what
        happened is that the response could not be parsed. The subagent prompt
        forbids exactly this: a failed lookup is not evidence the subject is
        clean. No verdict is honest; a fabricated clean one is not.
        """
        findings = project_vt([_ToolCall("vt_lookup_domain", "coinhive.com", {"unexpected": "envelope"})])

        assert findings.verdicts == []
