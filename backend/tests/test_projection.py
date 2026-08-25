import json
"""Projecting captured tool output into typed findings.

The two-layer payload only works if neither layer can forge the other: the model
says which category each query served, code supplies every row. These tests pin
that split, and the behaviour when the two disagree.
"""

from smartops.projection import _rows_of, project, project_siem, project_vt
from smartops.subagents import _ToolCall

from contracts import QueryRun


def call(query, rows, tool="splunk_run_query"):
    return _ToolCall(tool=tool, query=query, payload={"results": rows})


VT_SUMMARY = "domain=coinhive.com: 11 malicious / 1 suspicious of 91 engines"


class TestBucketing:
    def test_rows_land_in_the_category_the_model_tagged(self):
        findings = project_siem(
            [call("index=botsv3 sourcetype=dns", [{"q": "coinhive.com"}])],
            [QueryRun(query="index=botsv3 sourcetype=dns", category="dns_resolutions")], task_id="t"
        )

        assert findings.dns_resolutions[0].rows == [{"q": "coinhive.com"}]
        assert findings.dns_resolutions[0].row_count == 1
        assert findings.processes == []

    def test_the_result_set_is_keyed_by_the_query_that_produced_it(self):
        findings = project_siem(
            [call("index=botsv3 | stats count", [{"count": 4}])],
            [QueryRun(query="index=botsv3 | stats count", category="connections")], task_id="t"
        )

        assert findings.connections[0].query == "index=botsv3 | stats count"

    def test_whitespace_differences_still_match(self):
        """The model retypes its query into `queries_run`, and retyping changes
        spacing. Matching on the raw string would miss almost every time."""
        findings = project_siem(
            [call("index=botsv3   |  stats  count", [{"count": 1}])],
            [QueryRun(query="index=botsv3 | stats count", category="processes")], task_id="t"
        )

        assert findings.processes and findings.uncategorised == []


class TestNothingIsSilentlyDropped:
    def test_an_untagged_query_is_kept_not_discarded(self):
        """Rows were retrieved and paid for. Dropping them because attribution
        failed would be the worse error, and a full bucket here is a signal."""
        findings = project_siem([call("index=botsv3 | head 1", [{"a": 1}])], [], task_id="t")

        assert findings.uncategorised[0].rows == [{"a": 1}]
        assert findings.total_rows() == 1

    def test_a_query_the_model_never_reported_is_kept(self):
        # The model reported a different query than the one it actually ran.
        findings = project_siem(
            [call("index=botsv3 sourcetype=wineventlog", [{"a": 1}])],
            [QueryRun(query="something else entirely", category="processes")], task_id="t"
        )

        assert findings.processes == []
        assert findings.uncategorised[0].rows == [{"a": 1}]

    def test_a_call_with_no_recoverable_query_still_appears(self):
        findings = project_siem([_ToolCall("splunk_get_indexes", None, {"results": [{"i": "x"}]})], [], task_id="t")

        assert findings.uncategorised[0].row_count == 1
        assert "not recoverable" in findings.uncategorised[0].query

    def test_untagged_queries_are_inferred_from_spl_predicates(self):
        calls = [
            call("index=botsv3 sourcetype=stream:dns query=coinhive.com", [{"q": "coinhive.com"}]),
            call("index=botsv3 sourcetype=stream:tcp dest_port=443", [{"port": 443}]),
            call("index=botsv3 sourcetype=WinEventLog EventCode=4688", [{"proc": "cmd.exe"}]),
            call("index=botsv3 sourcetype=WinEventLog EventCode=4624", [{"user": "admin"}]),
        ]
        findings = project_siem(calls, [], task_id="t")

        assert findings.dns_resolutions[0].row_count == 1
        assert findings.connections[0].row_count == 1
        assert findings.processes[0].row_count == 1
        assert findings.auth_events[0].row_count == 1
        assert findings.uncategorised == []

    def test_eventcode_inference_is_bounded_to_the_exact_code(self):
        # Sysmon EventCode 1 = process create; 11/13/15 are file/registry/other and
        # must NOT be mis-read as processes by a naive "eventcode=1" substring.
        proc = project_siem([call("index=botsv3 EventCode=1", [{"p": 1}])], [], task_id="t")
        assert proc.processes[0].row_count == 1
        assert proc.uncategorised == []

        for code in (11, 13, 15, 100):
            findings = project_siem([call(f"index=botsv3 EventCode={code}", [{"e": code}])], [], task_id="t")
            assert findings.processes == [], f"EventCode={code} wrongly inferred as processes"
            assert findings.uncategorised[0].row_count == 1

    def test_sysmon_network_connection_eventcode_3_infers_connections(self):
        findings = project_siem(
            [call("index=botsv3 sourcetype=xmlwineventlog EventCode=3 dest_ip=1.2.3.4", [{"c": 1}])],
            [], task_id="t"
        )
        assert findings.connections[0].row_count == 1
        assert findings.uncategorised == []


class TestRowExtraction:
    def test_common_envelopes_are_understood(self):
        for key in ("results", "rows", "records", "events"):
            findings = project_siem(
                [_ToolCall("t", "index=botsv3 | head 1", {key: [{"a": 1}, {"a": 2}]})], [], task_id="t"
            )
            assert findings.uncategorised[0].row_count == 2, key

    def test_a_bare_list_is_understood(self):
        findings = project_siem([_ToolCall("t", "index=botsv3 | head 1", [{"a": 1}])], [], task_id="t")

        assert findings.uncategorised[0].row_count == 1

    def test_an_unrecognised_payload_reports_zero_rather_than_guessing(self):
        """Giving up honestly beats reshaping an unknown envelope into something
        wrong -- a zero-row result set is visible, a mangled one is not."""
        findings = project_siem([_ToolCall("t", "index=botsv3 | head 1", "some opaque string")], [], task_id="t")

        assert findings.uncategorised[0].row_count == 0
        assert findings.uncategorised[0].rows == []


class TestFamilies:
    def test_vt_projects_here_not_only_at_the_call_site(self):
        """`project()` must dispatch vt itself, not leave it to its callers.

        This used to assert the opposite -- that vt had no projector, because
        `enrich_mission()` builds `VtFindings` straight from parsed Verdicts on a
        path that calls no model. True of the *enricher*, but the vt *subagent*
        goes through `investigate()`, which needs a projector like any other
        family. `893f587` supplied one by appending `or project_vt(...)` at the
        success call site, which left the no-answer branch calling bare
        `project()` and reporting `findings=None` while holding real evidence.

        Dispatching here is what makes both branches -- and any third -- correct
        by construction.
        """
        findings = project(
            "vt", [_ToolCall("vt_lookup_domain", "coinhive.com", VT_SUMMARY)], [], task_id="t"
        )
        assert findings is not None
        assert [v.value for v in findings.verdicts] == ["coinhive.com"]

    def test_an_unknown_family_projects_nothing_rather_than_raising(self):
        assert project("edr", [call("index=x | head 1", [{"a": 1}])], [], task_id="t") is None


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
        findings = project_vt([_ToolCall("vt_lookup_domain", "coinhive.com", self.ENRICHER_TEXT)], task_id="t")

        assert [v.value for v in findings.verdicts] == ["coinhive.com"]
        assert findings.verdicts[0].found is True
        assert findings.verdicts[0].malicious == 11

    def test_the_live_tool_envelope_parses_identically(self):
        """The regression. Both paths carry the same summary, so both must yield
        the same verdict -- an anchored pattern matched only the bare string."""
        findings = project_vt(
            [_ToolCall("vt_lookup_domain", "coinhive.com", self._wrapped(self.ENRICHER_TEXT))], task_id="t"
        )

        assert findings.verdicts[0].value == "coinhive.com"
        assert findings.verdicts[0].found is True
        assert findings.verdicts[0].malicious == 11
        assert findings.verdicts[0].suspicious == 1
        assert findings.verdicts[0].harmless == 79  # 91 engines - 11 - 1

    def test_an_unknown_indicator_is_recorded_as_unknown(self):
        findings = project_vt(
            [_ToolCall("vt_lookup_domain", "nope.example", self._wrapped("domain=nope.example: unknown to VirusTotal"))], task_id="t"
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
            ], task_id="t"
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
        findings = project_vt([_ToolCall("vt_lookup_domain", "coinhive.com", {"unexpected": "envelope"})], task_id="t")

        assert findings.verdicts == []


class TestRowsSurviveTheLiveToolEnvelope:
    """The rows a Splunk search returned must reach the typed findings payload.

    This was broken for every run the system had ever made. `_rows_of` looked for
    `results`/`rows`/`records`/`events` at the top level of the payload, but a
    tool reached through a live `Agent` nests the body under `structuredContent`.
    So every projected `ResultSet` carried `row_count=0` and `rows=[]`.

    Nothing looked wrong from outside: `Evidence` was captured correctly, so
    citations resolved and evidence counts were healthy. Only the findings -- the
    half the two-layer design exists to have code assemble -- were empty.
    Measured on a 10-case live run: 54 siem evidence items held real rows and the
    projection saw zero for all 54.
    """

    @staticmethod
    def _envelope(rows: list[dict]) -> dict:
        """The shape splunk_run_query actually returns through a live Agent."""
        return {
            "status": "success",
            "toolUseId": "tooluse_abc",
            "content": [{"text": json.dumps({"results": rows})}],
            "structuredContent": {
                "results": rows,
                "truncated": False,
                "total_rows": len(rows),
            },
            "isError": False,
        }

    def test_rows_nested_under_structured_content_are_found(self):
        rows = [{"host": "BSTOLL-L", "count": "21"}, {"host": "MKRAEUS-L", "count": "7"}]

        assert _rows_of(self._envelope(rows)) == rows

    def test_a_categorised_query_reports_its_real_row_count(self):
        """End to end: the count a reader sees comes from the tool's own rows."""
        rows = [{"query": "coinhive.com", "count": "21"}]
        findings = project_siem(
            [_ToolCall("splunk_run_query", "index=botsv3 sourcetype=stream:dns", self._envelope(rows))],
            [QueryRun(query="index=botsv3 sourcetype=stream:dns", category="dns_resolutions")], task_id="t"
        )

        assert findings.dns_resolutions[0].row_count == 1
        assert findings.dns_resolutions[0].rows == rows

    def test_an_empty_result_is_still_zero_rather_than_unrecognised(self):
        """A search that legitimately matched nothing must stay distinguishable
        from one whose envelope could not be read -- both show 0, so the
        difference has to hold at the shape level."""
        assert _rows_of(self._envelope([])) == []

    def test_a_top_level_payload_still_works(self):
        """The enricher and the scripted path hand rows over unwrapped."""
        assert _rows_of({"results": [{"a": 1}]}) == [{"a": 1}]


class TestEvidenceBackReference:
    """The projected row set names the `Evidence` it came from.

    Without it a stored citation resolves only to a POSITION in a recomputed
    routing, so any change to routing order silently re-targets every citation
    already written to disk.
    """

    def test_the_projector_and_the_collector_mint_the_same_ids(self):
        # The whole back-reference rests on one invariant: `project_siem` and
        # `_EvidenceCollector.evidence()` enumerate the SAME list, so index i in
        # one is index i in the other. Nothing enforced that, so pin it here --
        # if the two ever drift, every evidence_id points at the wrong payload
        # while still looking perfectly well-formed.
        from datetime import UTC, datetime

        from smartops.subagents import _EvidenceCollector

        calls = [
            call("index=botsv3 sourcetype=dns", [{"q": "coinhive.com"}]),
            call("index=botsv3 EventCode=1", [{"p": "powershell.exe"}]),
            call("index=botsv3 EventCode=4624", [{"user": "bostoll"}]),
        ]
        collector = _EvidenceCollector()
        collector.calls = calls
        evidence = collector.evidence("t-1:siem:s0", "siem", datetime.now(UTC))

        findings = project_siem(
            calls,
            [
                QueryRun(query="index=botsv3 sourcetype=dns", category="dns_resolutions"),
                QueryRun(query="index=botsv3 EventCode=1", category="processes"),
                QueryRun(query="index=botsv3 EventCode=4624", category="auth_events"),
            ],
            task_id="t-1:siem:s0",
        )

        assert [e.id for e in evidence] == [
            "t-1:siem:s0:0", "t-1:siem:s0:1", "t-1:siem:s0:2"
        ]
        assert findings.dns_resolutions[0].evidence_id == evidence[0].id
        assert findings.processes[0].evidence_id == evidence[1].id
        assert findings.auth_events[0].evidence_id == evidence[2].id

    def test_a_vt_payload_carrying_its_own_evidence_id_keeps_it(self):
        # project_vt's dict branch spreads the payload over the default rather
        # than passing evidence_id as a keyword beside `**v`, which would be a
        # duplicate-keyword TypeError the moment a payload carried the field.
        findings = project_vt(
            [_ToolCall("vt", None, {"verdicts": [
                {"kind": "domain", "value": "a.com", "found": True,
                 "evidence_id": "already-set"},
            ]})],
            task_id="t-1:vt:s0",
        )
        assert findings.verdicts[0].evidence_id == "already-set"

    def test_a_vt_payload_without_one_is_stamped(self):
        findings = project_vt(
            [_ToolCall("vt", None, {"verdicts": [
                {"kind": "domain", "value": "a.com", "found": True},
            ]})],
            task_id="t-1:vt:s0",
        )
        assert findings.verdicts[0].evidence_id == "t-1:vt:s0:0"


class TestTheModelsOwnAnswerIsNotEvidence:
    """The end-to-end property: no citable header is ever backed by the model.

    Reproduced from `.smartops/runs/cli-20260823T112627`, where the SIEM subagent
    made 9 real queries and the pipeline emitted 10 result sets. The extra one was
    the `SiemAnswer` structured-output call: Strands runs it as a tool, so the
    collector recorded it, and `_query_of` lifted the longest search-looking
    string out of the answer's own `queries_run` -- which meant it arrived here
    wearing a real SPL query and was filed under `auth_events`. It became
    `auth_events#8` in the packed evidence, a header the analysts could and did
    cite, whose evidence resolved to the model quoting itself.

    Written against the whole chain rather than any one function because every
    stage behaved correctly in isolation; only the composition was wrong.
    """

    def _events(self, names_and_queries):
        class _Event:
            def __init__(self, tool_use, result):
                self.tool_use = tool_use
                self.result = result
                self.exception = None

        return [
            _Event(
                {"name": name, "input": {"query": query} if query else {}},
                {"status": "success", "content": [{"json": {"results": [{"user": "bostoll"}]}}]},
            )
            for name, query in names_and_queries
        ]

    def test_the_answer_call_produces_no_result_set_and_no_header(self):
        from datetime import UTC, datetime

        from smartops.subagent_analysts.packing import valid_citation_ids
        from smartops.subagent_analysts.routing import route
        from smartops.subagents import _EvidenceCollector

        from contracts import (
            BrokerReport,
            CostSummary,
            Entity,
            Scope,
            SubtaskResult,
            SubtaskStatus,
            TaskClassification,
        )

        task_id = "t-1:siem:s0"
        real = [
            ("splunk_run_query", "index=botsv3 sourcetype=WinEventLog EventCode=4624"),
            ("splunk_run_query", "index=botsv3 sourcetype=WinEventLog EventCode=4625"),
        ]
        # The answer call, carrying a query string exactly as `_query_of` scraped
        # one from the real run's `SiemAnswer` input.
        answer = [("SiemAnswer", "index=botsv3 sourcetype=WinEventLog EventCode=4672")]

        collector = _EvidenceCollector(answer_tool="SiemAnswer")
        for event in self._events(real + answer):
            collector._record(event)

        # One list, two consumers -- the alignment the back-reference rests on.
        evidence = collector.evidence(task_id, "siem", datetime.now(UTC))
        findings = project_siem(
            collector.calls,
            [QueryRun(query=q, category="auth_events") for _n, q in real],
            task_id=task_id,
        )

        assert len(collector.calls) == len(real), "the answer call is not a tool result"
        assert len(findings.auth_events) == len(real), "no phantom result set"
        assert len(evidence) == len(real)
        assert not any(e.raw["tool"] == "SiemAnswer" for e in evidence)

        # And nothing downstream can cite what was never emitted.
        report = BrokerReport(
            task_id="t-1",
            hypothesis_id="h-1",
            results=[
                SubtaskResult(
                    task_id=task_id,
                    family="siem",
                    status=SubtaskStatus.OK,
                    findings=findings,
                )
            ],
            classification=TaskClassification(tool_families=["siem"], rationale="x"),
            cost=CostSummary(),
        )
        scope = Scope(
            entities=[Entity(kind="user", value="bostoll")],
            time_window=(datetime(2018, 8, 20, tzinfo=UTC), datetime(2018, 8, 21, tzinfo=UTC)),
        )
        ids = valid_citation_ids(route(report, scope).identity)

        assert list(ids) == ["auth_events#1", "auth_events#2"]
        assert "auth_events#3" not in ids
        # Every header resolves to a real tool result, not to the model's answer.
        collected = {e.id: e.raw["tool"] for e in evidence}
        for header, evidence_ids in ids.items():
            assert evidence_ids, f"{header} resolves to nothing"
            for eid in evidence_ids:
                assert collected[eid] == "splunk_run_query"
