"""Empty searches reach the Analyst by name; empty exhibits beside real rows do not (F8)."""

from contracts import DomainFinding, ResultSet

from contracts.reasoning import NO_ROWS_FOOTER
from smartops.subagent_analysts.analyze import NO_ROWS_LINE_CAP, _as_record
from smartops.subagent_analysts.routing import DomainSlice


def _judge(sets, cited=None):
    slice_ = DomainSlice(domain="endpoint", siem_sets=sets)
    cited = cited if cited is not None else [f"{category}#1" for category, _ in sets]
    return _as_record(DomainFinding(domain="endpoint", narrative="n", citations=cited), slice_)


def _empty(category, query=None):
    return (category, ResultSet(query=query or f"search {category}", row_count=0, rows=[]))


REAL = ("processes", ResultSet(query="p", row_count=1, rows=[{"Image": "a.exe"}]))


def test_empty_exhibits_beside_real_rows_are_named_not_shown():
    judged = _judge([REAL, _empty("file_events"), _empty("registry_events"), _empty("auth_events")])

    assert [e.citation for e in judged.exhibits] == ["processes#1"]
    assert judged.narrative == "n"  # the model's prose only; code lines are facts (B14)
    footer = judged.facts[judged.facts.index(NO_ROWS_FOOTER) + 1:]
    assert footer == ["~ 3 searches returned no rows, including:",
                      "~ search file_events", "~ search registry_events", "~ search auth_events"]
    assert len(judged.citations) == 4  # the gate still sees every id


def test_an_uncited_empty_search_is_named_too():
    # 5aae1a35 T1: the PID 220 creation search was empty and nobody cited it.
    judged = _judge([REAL, _empty("dns_resolutions", "EventCode=1 ProcessId=220")], cited=["processes#1"])

    assert "~ EventCode=1 ProcessId=220" in judged.facts


def test_only_empty_exhibits_are_kept_as_negative_evidence():
    judged = _judge([_empty("file_events"), _empty("auth_events")])

    assert len(judged.exhibits) == 2


def test_the_footer_is_a_count_and_the_searches_naming_the_tasks_entities_first():
    # 874ab334: 26 no-rows lines in L2 and 47 in L3, the largest code footer.
    from datetime import UTC, datetime

    from contracts import Entity, Scope

    slice_ = DomainSlice(domain="endpoint", siem_sets=[REAL, *(_empty("file_events", f"q{i}") for i in range(9)),
                                                       _empty("file_events", "EventCode=1 ProcessId=220")])
    now = datetime(2026, 10, 6, tzinfo=UTC)
    scope = Scope(entities=[Entity(kind="process_id", value="220")], time_window=(now.replace(hour=0), now.replace(hour=1)))
    judged = _as_record(DomainFinding(domain="endpoint", narrative="n", citations=["processes#1"]), slice_, scope)

    footer = judged.facts[judged.facts.index(NO_ROWS_FOOTER) + 1:]
    assert footer[0] == "~ 10 searches returned no rows, including:"
    assert footer[1] == "~ EventCode=1 ProcessId=220"
    assert len(footer) == NO_ROWS_LINE_CAP + 1


def test_a_comma_list_of_figures_is_not_fused_into_one():
    # 25965109: "4720,4722,..." read as 47204722... and three observations were dropped.
    from smartops.subagent_analysts.analyze import _figures

    assert {"4720", "4722", "1126"} <= _figures("EventCodes 4720,4722 across 1,126 events")
    assert _figures("EventCodes 4720,4722") == {"4720", "4722"}
