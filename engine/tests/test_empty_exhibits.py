"""Empty searches reach the Analyst by name; empty exhibits beside real rows do not (F8)."""

from contracts import DomainFinding, ResultSet

from smartops.subagent_analysts.analyze import NO_ROWS_FOOTER, NO_ROWS_LINE_CAP, _as_judgement
from smartops.subagent_analysts.routing import DomainSlice


def _judge(sets, cited=None):
    slice_ = DomainSlice(domain="endpoint", siem_sets=sets)
    cited = cited if cited is not None else [f"{category}#1" for category, _ in sets]
    return _as_judgement(DomainFinding(domain="endpoint", narrative="n", citations=cited), slice_)


def _empty(category, query=None):
    return (category, ResultSet(query=query or f"search {category}", row_count=0, rows=[]))


REAL = ("processes", ResultSet(query="p", row_count=1, rows=[{"Image": "a.exe"}]))


def test_empty_exhibits_beside_real_rows_are_named_not_shown():
    judged = _judge([REAL, _empty("file_events"), _empty("registry_events"), _empty("auth_events")])

    assert [e.citation for e in judged.exhibits] == ["processes#1"]
    footer = judged.narrative.split(NO_ROWS_FOOTER + "\n")[1].splitlines()
    assert footer == ["~ search file_events", "~ search registry_events", "~ search auth_events"]
    assert len(judged.citations) == 4  # the gate still sees every id


def test_an_uncited_empty_search_is_named_too():
    # 5aae1a35 T1: the PID 220 creation search was empty and nobody cited it.
    judged = _judge([REAL, _empty("dns_resolutions", "EventCode=1 ProcessId=220")], cited=["processes#1"])

    assert "~ EventCode=1 ProcessId=220" in judged.narrative


def test_only_empty_exhibits_are_kept_as_negative_evidence():
    judged = _judge([_empty("file_events"), _empty("auth_events")])

    assert len(judged.exhibits) == 2


def test_the_footer_is_capped():
    judged = _judge([REAL, *(_empty(c, f"q{i}") for i, c in enumerate(["file_events"] * 10))])

    footer = judged.narrative.split(NO_ROWS_FOOTER + "\n")[1].splitlines()
    assert len(footer) == NO_ROWS_LINE_CAP + 1 and "2 more empty searches" in footer[-1]


def test_a_comma_list_of_figures_is_not_fused_into_one():
    # 25965109: "4720,4722,..." read as 47204722... and three observations were dropped.
    from smartops.subagent_analysts.analyze import _figures

    assert {"4720", "4722", "1126"} <= _figures("EventCodes 4720,4722 across 1,126 events")
    assert _figures("EventCodes 4720,4722") == {"4720", "4722"}
