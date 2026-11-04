"""One size budget for a batch, measured as the Analyst reads it (B9, B14, B51).

Since B14 (2026-11-04) only the explanation crosses: each domain's observations.
The code evidence (summaries, facts) stays in the record for the Broker's review."""

import json
from pathlib import Path

from contracts import AnalystPayloadBatch, DomainRecord, HypothesisFindings, pack_for_analyst


def _sent(payloads) -> str:
    """What `analyst.py:566` puts in the prompt: the batch, indented and ASCII-escaped."""
    return json.dumps(AnalystPayloadBatch(batch_id="d6b48ef0-L2", payloads=payloads).model_dump(mode="json"), indent=2)


def _task(task_id, observations=(), summaries=(), facts=()):
    return HypothesisFindings(
        task_id=task_id, run_id="r", hypothesis_id=task_id, hypothesis="h",
        findings=[DomainRecord(domain="endpoint", observations=list(observations),
                               summaries=list(summaries), facts=list(facts))],
    )


def test_no_budget_sends_every_observation_and_no_evidence():
    big = _task("t2", [f"line {i} [processes#1]" for i in range(5)], summaries=["~ s#1"], facts=["~ f"])
    assert pack_for_analyst([big])[0].findings[0].model_dump() == {
        "domain": "endpoint", "observations": big.findings[0].observations}


def test_the_heaviest_domain_is_cut_first_and_the_small_one_stays_whole():
    small = _task("t1", ["one short line [processes#1]"])
    big = _task("t2", [f"line {i} " + "z" * 300 + " [processes#1]" for i in range(6)])
    budget = len(_sent(pack_for_analyst([small, big]))) - 700

    payloads = pack_for_analyst([small, big], budget)

    big_sent = payloads[1].findings[0].observations
    assert big_sent[0].startswith("line 0")  # order kept
    assert big_sent[-1].startswith("… ") and "observations omitted" in big_sent[-1]  # counted, not silent
    assert payloads[0].findings[0].observations == small.findings[0].observations
    assert len(_sent(payloads)) <= budget


def test_no_domain_loses_its_last_line():
    tasks = [_task(f"t{i}", [f"first {i} " + "a" * 200, f"second {i} " + "b" * 200]) for i in range(4)]

    payloads = pack_for_analyst(tasks, 1)

    assert all(p.findings[0].observations[0].startswith(f"first {i}") for i, p in enumerate(payloads))


def test_a_download_explained_by_the_sub_analyst_crosses_whole():
    # d6b48ef0: the narrative said "update downloads"; the Broker's review now sends that back.
    line = ("HOST-1 ran powershell.exe from OneDrive.exe, which downloads win-agent-2.4.1.bin from "
            "192.168.77.211 to $env:TEMP\\svcupdate.dat [processes#1]")
    t3 = _task("d6b48ef0-L2-T3", [line, *(f"other {i} " + "x" * 300 + " [processes#2]" for i in range(30))])

    sent = pack_for_analyst([t3], 13_272)[0].findings[0].observations

    assert sent[0] == line and len(_sent(pack_for_analyst([t3], 13_272))) <= 13_272


def test_a_domain_with_rows_and_no_account_says_so():
    # 3e7613cf: all 8 tasks reached the Analyst with rows and no observation at all.
    task = _task("t1", summaries=["~ processes#1 — computed over all 4 rows:"])

    sent = pack_for_analyst([task])[0]

    assert sent.findings[0].observations == ["Explanation incomplete for endpoint: evidence remains untranslated."]
    assert sent.no_rows == []  # rows reached it: a failed translation is not "no rows"


def test_a_domain_no_row_reached_is_not_sent_but_named_in_one_line():
    # d6b48ef0: 14 of 21 domains crossed as empty blocks, ~2.2k of the budget (B51).
    from contracts import DomainGap, RetrievalSummary

    task = HypothesisFindings(
        task_id="t1", run_id="r", hypothesis_id="t1", hypothesis="h",
        findings=[DomainRecord(domain="identity"), DomainRecord(domain="network"),
                  DomainRecord(domain="endpoint", observations=["PowerShell ran [processes#1]."])],
    )
    sent = pack_for_analyst([task])[0]

    assert [f.domain for f in sent.findings] == ["endpoint"]
    assert sent.no_rows == ["No rows in this task's results belong to identity, network."]

    # A domain left empty because its source was down is already said by not_searched.
    down = DomainGap(family="siem", reason="no_tools_resolved", served_domains=["network"], unanswered_domains=["network"])
    sent = pack_for_analyst([task.model_copy(update={"retrieval": RetrievalSummary(gaps=[down])})])[0]
    assert sent.no_rows == ["No rows in this task's results belong to identity."]


FIXTURE = Path(__file__).parent / "fixtures" / "d6b48ef0_L2.json"


def test_d6b48ef0_fits_the_budget_with_an_explanation_for_every_domain_with_rows():
    tasks = [HypothesisFindings.model_validate(t) for t in json.loads(FIXTURE.read_text(encoding="utf-8"))]

    payloads = pack_for_analyst(tasks, 13_272)

    assert len(_sent(payloads)) <= 13_272
    assert all(f.observations for p in payloads for f in p.findings)
