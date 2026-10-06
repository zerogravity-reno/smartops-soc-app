"""One size budget for a batch, water-filled across every task's domains (B9)."""

from contracts import AnalystPayloadBatch, DomainJudgement, HypothesisFindings, pack_for_analyst


def _task(task_id, narrative, summaries):
    return HypothesisFindings(
        task_id=task_id, run_id="r", hypothesis_id=task_id, hypothesis="h",
        findings=[DomainJudgement(domain="endpoint", narrative=narrative, summaries=summaries)],
    )


def test_a_long_narrative_task_still_gets_summaries_and_the_batch_fits():
    small = _task("t1", "short.", ["~ small#1 " + "x" * 80])
    big = _task("t2", "y" * 3000, [f"~ processes#{i} " + "z" * 300 for i in range(1, 6)])
    budget = 4200

    payloads = pack_for_analyst([small, big], budget)

    big_sent = payloads[1].findings[0].summaries
    assert big_sent[0].startswith("~ processes#1")  # cited-first order kept
    assert big_sent[-1].startswith("… ")  # and the rest are counted, not dropped silently
    assert payloads[0].findings[0].summaries == small.findings[0].summaries  # the small need is met in full
    assert len(AnalystPayloadBatch(batch_id="b", payloads=payloads).model_dump_json(indent=2)) <= budget + 200


def test_no_budget_sends_everything():
    big = _task("t2", "y" * 3000, [f"~ s#{i}" for i in range(5)])
    assert pack_for_analyst([big])[0].findings[0].summaries == big.findings[0].summaries
