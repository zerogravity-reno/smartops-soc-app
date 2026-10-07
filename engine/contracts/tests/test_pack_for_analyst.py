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


def test_observations_give_way_when_narratives_fill_the_budget():
    # c7dbf51d: narratives plus observations were 25.9k of 20.7k, so every summary went.
    def task(task_id, n_obs):
        return HypothesisFindings(
            task_id=task_id, run_id="r", hypothesis_id=task_id, hypothesis="h",
            findings=[DomainJudgement(domain="endpoint", narrative="n" * 500,
                                      observations=[f"obs {i} " + "o" * 200 for i in range(n_obs)])],
        )
    budget = 3000

    payloads = pack_for_analyst([task("t1", 2), task("t2", 20)], budget)

    assert [p.findings[0].narrative for p in payloads] == ["n" * 500] * 2  # narratives always cross
    assert len(payloads[0].findings[0].observations) == 2  # the smaller domain is left alone
    kept = payloads[1].findings[0].observations
    assert kept[0].startswith("obs 0 ") and kept[-1].startswith("… ")  # tail cut, and counted
    assert len(AnalystPayloadBatch(batch_id="b", payloads=payloads).model_dump_json(indent=2)) <= budget + 200
