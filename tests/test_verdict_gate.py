from smartops.analyst import evaluation_limits, follow_up_tasks, verdict_gate

PLAN = {"hypotheses": [{"id": "H1", "verdict": "TRUE_POSITIVE"}, {"id": "H2", "verdict": "BENIGN"}]}
PAYLOADS = [
    {"task_id": "r-L2-T2", "hypothesis": "What set the RunOnce value?",
     "findings": [{"domain": "endpoint", "narrative": "", "observations": ["setup.exe wrote it [registry_events#2]"]}]},
    {"task_id": "r-L2-T3", "hypothesis": "Who logged on?",
     "findings": [{"domain": "endpoint", "narrative": "n", "observations": ["o"]},
                  {"domain": "network", "narrative": "", "observations": []}]},
]
RUNS = [
    {"task_id": "r-L2-T2", "steps": [{"step_id": "siem", "completed": True, "status": "ok"},
                                     {"step_id": "vt", "completed": False, "status": "rejected"}]},
    {"task_id": "r-L2-T3", "steps": [{"step_id": "siem", "completed": True, "status": "ok"}]},
]


def gate(refs, scores=None, **synth):
    return verdict_gate({"hypothesis_scores": scores or {"H1": 90, "H2": "40"}, "evidence_refs": refs, **synth},
                        PLAN, PAYLOADS, RUNS)


def test_reached_with_a_cited_finding():
    out = gate(["T3:endpoint"], status="REQUIRES_INVESTIGATION", follow_up_tasks=[{"question": "q"}])
    assert out["status"] == "VERDICT_REACHED"
    assert out["verdict"] == "TRUE_POSITIVE"  # filled from the top hypothesis
    assert out["follow_up_tasks"] == []
    assert gate(["r-L2-T3:endpoint"])["status"] == "VERDICT_REACHED"  # full task id


def test_confident_but_uncited_reaches_a_verdict():
    out = gate(["ALERT:rule_name"], {"H1": 95, "H2": 10}, status="VERDICT_REACHED", verdict="TRUE_POSITIVE")
    assert out["status"] == "VERDICT_REACHED"


def test_close_scores_investigate_again():
    out = gate(["T3:endpoint"], {"H1": 88, "H2": 80}, status="VERDICT_REACHED")
    assert out["status"] == "REQUIRES_INVESTIGATION"
    assert "evidence_gaps" not in out
    assert verdict_gate({}, PLAN)["status"] == "REQUIRES_INVESTIGATION"


def test_refs_are_informational():
    # A missing or stale citation no longer turns an otherwise gated verdict into
    # an endless investigation loop.
    for ref in ("T3:user", "T3:network", "T9:endpoint"):
        out = gate(["T3:endpoint", ref])
        assert out["status"] == "VERDICT_REACHED", ref


def test_gaps_become_follow_ups_when_synthesis_sent_none():
    sent = [{"entity": [{"type": "host", "value": "h"}], "time_window": {"start": "2026-10-06T00:00:00Z", "end": "2026-10-06T01:00:00Z"}}]
    tasks = follow_up_tasks([], sent, ["Who logged on?", "", 3])
    assert [(t["task_id"], t["question"]) for t in tasks] == [("G1", "Who logged on?")]
    assert follow_up_tasks([{"task_id": "FU1", "question": "q"}], sent, ["gap"])[0]["task_id"] == "FU1"


def test_handoff_budget_leaves_the_analyst_its_generation():
    from smartops.subagent_analysts import packing
    from smartops import analyst
    assert packing._ANALYST_GENERATION_RESERVE == analyst.MAX_GEN_LEN
    assert packing._ANALYST_ROUNDS == analyst.FULL_ROUNDS


def test_evaluation_limits_keep_unanswerable_questions_out_of_evidence():
    limits = evaluation_limits([{
        "unanswerable": ["No connected source holds this: Is 192.168.40.211 registered? (asset inventory)"]
    }])
    assert "unknown, not negative findings" in limits
    assert "192.168.40.211 registered" in limits
    assert evaluation_limits([{}]) == ""


def test_gate_rejects_negative_claim_from_an_unanswerable_source():
    out = verdict_gate(
        {"hypothesis_scores": {"H1": 95, "H2": 10},
         "verdict": "TRUE_POSITIVE",
         "verdict_reasoning": "Asset inventory lacks any update-server registration for 192.168.40.211."},
        PLAN,
        [{"unanswerable": [
            "No connected source holds this: Is 192.168.40.211 registered? (asset inventory)"
        ]}],
    )
    assert out["status"] == "REQUIRES_INVESTIGATION"
    assert out["verdict"] == "REQUIRES_INVESTIGATION"
    assert out["unsupported_claims"]


def test_an_older_round_is_compacted_to_questions_domains_and_its_evaluation():
    from smartops.analyst import compact_round
    rec = compact_round({"payloads": PAYLOADS}, {"hypothesis_scores": {"H1": 60}, "evidence_refs": ["T3:endpoint"],
                                                 "evidence_gaps": [], "verdict_reasoning": "long prose"})
    assert rec["tasks"][1] == {"task_id": "r-L2-T3", "question": "Who logged on?",
                               "domains_with_observations": ["endpoint"]}
    assert rec["evaluation"] == {"hypothesis_scores": {"H1": 60}, "evidence_refs": ["T3:endpoint"]}
    assert "narrative" not in str(rec)
