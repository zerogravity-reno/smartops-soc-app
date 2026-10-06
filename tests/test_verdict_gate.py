from webapp.services.run_trace import verdict_gate

PLAN = {"hypotheses": [{"id": "H1", "verdict": "TRUE_POSITIVE"}, {"id": "H2", "verdict": "BENIGN"}]}


def test_reached_with_a_cited_finding():
    out = verdict_gate({"hypothesis_scores": {"H1": 90, "H2": "40"}, "evidence_refs": ["T3:endpoint"],
                        "status": "REQUIRES_INVESTIGATION", "follow_up_tasks": [{"question": "q"}]}, PLAN)
    assert out["status"] == "VERDICT_REACHED"
    assert out["verdict"] == "TRUE_POSITIVE"  # filled from the top hypothesis
    assert out["follow_up_tasks"] == []


def test_confident_but_uncited_investigates_again():
    out = verdict_gate({"hypothesis_scores": {"H1": 95, "H2": 10}, "evidence_refs": ["ALERT:rule_name"],
                        "status": "VERDICT_REACHED", "verdict": "TRUE_POSITIVE"}, PLAN)
    assert out["status"] == "REQUIRES_INVESTIGATION"
    assert out["evidence_gaps"]


def test_close_scores_investigate_again():
    out = verdict_gate({"hypothesis_scores": {"H1": 88, "H2": 80}, "evidence_refs": ["T3:endpoint"],
                        "status": "VERDICT_REACHED"}, PLAN)
    assert out["status"] == "REQUIRES_INVESTIGATION"
    assert "evidence_gaps" not in out
    assert verdict_gate({}, PLAN)["status"] == "REQUIRES_INVESTIGATION"
