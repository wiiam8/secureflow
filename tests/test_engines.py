import copy

import pytest

from app.services.policies import PolicyValidationError, validate_policy
from app.services.policy_engine import DEFAULT_POLICY, EvalItem, PolicyRules, RiskConfig, evaluate
from app.services.risk_engine import compute_risk


def item(sev="Low", cat="code", scanner="bandit", risk=1.0, fid=1, excepted=False):
    return EvalItem(fid, "t", sev, cat, scanner, risk, "a.py:1", excepted=excepted, exception_note="n")


def pol(**over):
    d = copy.deepcopy(DEFAULT_POLICY)
    d.update(over)
    return PolicyRules.model_validate(d)


# ---- risk model: documented neutral defaults (R = S x C x E) ---------------------------------
def test_risk_neutral_defaults_when_information_is_missing():
    score, f = compute_risk("High", None, "code", "a.py", None, RiskConfig())
    assert (f["S"], f["C"], f["E"], score) == (4, 1.0, 1.0, 4.0)
    assert "neutral" in f["C_note"] and f["E_parts"][0]["value"] == 1.0


def test_risk_every_factor_is_explained():
    score, f = compute_risk("Critical", "LOW", "secret", "app/api/x.py", "1.2",
                            RiskConfig(exposed_paths=["app/api/*"]))
    assert f["S"] == 5 and f["C"] == 0.5
    assert f["E"] == pytest.approx(1.5 * 1.5 * 1.2)
    assert {p["name"] for p in f["E_parts"]} == {"category 'secret'", "exposed path", "fix available"}
    assert score == pytest.approx(5 * 0.5 * 1.5 * 1.5 * 1.2, abs=0.01)


def test_risk_exposure_is_capped():
    _, f = compute_risk("High", "HIGH", "secret", "x/y", "1", RiskConfig(exposed_paths=["x/*"], exposed_weight=3, category_weights={"secret": 3}))
    assert f["E"] == 3.0


def test_risk_unknown_confidence_is_neutral():
    _, f = compute_risk("Low", "BANANA", "code", None, None, RiskConfig())
    assert f["C"] == 1.0


# ---- policy engine ---------------------------------------------------------------------------
def test_pass_when_nothing_matches():
    out = evaluate(pol(), [item("Low")])
    assert out.decision == "PASS"


def test_critical_blocks_and_high_dependency_blocks():
    assert evaluate(pol(), [item("Critical")]).decision == "BLOCK"
    assert evaluate(pol(), [item("High", "dependency", "pip-audit")]).decision == "BLOCK"
    assert evaluate(pol(), [item("High", "secret", "gitleaks")]).decision == "BLOCK"


def test_high_code_finding_only_warns():
    out = evaluate(pol(), [item("High", "code")])
    assert out.decision == "WARN" and out.reasons[0]["rule"] == "W1"


def test_block_beats_warn_and_reasons_are_sorted_blocking_first():
    out = evaluate(pol(), [item("Medium", fid=1), item("Critical", fid=2)])
    assert out.decision == "BLOCK"
    assert out.reasons[0]["type"] == "blocking" and out.reasons[0]["finding_id"] == 2


def test_excepted_finding_does_not_block_but_is_still_reported():
    out = evaluate(pol(), [item("Critical", excepted=True)])
    assert out.decision == "PASS"
    assert any(r["type"] == "excepted" and "would have triggered BLOCK" in r["message"] for r in out.reasons)


def test_min_risk_condition():
    p = pol(blocking_rules=[{"id": "R", "min_risk": 10}], warning_rules=[])
    assert evaluate(p, [item(risk=9.9)]).decision == "PASS"
    assert evaluate(p, [item(risk=10)]).decision == "BLOCK"


def test_scanner_notes_degrade_pass_to_warn():
    out = evaluate(pol(), [], ["Bandit could not analyse 2 file(s)"])
    assert out.decision == "WARN"
    assert evaluate(pol(warn_on_scanner_notes=False), [], ["x"]).decision == "PASS"


def test_default_decision_warn():
    assert evaluate(pol(default_decision="WARN"), []).decision == "WARN"


# ---- policy validation: bad policies are rejected, never silently accepted --------------------
@pytest.mark.parametrize("patch", [
    {"required_scanners": ["nessus"]},
    {"blocking_rules": [{"id": "X"}]},                               # rule without a condition
    {"blocking_rules": [{"severity": ["Catastrophic"]}]},
    {"blocking_rules": [{"severity": ["High"], "typo_field": 1}]},   # unknown field
    {"default_decision": "BLOCK"},
    {"integration_error": {"behavior": "FAIL_OPEN"}},                # fail-open is not an option
    {"risk": {"neutral_confidence": 0}},
    {"exceptions": {"max_days": 0}},
    {"sla_days": {"High": 0}},
    {"unknown_top_level": True},
])
def test_invalid_policies_rejected(patch):
    d = copy.deepcopy(DEFAULT_POLICY)
    d.update(patch)
    with pytest.raises(PolicyValidationError):
        validate_policy(d)


def test_scanner_names_are_normalised_in_policy():
    d = copy.deepcopy(DEFAULT_POLICY)
    d["required_scanners"] = ["Pip_Audit", "BANDIT", "bandit"]
    assert validate_policy(d).required_scanners == ["pip-audit", "bandit"]
