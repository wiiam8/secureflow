"""End-to-end decision pipeline through the real HTTP API."""
import copy

import pytest

from app.database import SessionLocal
from app.models import AuditEvent, Finding, ScanReport
from tests.conftest import CLEAN, bearer, load

BANDIT = "bandit_real.json"
LEAK = "gitleaks_real_UNSANITIZED.json"
SECRET = "7c9e2f41ab8d03e65f1a9b4c7d2e8f30"


def clean_gitleaks():
    """What the CI script sends: no Secret/Match, HMAC fingerprint added."""
    out = load(LEAK)
    for x in out:
        x.pop("Secret"), x.pop("Match")
        x["SecretFingerprint"] = "aaaabbbbccccdddd"
    return out


def bandit_only(*rules):
    d = copy.deepcopy(load(BANDIT))
    d["results"] = [r for r in d["results"] if r["test_id"] in rules]
    return d


# ---- decisions --------------------------------------------------------------------------------
def test_clean_run_passes(pipeline):
    r = pipeline.run(CLEAN)
    body = r.json()
    assert r.status_code == 200 and body["decision"] == "PASS" and body["exit_code"] == 0
    assert body["policy_version"] == 1 and body["dashboard_url"].endswith(f"/runs/{body['run_id']}")


def test_real_reports_block_with_explanation(pipeline):
    r = pipeline.run({"bandit": load(BANDIT), "gitleaks": clean_gitleaks(), "pip-audit": load("pip_audit_real.json")})
    body = r.json()
    assert body["decision"] == "BLOCK" and body["exit_code"] == 1
    blocking = [x for x in body["reasons"] if x["type"] == "blocking"]
    assert {x["rule"] for x in blocking} == {"B2"}
    assert any(x["category"] == "secret" for x in blocking)
    assert sum(1 for x in blocking if x["category"] == "dependency") == 23
    assert body["summary"]["total"] == 8 + 1 + 23


def test_high_code_findings_only_warn(pipeline):
    r = pipeline.run({"bandit": bandit_only("B602", "B324"), "gitleaks": []})
    assert r.json()["decision"] == "WARN" and r.json()["exit_code"] == 0


# ---- FAIL-CLOSED: an integration problem is never a PASS ---------------------------------------
@pytest.mark.parametrize("name,reports,client_errors", [
    ("required scanner missing", {"bandit": {"results": []}}, []),
    ("no report at all", {}, []),
    ("malformed bandit", {"bandit": {"oops": 1}, "gitleaks": []}, []),
    ("bandit is not json object", {"bandit": [1, 2], "gitleaks": []}, []),
    ("malformed gitleaks", {"bandit": {"results": []}, "gitleaks": {"x": 1}}, []),
    ("null report", {"bandit": None, "gitleaks": []}, []),
    ("unsupported scanner", {"bandit": {"results": []}, "gitleaks": [], "nessus": {}}, []),
    ("CI could not read a file", {"bandit": {"results": []}}, [{"scanner": "gitleaks", "error": "report file not found"}]),
])
def test_integration_errors_are_ERROR_never_PASS(pipeline, name, reports, client_errors):
    r = pipeline.run(reports, client_errors=client_errors)
    body = r.json()
    assert r.status_code == 200, name
    assert body["decision"] == "ERROR" and body["exit_code"] == 2, name
    assert any(x["type"] == "integration_error" for x in body["reasons"]), name


def test_error_run_does_not_resolve_existing_findings(pipeline):
    pipeline.run({"bandit": bandit_only("B602"), "gitleaks": []})
    bad = pipeline.run({"bandit": {"broken": True}, "gitleaks": []}).json()
    assert bad["decision"] == "ERROR"
    with SessionLocal() as db:
        f = db.query(Finding).filter_by(rule_id="B602").one()
        assert f.present and f.status == "Open"  # a broken report must not make findings vanish


def test_duplicate_scanner_in_one_upload_is_error(pipeline):
    r = pipeline.run().json() if False else pipeline.client.post("/api/v1/ingest", headers=pipeline.headers, json={
        "ci_run_id": "9", "commit_sha": "abc1234", "branch": "main",
        "reports": [{"scanner": "bandit", "report": {"results": []}}, {"scanner": "bandit", "report": {"results": []}},
                    {"scanner": "gitleaks", "report": []}]})
    assert r.json()["decision"] == "ERROR"


# ---- secrets are never stored --------------------------------------------------------------------
def test_secret_value_is_never_persisted_anywhere(pipeline, client, admin, project):
    # Even if a client forgets to strip Secret/Match, the adapter never reads them.
    raw = load(LEAK)
    pipeline.run({"bandit": load(BANDIT), "gitleaks": raw})
    from tests.conftest import db_dump
    dump = db_dump()
    assert "generic-api-key" in dump  # the finding itself IS stored...
    assert SECRET not in dump  # ...but never the secret value
    assert "SuperSecret123" not in dump  # Bandit's hardcoded password
    ev = client.get("/api/v1/runs/1/evidence", headers=admin).text
    assert SECRET not in ev and "SuperSecret123" not in ev


# ---- idempotency ------------------------------------------------------------------------------
def test_same_ci_run_is_evaluated_once(pipeline):
    a = pipeline.run(CLEAN, run_id=77).json()
    b = pipeline.run(CLEAN, run_id=77).json()
    assert b["replay"] is True and b["run_id"] == a["run_id"] and b["decision"] == a["decision"]
    c = pipeline.run(CLEAN, run_id=77, ci_run_attempt=2).json()
    assert c["run_id"] != a["run_id"]  # a re-run attempt is a new evaluation


# ---- reconciliation: new / persisting / resolved / reappeared ---------------------------------
def lifecycle(client, admin, pid):
    return {f["rule_id"]: f for f in client.get(f"/api/v1/projects/{pid}/findings?limit=500", headers=admin).json()}


def test_finding_lifecycle_across_runs(pipeline, client, admin, project):
    pid = project[0]
    r1 = pipeline.run({"bandit": bandit_only("B602", "B324"), "gitleaks": []}).json()
    assert (r1["summary"]["new"], r1["summary"]["persisting"]) == (2, 0)

    r2 = pipeline.run({"bandit": bandit_only("B602"), "gitleaks": []}).json()   # B324 fixed
    assert (r2["summary"]["persisting"], r2["summary"]["resolved"]) == (1, 1)
    f = lifecycle(client, admin, pid)
    assert f["B324"]["status"] == "Resolved" and f["B324"]["present"] is False
    assert f["B602"]["status"] == "Open" and f["B602"]["seen_count"] == 2

    r3 = pipeline.run({"bandit": bandit_only("B602", "B324"), "gitleaks": []}).json()  # B324 is back
    assert r3["summary"]["reappeared"] == 1
    assert lifecycle(client, admin, pid)["B324"]["status"] == "Open"


def test_branches_are_tracked_independently(pipeline, client, admin, project):
    pipeline.run({"bandit": bandit_only("B602"), "gitleaks": []}, branch="main")
    r = pipeline.run({"bandit": bandit_only("B602"), "gitleaks": []}, branch="feature/x").json()
    assert r["summary"]["new"] == 1  # new on this branch
    assert len(client.get(f"/api/v1/projects/{project[0]}/findings", headers=admin).json()) == 2


def test_one_scanner_report_does_not_resolve_another_scanners_findings(pipeline, client, admin, project):
    pipeline.run({"bandit": bandit_only("B602"), "gitleaks": clean_gitleaks()})
    pipeline.run({"bandit": bandit_only("B602"), "gitleaks": []})  # secret removed
    f = lifecycle(client, admin, project[0])
    assert f["generic-api-key"]["status"] == "Resolved" and f["B602"]["status"] == "Open"


# ---- policy versioning ------------------------------------------------------------------------
def test_policy_change_applies_to_next_run_and_is_versioned(pipeline, client, admin, project):
    pid = project[0]
    reports = {"bandit": bandit_only("B602"), "gitleaks": []}
    assert pipeline.run(reports).json()["decision"] == "WARN"
    pol = client.get(f"/api/v1/projects/{pid}/policy", headers=admin).json()["rules"]
    pol["blocking_rules"].append({"id": "B3", "description": "no High code", "severity": ["High"], "categories": ["code"]})
    assert client.put(f"/api/v1/projects/{pid}/policy?comment=stricter", json=pol, headers=admin).json()["version"] == 2
    r = pipeline.run(reports).json()
    assert r["decision"] == "BLOCK" and r["policy_version"] == 2
    assert client.get(f"/api/v1/runs/{r['run_id']}", headers=admin).json()["policy_version"] == 2


def test_invalid_policy_is_rejected_with_reasons(client, admin, project):
    r = client.put(f"/api/v1/projects/{project[0]}/policy", json={"required_scanners": ["nope"]}, headers=admin)
    assert r.status_code == 422 and "unknown scanner" in str(r.json())
    assert client.get(f"/api/v1/projects/{project[0]}/policy", headers=admin).json()["version"] == 1


def test_required_scanners_follow_policy(pipeline, client, admin, project):
    pid = project[0]
    pol = client.get(f"/api/v1/projects/{pid}/policy", headers=admin).json()["rules"]
    pol["required_scanners"] = ["bandit", "gitleaks", "pip-audit"]
    client.put(f"/api/v1/projects/{pid}/policy", json=pol, headers=admin)
    r = pipeline.run(CLEAN).json()
    assert r["decision"] == "ERROR" and any("pip-audit" in x["message"] for x in r["reasons"])


# ---- audit trail ------------------------------------------------------------------------------
def test_actions_are_audited(pipeline, project):
    pipeline.run(CLEAN)
    with SessionLocal() as db:
        actions = {e.action for e in db.query(AuditEvent).all()}
    assert {"project.created", "token.created", "report.received", "decision.made", "policy.changed"} <= actions
