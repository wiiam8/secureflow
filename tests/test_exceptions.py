"""GRC risk-acceptance workflow: justification, expiry, four-eyes roles, forbidden categories."""
from datetime import date, timedelta

import pytest

from app.database import SessionLocal
from app.models import AuditEvent, Finding
from tests.conftest import CLEAN, api_login, bearer, load, make_user
import copy


def b602():
    d = copy.deepcopy(load("bandit_real.json"))
    d["results"] = [r for r in d["results"] if r["test_id"] == "B602"]
    return {"bandit": d, "gitleaks": []}


@pytest.fixture
def strict(client, admin, project):
    """Policy that BLOCKS High code findings, so an exception has something to lift."""
    pid = project[0]
    pol = client.get(f"/api/v1/projects/{pid}/policy", headers=admin).json()["rules"]
    pol["blocking_rules"].append({"id": "B3", "description": "High code blocks", "severity": ["High"], "categories": ["code"]})
    client.put(f"/api/v1/projects/{pid}/policy", json=pol, headers=admin)
    return pid


def fid(rule="B602"):
    with SessionLocal() as db:
        return db.query(Finding).filter_by(rule_id=rule).first().id


def accept(client, headers, finding_id, days=30, reason="Mitigated by WAF rule, fix planned next sprint"):
    return client.patch(f"/api/v1/findings/{finding_id}/status", headers=headers,
                        json={"status": "Accepted", "reason": reason, "accepted_until": str(date.today() + timedelta(days=days))})


def test_accepted_risk_lifts_the_block_and_is_explained(client, admin, strict, pipeline):
    assert pipeline.run(b602()).json()["decision"] == "BLOCK"
    assert accept(client, admin, fid()).status_code == 200
    r = pipeline.run(b602()).json()
    assert r["decision"] == "PASS" and r["summary"]["excepted"] == 1
    assert any(x["type"] == "excepted" and "would have triggered BLOCK" in x["message"] for x in r["reasons"])


def test_exception_expiry_returns_finding_to_blocking(client, admin, strict, pipeline):
    pipeline.run(b602())
    accept(client, admin, fid())
    with SessionLocal() as db:  # time passes
        f = db.query(Finding).filter_by(rule_id="B602").one()
        f.accepted_until = date.today() - timedelta(days=1)
        db.commit()
    r = pipeline.run(b602()).json()
    assert r["decision"] == "BLOCK"
    with SessionLocal() as db:
        assert db.query(Finding).filter_by(rule_id="B602").one().status == "Open"
        assert db.query(AuditEvent).filter_by(action="exception.expired").count() == 1


@pytest.mark.parametrize("payload,expect", [
    ({"status": "Accepted", "reason": "short", "accepted_until": "+30"}, "justification"),
    ({"status": "Accepted", "reason": "A long enough justification", "accepted_until": None}, "expiry"),
    ({"status": "Accepted", "reason": "A long enough justification", "accepted_until": "-1"}, "expiry"),
    ({"status": "Accepted", "reason": "A long enough justification", "accepted_until": "+400"}, "more than 90"),
    ({"status": "Resolved", "reason": "x"}, "automatically"),
    ({"status": "Banana"}, "Unknown"),
])
def test_exception_requires_justification_and_bounded_expiry(client, admin, strict, pipeline, payload, expect):
    pipeline.run(b602())
    if payload.get("accepted_until"):
        n = int(payload["accepted_until"])
        payload["accepted_until"] = str(date.today() + timedelta(days=n))
    r = client.patch(f"/api/v1/findings/{fid()}/status", json=payload, headers=admin)
    assert r.status_code == 422 and expect in r.text, r.text


def test_leaked_secrets_cannot_be_accepted(client, admin, pipeline):
    leak = load("gitleaks_real_UNSANITIZED.json")
    for x in leak:
        x.pop("Secret"), x.pop("Match")
    pipeline.run({"bandit": {"results": []}, "gitleaks": leak})
    r = accept(client, admin, fid("generic-api-key"))
    assert r.status_code == 422 and "cannot be accepted" in r.text


def test_developer_can_flag_for_review_but_never_accept(client, admin, project, strict, pipeline):
    pipeline.run(b602())
    make_user("dev", "developer")
    dev = api_login(client, "dev", "Password-12345")
    client.post(f"/api/v1/projects/{project[0]}/tokens", json={}, headers=dev)  # no membership -> 404
    assert accept(client, dev, fid()).status_code == 404  # not a member: cannot even see it
    from app.database import SessionLocal as S
    from app.models import ProjectMember, User
    with S() as db:
        uid = db.query(User).filter_by(username="dev").one().id
        db.add(ProjectMember(project_id=project[0], user_id=uid)); db.commit()
    assert accept(client, dev, fid()).status_code == 403
    r = client.patch(f"/api/v1/findings/{fid()}/status", json={"status": "In Review", "reason": "looking"}, headers=dev)
    assert r.status_code == 200 and r.json()["status"] == "In Review"


def test_exception_is_inherited_on_other_branch_but_not_after_reappearing(client, admin, strict, pipeline):
    pipeline.run(b602(), branch="main")
    accept(client, admin, fid())
    r = pipeline.run(b602(), branch="feature/y").json()
    assert r["decision"] == "PASS" and r["summary"]["excepted"] == 1
    # fix it on main, then it comes back: the exception must NOT silently return
    pipeline.run(CLEAN, branch="main")
    r = pipeline.run(b602(), branch="main").json()
    assert r["summary"]["reappeared"] == 1 and r["decision"] == "BLOCK"


def test_policy_can_forbid_exceptions_entirely(client, admin, project, strict, pipeline):
    pid = project[0]
    pol = client.get(f"/api/v1/projects/{pid}/policy", headers=admin).json()["rules"]
    pol["exceptions"]["allowed"] = False
    client.put(f"/api/v1/projects/{pid}/policy", json=pol, headers=admin)
    pipeline.run(b602())
    assert accept(client, admin, fid()).status_code == 422


def test_status_changes_are_audited_with_reason(client, admin, strict, pipeline):
    pipeline.run(b602())
    accept(client, admin, fid(), reason="Compensating control documented in RISK-42")
    with SessionLocal() as db:
        ev = db.query(AuditEvent).filter_by(action="finding.status_changed").one()
    assert ev.actor == "user:admin" and ev.details["to"] == "Accepted" and "RISK-42" in ev.details["reason"]


def test_sla_overdue_is_computed_from_first_seen(client, admin, strict, pipeline):
    pipeline.run(b602())
    with SessionLocal() as db:
        f = db.query(Finding).filter_by(rule_id="B602").one()
        f.first_seen = f.first_seen - timedelta(days=45)  # High SLA is 30 days
        db.commit()
    from app.services.stats import project_overview
    from app.models import Project
    with SessionLocal() as db:
        assert project_overview(db, db.get(Project, strict))["overdue"] == 1
