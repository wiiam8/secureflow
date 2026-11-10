import copy
import re

import pytest

from app.database import SessionLocal
from app.models import ProjectMember, User
from tests.conftest import CLEAN, load, make_user

CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def token(client, path="/login"):
    return CSRF.search(client.get(path).text).group(1)


def web_login(client, username="admin", password="Admin-Password-123"):
    r = client.post("/login", data={"username": username, "password": password, "csrf_token": token(client)})
    assert r.status_code == 303, r.text[:200]


def leak():
    out = load("gitleaks_real_UNSANITIZED.json")
    for x in out:
        x.pop("Secret"), x.pop("Match")
    return out


@pytest.fixture
def populated(client, pipeline):
    pipeline.run({"bandit": load("bandit_real.json"), "gitleaks": leak(), "pip-audit": load("pip_audit_real.json")})
    web_login(client)
    return client


def test_login_flow_and_redirect_when_anonymous(client):
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/projects/1").status_code == 303
    r = client.post("/login", data={"username": "admin", "password": "bad", "csrf_token": token(client)})
    assert r.status_code == 401 and "Invalid username or password" in r.text
    web_login(client)
    assert client.get("/").status_code == 200


def test_every_page_renders(populated):
    c = populated
    for path in ["/", "/projects/new", "/projects/1", "/projects/1/runs", "/runs/1", "/projects/1/findings",
                 "/projects/1/findings?severity=High&scope=all&category=secret", "/findings/1", "/projects/1/controls",
                 "/projects/1/audit", "/projects/1/settings", "/admin/users"]:
        r = c.get(path)
        assert r.status_code == 200, path
        assert "Traceback" not in r.text, path


def test_run_page_explains_the_decision(populated):
    html = populated.get("/runs/1").text
    assert "BLOCK" in html and "Why this decision" in html and "B2" in html
    assert "generic-api-key" in html and "7c9e2f41ab8d03e65f1a9b4c7d2e8f30" not in html
    assert "SuperSecret123" not in html


def test_finding_page_shows_risk_formula(populated):
    html = populated.get("/findings/1").text
    assert "R = S × C × E" in html and "neutral" in html.lower()


def test_evidence_download(populated):
    r = populated.get("/runs/1/evidence.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    ev = r.json()
    assert ev["decision"]["result"] == "BLOCK" and ev["policy"]["version"] == 1 and len(ev["evidence_sha256"]) == 64
    assert "does not establish compliance" in ev["disclaimer"] or "do not establish compliance" in ev["disclaimer"]
    assert ev["audit_trail"] and ev["findings"][0]["controls"]


def test_no_inline_script_or_style_so_csp_holds(populated):
    for path in ["/", "/projects/1", "/runs/1", "/findings/1", "/projects/1/settings", "/projects/1/controls"]:
        html = populated.get(path).text
        assert not re.search(r"<script(?![^>]*(src=|type=\"application/json\"))", html), path
        assert " style=" not in html and "onclick=" not in html, path


# ---- CSRF -------------------------------------------------------------------------------------
def test_state_changing_posts_require_csrf(populated):
    c = populated
    for path, data in [("/projects/new", {"name": "x"}), ("/projects/1/tokens", {"label": "x"}),
                       ("/projects/1/policy", {"policy_json": "{}"}), ("/findings/1/status", {"status": "In Review"}),
                       ("/admin/users", {"username": "bob", "email": "b@x.org", "password": "x" * 12}),
                       ("/logout", {})]:
        assert c.post(path, data=data).status_code == 403, path
        assert c.post(path, data={**data, "csrf_token": "forged"}).status_code == 403, path
    assert c.get("/").status_code == 200  # still logged in: nothing happened


def test_login_form_also_needs_csrf(client):
    assert client.post("/login", data={"username": "admin", "password": "Admin-Password-123"}).status_code == 403


# ---- XSS --------------------------------------------------------------------------------------
def test_scanner_content_is_html_escaped(client, pipeline):
    evil = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    rep = {"results": [{"check_id": "r.evil", "path": evil, "start": {"line": 1},
                        "extra": {"severity": "ERROR", "message": evil}}]}
    pipeline.run({"bandit": {"results": []}, "gitleaks": [], "semgrep": rep})
    web_login(client)
    for path in ["/projects/1/findings", "/findings/1", "/runs/1"]:
        html = client.get(path).text
        assert "<script>alert(1)</script>" not in html and "<img src=x" not in html, path
        assert "&lt;script&gt;" in html or "&lt;img" in html or "evil" in html


def test_ci_run_url_is_a_safe_link(client, pipeline):
    pipeline.run(CLEAN, ci_run_url="https://github.com/o/r/actions/runs/1")
    web_login(client)
    html = client.get("/runs/1").text
    assert 'href="https://github.com/o/r/actions/runs/1" target="_blank" rel="noopener noreferrer"' in html


# ---- actions ----------------------------------------------------------------------------------
def test_token_is_shown_once_then_never_again(populated):
    t = token(populated, "/projects/1/settings")
    r = populated.post("/projects/1/tokens", data={"label": "gh", "csrf_token": t})
    raw = re.search(r"sf_[A-Za-z0-9_\-]{20,}", r.text).group(0)
    assert "shown only once" in r.text
    assert raw not in populated.get("/projects/1/settings").text


def test_policy_editor_saves_and_rejects(populated):
    import json
    t = token(populated, "/projects/1/settings")
    bad = populated.post("/projects/1/policy", data={"policy_json": "{not json", "csrf_token": t})
    assert bad.status_code == 422 and "Policy not saved" in bad.text
    bad = populated.post("/projects/1/policy", data={"policy_json": json.dumps({"required_scanners": ["nope"]}), "csrf_token": t})
    assert bad.status_code == 422 and "unknown scanner" in bad.text
    from app.services.policy_engine import DEFAULT_POLICY
    pol = copy.deepcopy(DEFAULT_POLICY)
    pol["name"] = "Edited in UI"
    ok = populated.post("/projects/1/policy", data={"policy_json": json.dumps(pol), "comment": "tweak", "csrf_token": t})
    assert ok.status_code == 303
    assert "Edited in UI" in populated.get("/projects/1/settings").text


def test_status_form_roundtrip_and_validation_message(populated):
    t = token(populated, "/findings/1")
    r = populated.post("/findings/1/status", data={"status": "Accepted", "reason": "x", "csrf_token": t})
    assert r.status_code == 303
    assert "at least 10 characters" in populated.get("/findings/1").text or "cannot be accepted" in populated.get("/findings/1").text


def test_admin_creates_user_with_validation(populated):
    t = token(populated, "/admin/users")
    populated.post("/admin/users", data={"username": "ab", "email": "x", "password": "short", "role": "developer", "csrf_token": t})
    with SessionLocal() as db:
        assert db.query(User).filter_by(username="ab").count() == 0
    populated.post("/admin/users", data={"username": "newdev", "email": "n@x.org", "password": "A-Long-Password-1", "role": "developer", "csrf_token": t})
    with SessionLocal() as db:
        assert db.query(User).filter_by(username="newdev").one().role == "developer"


def test_developer_web_permissions(client, pipeline):
    pipeline.run(CLEAN)
    make_user("dev", "developer")
    web_login(client, "dev", "Password-12345")
    assert client.get("/").status_code == 200 and "demo" not in client.get("/").text  # not a member
    assert client.get("/projects/1").status_code == 404
    with SessionLocal() as db:
        db.add(ProjectMember(project_id=1, user_id=db.query(User).filter_by(username="dev").one().id)); db.commit()
    assert client.get("/projects/1").status_code == 200
    assert client.get("/admin/users").status_code == 403
    assert client.get("/projects/1/audit").status_code == 403
    assert client.get("/projects/new").status_code == 403
    t = token(client, "/projects/1/settings")
    assert client.post("/projects/1/tokens", data={"label": "x", "csrf_token": t}).status_code == 403
    assert "Generate token" not in client.get("/projects/1/settings").text


def test_logout_ends_the_session(client):
    web_login(client)
    client.post("/logout", data={"csrf_token": token(client, "/")})
    assert client.get("/", follow_redirects=False).status_code == 303
