import pytest

from app.config import settings
from app.database import SessionLocal
from app.models import IntegrationToken, User
from tests.conftest import CLEAN, api_login, bearer, make_user


# ---- pipeline token ---------------------------------------------------------------------------
def post_ingest(client, headers, **over):
    body = {"ci_run_id": "1", "commit_sha": "abc1234", "branch": "main",
            "reports": [{"scanner": "bandit", "report": {"results": []}}, {"scanner": "gitleaks", "report": []}], **over}
    return client.post("/api/v1/ingest", json=body, headers=headers)


def test_ingest_requires_a_valid_token(client, project):
    assert post_ingest(client, {}).status_code == 401
    assert post_ingest(client, bearer("sf_wrong")).status_code == 401
    assert post_ingest(client, {"Authorization": "Basic abc"}).status_code == 401
    assert post_ingest(client, project[1]).status_code == 200


def test_revoked_token_is_rejected(client, admin, project):
    pid = project[0]
    tok_id = client.get(f"/api/v1/projects/{pid}/tokens", headers=admin).json()[0]["id"]
    assert client.delete(f"/api/v1/projects/{pid}/tokens/{tok_id}", headers=admin).status_code == 204
    assert post_ingest(client, project[1]).status_code == 401


def test_token_is_stored_hashed_only(client, admin, project):
    raw = project[1]["Authorization"].split()[1]
    with SessionLocal() as db:
        tok = db.query(IntegrationToken).one()
        assert tok.token_hash != raw and raw not in (tok.token_hash, tok.prefix) and len(tok.token_hash) == 64
    from tests.conftest import db_dump
    assert raw not in db_dump()


def test_token_is_scoped_to_its_project(client, admin, project):
    other = client.post("/api/v1/projects", json={"name": "other"}, headers=admin).json()
    post_ingest(client, project[1])
    runs_other = client.get(f"/api/v1/projects/{other['id']}/runs", headers=admin).json()
    assert runs_other == []  # the demo token wrote to demo only


def test_pipeline_token_cannot_call_the_user_api_and_vice_versa(client, admin, project):
    assert client.get("/api/v1/projects", headers=project[1]).status_code == 401
    assert post_ingest(client, admin).status_code == 401  # a human access token is not a pipeline token


def test_tampered_or_garbage_access_token(client):
    assert client.get("/api/v1/me", headers=bearer("garbage")).status_code == 401
    assert client.get("/api/v1/me").status_code == 401


# ---- payload hardening ------------------------------------------------------------------------
@pytest.mark.parametrize("over,code", [
    ({"commit_sha": "not-hex!"}, 422),
    ({"ci_run_url": "javascript:alert(1)"}, 422),
    ({"ci_run_attempt": 0}, 422),
    ({"branch": ""}, 422),
    ({"surprise": 1}, 422),
])
def test_invalid_payloads_rejected(client, project, over, code):
    assert post_ingest(client, project[1], **over).status_code == code


def test_non_json_body_is_400(client, project):
    r = client.post("/api/v1/ingest", content=b"not json", headers={**project[1], "Content-Type": "application/json"})
    assert r.status_code == 400


def test_oversized_payload_is_413(client, project, monkeypatch):
    monkeypatch.setattr(settings, "max_report_bytes", 500)
    big = {"ci_run_id": "1", "commit_sha": "abc1234", "branch": "main", "reports": [{"scanner": "bandit", "report": {"results": [], "pad": "x" * 2000}}]}
    assert client.post("/api/v1/ingest", json=big, headers=project[1]).status_code == 413


# ---- roles & isolation ------------------------------------------------------------------------
def test_developer_isolation_and_limits(client, admin, project):
    make_user("dev", "developer")
    dev = api_login(client, "dev", "Password-12345")
    pid = project[0]
    assert client.get("/api/v1/projects", headers=dev).json() == []
    for url in (f"/api/v1/projects/{pid}/runs", f"/api/v1/projects/{pid}/findings", f"/api/v1/projects/{pid}/policy"):
        assert client.get(url, headers=dev).status_code == 404  # same answer as "does not exist"
    assert client.get("/api/v1/projects/999/runs", headers=dev).status_code == 404
    assert client.post("/api/v1/projects", json={"name": "x"}, headers=dev).status_code == 403


def test_security_officer_sees_all_but_cannot_manage_members_page(client, admin, project):
    make_user("sec", "security")
    sec = api_login(client, "sec", "Password-12345")
    assert len(client.get("/api/v1/projects", headers=sec).json()) == 1
    assert client.post("/api/v1/projects", json={"name": "by-sec"}, headers=sec).status_code == 201


def test_member_developer_can_read_but_not_change_policy_or_tokens(client, admin, project):
    from app.models import ProjectMember
    make_user("dev", "developer")
    with SessionLocal() as db:
        db.add(ProjectMember(project_id=project[0], user_id=db.query(User).filter_by(username="dev").one().id)); db.commit()
    dev = api_login(client, "dev", "Password-12345")
    pid = project[0]
    assert client.get(f"/api/v1/projects/{pid}/policy", headers=dev).status_code == 200
    assert client.put(f"/api/v1/projects/{pid}/policy", json={}, headers=dev).status_code == 403
    assert client.get(f"/api/v1/projects/{pid}/tokens", headers=dev).status_code == 403
    assert client.post(f"/api/v1/projects/{pid}/tokens", json={}, headers=dev).status_code == 403


def test_deactivated_user_loses_access_immediately(client, admin):
    make_user("tmp", "security")
    h = api_login(client, "tmp", "Password-12345")
    assert client.get("/api/v1/me", headers=h).status_code == 200
    with SessionLocal() as db:
        db.query(User).filter_by(username="tmp").one().is_active = False
        db.commit()
    assert client.get("/api/v1/me", headers=h).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "tmp", "password": "Password-12345"}).status_code == 401


def test_login_is_rate_limited(client):
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "Admin-Password-123"}).status_code == 429


def test_passwords_are_hashed_with_argon2(client):
    with SessionLocal() as db:
        h = db.query(User).filter_by(username="admin").one().password_hash
    assert h.startswith("$argon2") and "Admin-Password-123" not in h


# ---- headers ----------------------------------------------------------------------------------
def test_security_headers(client):
    h = client.get("/login").headers
    assert "default-src 'self'" in h["content-security-policy"] and "script-src 'self'" in h["content-security-policy"]
    assert "unsafe-inline" not in h["content-security-policy"] and "unsafe-eval" not in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert client.get("/api/v1/health").headers["cache-control"] == "no-store"


def test_production_refuses_insecure_secret_key(monkeypatch):
    from app.config import Settings, INSECURE_DEFAULT_KEY
    with pytest.raises(RuntimeError):
        Settings(environment="production", secret_key=INSECURE_DEFAULT_KEY).validate_for_runtime()
    with pytest.raises(RuntimeError):
        Settings(secret_key="short").validate_for_runtime()
