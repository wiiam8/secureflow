import json
import os
import tempfile
from pathlib import Path

# Environment MUST be set before the app is imported (settings are read at import time).
_DB = Path(tempfile.mkdtemp(prefix="sf-tests-")) / "test.db"
os.environ.update(
    # TEST_DATABASE_URL=postgresql://user@host/db runs the whole suite on PostgreSQL (tables are dropped!).
    DATABASE_URL=os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{_DB}",
    SECRET_KEY="pytest-secret-key-0123456789",
    ADMIN_PASSWORD="Admin-Password-123",
    ENVIRONMENT="test",
    BASE_URL="http://testserver",
    LOGIN_MAX_ATTEMPTS="5",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app, bootstrap_admin  # noqa: E402
from app.models import User  # noqa: E402
from app.security import hash_password, login_limiter  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
ADMIN = ("admin", "Admin-Password-123")


def db_dump() -> str:
    """Every row of every table as text (backend-agnostic): used to prove secrets are never stored."""
    from sqlalchemy import select

    out = []
    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            for row in conn.execute(select(table)):
                out.append(f"{table.name}: {tuple(row)}")
    return "\n".join(out)


def load(name: str):
    return json.loads((FIX / name).read_text())


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    login_limiter._attempts.clear()
    bootstrap_admin()
    yield


@pytest.fixture
def client():
    with TestClient(app, follow_redirects=False) as c:
        yield c


def bearer(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def api_login(client, username, password) -> dict:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return bearer(r.json()["access_token"])


@pytest.fixture
def admin(client):
    return api_login(client, *ADMIN)


def make_user(username: str, role: str, password: str = "Password-12345") -> None:
    with SessionLocal() as db:
        db.add(User(username=username, email=f"{username}@x.org", password_hash=hash_password(password), role=role))
        db.commit()


@pytest.fixture
def project(client, admin):
    """(project_id, pipeline_token_headers) for a project using the default policy."""
    p = client.post("/api/v1/projects", json={"name": "demo"}, headers=admin).json()
    t = client.post(f"/api/v1/projects/{p['id']}/tokens", json={"label": "ci"}, headers=admin).json()
    return p["id"], bearer(t["token"])


class Pipeline:
    """Helper to push a CI run to /ingest."""

    def __init__(self, client, headers):
        self.client, self.headers, self.n = client, headers, 0

    def run(self, reports=None, branch="main", run_id=None, client_errors=None, commit="abc1234def", **extra):
        self.n += 1
        body = {
            "ci_run_id": str(run_id or 1000 + self.n),
            "commit_sha": commit,
            "branch": branch,
            "reports": [{"scanner": k, "report": v} for k, v in (reports or {}).items()],
            "client_errors": client_errors or [],
            **extra,
        }
        return self.client.post("/api/v1/ingest", json=body, headers=self.headers)


@pytest.fixture
def pipeline(client, project):
    return Pipeline(client, project[1])


CLEAN = {"bandit": {"results": [], "errors": []}, "gitleaks": []}
