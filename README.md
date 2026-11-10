# SecureFlow

DevSecOps decision layer. Your pipeline runs Bandit, Gitleaks, pip-audit (+ Semgrep, Trivy); SecureFlow
**normalizes** their reports, **scores** the risk, applies a **versioned policy**, and returns an explainable
**PASS / WARN / BLOCK** to the pipeline, which fails on BLOCK. A dashboard keeps the history and the justification.

> Fail-closed: a missing or invalid report, an unreachable API, a bad token → **ERROR** (exit 2). Never PASS.

Docs: [architecture](docs/ARCHITECTURE.md) · [risk model](docs/RISK_MODEL.md) · [GRC layer](docs/GRC.md) · API docs at `/docs` when running.

## 1. Run it (pick one)

### A. Without Docker (fastest, SQLite)
```bash
./scripts/dev.sh
# -> http://localhost:8000   login: admin / ChangeMe-Admin-123
```
Needs Python 3.11+. (Windows: run the same commands from WSL, or see the manual steps in `scripts/dev.sh`.)

### B. Docker Compose (PostgreSQL)
```bash
cp .env.example .env          # then edit: POSTGRES_PASSWORD, SECRET_KEY, ADMIN_PASSWORD
docker compose up -d --build
# -> http://localhost:8000
```
If `ADMIN_PASSWORD` is empty, a random one is printed once: `docker compose logs api | grep "First administrator"`.

## 2. Connect a pipeline (the demo)

1. Create the demo repo: push the **contents of `demo-target/`** to a new GitHub repository
   (it is an intentionally vulnerable Flask app with fake secrets; the workflow is in `.github/workflows/secureflow.yml`).
2. In SecureFlow: **New project → Settings → Generate token**. Copy it (shown once).
3. In the GitHub repo → *Settings → Secrets and variables → Actions*, add:
   `SECUREFLOW_URL` (your public URL, see below) and `SECUREFLOW_TOKEN` (the token).
4. Push a commit. The *SecureFlow security gate* job runs the scanners, uploads, and **fails with BLOCK**
   (a fake API key + vulnerable dependencies). Open the run in the dashboard to see why.
5. Fix things (delete the key, upgrade `requirements.txt`) and push again → PASS.

### GitHub-hosted runners cannot reach `localhost`
Pick one:
- **Cloudflare quick tunnel** (easy for demos): `docker compose --profile tunnel up -d`, then
  `docker compose logs tunnel | grep trycloudflare` gives an `https://….trycloudflare.com` URL → use it as `SECUREFLOW_URL`
  (also set `BASE_URL` to it in `.env` so dashboard links are right).
- Deploy the stack on any VPS/VM with a domain + HTTPS (set `COOKIE_SECURE=true`, `ENVIRONMENT=production`).
- A **self-hosted runner** on your own machine can use `http://localhost:8000` directly.

Try the CI client locally without GitHub:
```bash
cd demo-target
SECUREFLOW_URL=http://localhost:8000 SECUREFLOW_TOKEN=sf_xxx GITHUB_SHA=abc1234 GITHUB_REF_NAME=main \
python scripts/secureflow_ci.py --report bandit=bandit.json --report gitleaks=gitleaks.json
echo $?   # 0 PASS/WARN · 1 BLOCK · 2 ERROR
```

## 3. Using it

| Role | Can |
|---|---|
| **Administrator** | everything, manage users and project members |
| **Security officer** | see all projects, create projects, tokens, edit policy, **accept risks** |
| **Developer** | see only projects they are a member of, flag findings "In Review", **cannot** accept risks |

- **Policy** (Settings tab) is JSON, validated on save, versioned. Default: Critical blocks; High secret/dependency
  blocks; High/Medium warns; `required_scanners: [bandit, gitleaks]` (a missing required scanner = ERROR).
  To use the other scanners, add them to `required_scanners` **and** to the workflow.
- **Risk acceptance**: finding page → status *Accepted* with justification and expiry. Not allowed for secrets.
- **Evidence**: run page → *Download evidence (JSON)*.

## 4. Tests
```bash
pip install -r requirements-dev.txt
pytest -q                                   # 157 tests, SQLite
TEST_DATABASE_URL=postgresql://user@host/emptydb pytest -q   # same suite on PostgreSQL (drops tables!)
```

## 5. Honest status: read before presenting

**Verified in the build environment:** 157 tests pass on SQLite **and** PostgreSQL 16; Alembic upgrade/downgrade on both;
a live server driven by the real CI script (BLOCK/PASS/ERROR/replay/server-down); dashboard rendered in headless Chromium
with no CSP violations; adapters tested on **real** Bandit, Gitleaks, pip-audit and Semgrep output.

**Not verified (could not be run there), so test these first:**
- `docker compose up`: the sandbox had no Docker daemon. The Dockerfile/compose are standard, but unrun.
- The GitHub Actions workflow on real GitHub runners (YAML is valid; Gitleaks download URL and tool versions to be confirmed).
- **Trivy**: the adapter is tested only on a **hand-written** sample following Trivy's documented schema, and the
  workflow lines for Trivy are commented out. Run a real `trivy image --format json` and add it to `tests/fixtures`.
- Semgrep with the registry rules (`p/python`): only local rules were tested.

**Known limitations (good material for the report's "perspectives"):**
- Same issue reported by two scanners (e.g. Bandit and Semgrep on `shell=True`) appears as two findings; no cross-scanner dedup.
- pip-audit/Gitleaks give no severity, so it comes from the policy (default High).
- Login rate limit is in-memory, per process. Run one worker or put a limiter in front.
- Local accounts only (no SSO). Sessions are signed cookies (no server-side revocation, 8 h lifetime).
- Python + Docker + GitHub Actions only (the agreed scope).
