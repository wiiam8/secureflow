#!/usr/bin/env bash
# Local run without Docker (SQLite). Usage:  ./scripts/dev.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements-dev.txt
export DATABASE_URL="${DATABASE_URL:-sqlite:///./secureflow.db}"
export SECRET_KEY="${SECRET_KEY:-dev-only-secret-change-me-please}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-ChangeMe-Admin-123}"
alembic upgrade head
echo "-> http://localhost:8000   login: ${ADMIN_USERNAME:-admin} / $ADMIN_PASSWORD"
exec uvicorn app.main:app --reload --port 8000
