#!/bin/sh
set -e
echo "[secureflow] applying database migrations..."
alembic upgrade head
exec "$@"
