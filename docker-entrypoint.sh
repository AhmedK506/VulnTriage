#!/usr/bin/env bash
# Container entrypoint: wait for the database, create the schema + seed the
# default user, then exec the CMD (gunicorn).
set -e

echo "[entrypoint] DATABASE_URL=${DATABASE_URL%%:*}://… (host hidden)"

# Wait for Postgres to accept connections (skipped for SQLite/other URLs).
python - <<'PY'
import os, sys, time
url = os.environ.get("DATABASE_URL", "")
if not url.startswith("postgres"):
    print("[entrypoint] non-postgres database, skipping readiness wait")
    sys.exit(0)
from sqlalchemy import create_engine
for attempt in range(1, 31):
    try:
        create_engine(url).connect().close()
        print("[entrypoint] database is up")
        break
    except Exception as exc:
        print(f"[entrypoint] waiting for database ({attempt}/30): {exc}")
        time.sleep(2)
else:
    print("[entrypoint] database never became available")
    sys.exit(1)
PY

echo "[entrypoint] initialising schema and seeding default user…"
python scripts/init_db.py

echo "[entrypoint] starting: $*"
exec "$@"
