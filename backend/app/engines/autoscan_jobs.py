"""
In-memory job store for asynchronous Auto Scan runs.

Auto Scan can take minutes (ZAP spider + active scan), so the web route can't
block. It starts the orchestrator in a background thread and reports live
progress here; the frontend polls a status endpoint and renders a progress bar.

This is a simple process-local dict — fine for the single-process desktop app
and a single gunicorn worker. It is not shared across workers/processes; for a
multi-worker deployment this would move to Redis or the DB.
"""

import uuid
import threading
from datetime import datetime

_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()

# Rough step budget so the frontend can turn step count into a percentage.
# base pipeline stages (dedup, cwe, nvd, cwe-cvss, ml, confidence, report) ≈ 7.
BASE_STEPS = 7


def create_job(target: str, scanners: list[str], search_exploits: bool,
               run_poc: bool) -> str:
    job_id = uuid.uuid4().hex
    # Each scanner emits ~2 progress messages ("Running x", "x: n findings").
    expected = BASE_STEPS + len(scanners) * 2 + (1 if search_exploits else 0) \
        + (1 if run_poc else 0)
    with _LOCK:
        _JOBS[job_id] = {
            "status": "running",          # running | done | error
            "target": target,
            "steps": [],                  # list of progress message strings
            "expected_steps": max(expected, 1),
            "result": None,
            "error": None,
            "started_at": datetime.utcnow().isoformat(),
        }
    return job_id


def add_step(job_id: str, message: str) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job:
            job["steps"].append(message)


def finish_job(job_id: str, result=None, error=None) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job:
            job["status"] = "error" if error else "done"
            job["result"] = result
            job["error"] = error


def get_job(job_id: str) -> dict | None:
    with _LOCK:
        job = _JOBS.get(job_id)
        return dict(job) if job else None
