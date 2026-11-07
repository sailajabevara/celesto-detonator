"""Run Ledger API (trusted control plane). Never creates guests itself."""
import json
import os
import re
import time
from pathlib import Path

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI(title="Run Ledger")
NAME_RX = re.compile(r"^sbx-[a-z0-9]{8,}$")
STATES = {"created", "ready", "running", "succeeded", "failed", "deleted"}
SCHEMA = """CREATE TABLE IF NOT EXISTS runs (
 run_id TEXT PRIMARY KEY, sandbox_name TEXT NOT NULL CHECK (sandbox_name ~ '^sbx-[a-z0-9]{8,}$'),
 problem_id TEXT NOT NULL, state TEXT NOT NULL, execution_target TEXT NOT NULL CHECK (execution_target='celesto_sandbox'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target)
 VALUES ('run-seeddemo1','sbx-seeddemo1','pkg-detonator','deleted','celesto_sandbox') ON CONFLICT (run_id) DO NOTHING;"""


def _dsn() -> str:
    return os.environ.get("DATABASE_URL", "postgresql://ledger:ledger@localhost:5432/ledger")


def validate(body) -> str | None:
    """Return an error string, or None if the body is valid."""
    if not isinstance(body, dict):
        return "body must be a JSON object"
    for k in ("run_id", "sandbox_name", "problem_id", "state", "execution_target"):
        if not isinstance(body.get(k), str) or not body[k]:
            return f"missing or invalid field: {k}"
    if body["execution_target"] != "celesto_sandbox":
        return "execution_target must be celesto_sandbox"
    if body["state"] not in STATES:
        return f"state must be one of {sorted(STATES)}"
    if not NAME_RX.match(body["sandbox_name"]):
        return "sandbox_name must match ^sbx-[a-z0-9]{8,}$"
    return None


def db_list() -> list[dict]:
    with psycopg.connect(_dsn()) as c, c.cursor() as cur:
        cur.execute("SELECT run_id, sandbox_name, problem_id, state, execution_target, created_at, updated_at FROM runs ORDER BY created_at, run_id")
        cols = [d.name for d in cur.description]
        return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in zip(cols, row)} for row in cur.fetchall()]


def db_upsert(b: dict) -> dict:
    with psycopg.connect(_dsn()) as c, c.cursor() as cur:
        cur.execute(
            "INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target) VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (run_id) DO UPDATE SET sandbox_name=EXCLUDED.sandbox_name, state=EXCLUDED.state, updated_at=now()",
            (b["run_id"], b["sandbox_name"], b["problem_id"], b["state"], b["execution_target"]))
    return {k: b[k] for k in ("run_id", "sandbox_name", "problem_id", "state", "execution_target")}


@app.on_event("startup")
def _startup():
    for _ in range(30):  # compose already waits for healthy ledger; this covers local dev
        try:
            with psycopg.connect(_dsn()) as c:
                c.execute(SCHEMA)
            return
        except Exception:
            time.sleep(1)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/runs")
def list_runs():
    return db_list()


@app.post("/api/runs")
async def create_run(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    err = validate(body)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    return JSONResponse(db_upsert(body), status_code=201)


def _reports_dir() -> Path:
    return Path(os.environ.get("REPORTS_DIR", "reports")).resolve()


@app.get("/api/reports")
def list_reports():
    d = _reports_dir()
    return sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()) if d.exists() else []


@app.get("/api/reports/{path:path}")
def get_report(path: str):
    d = _reports_dir()
    p = (d / path).resolve()
    if d not in p.parents or not p.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    return Response(p.read_text(), media_type="application/json" if p.suffix == ".json" else "text/plain")
