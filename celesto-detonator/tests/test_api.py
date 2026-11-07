import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from fastapi.testclient import TestClient

from detonator import api

GOOD = {"run_id": "r1", "sandbox_name": "sbx-abcd1234", "problem_id": "pkg-detonator",
        "state": "running", "execution_target": "celesto_sandbox"}


def client(monkeypatch):
    store = {"run-seeddemo1": {"run_id": "run-seeddemo1", "sandbox_name": "sbx-seeddemo1", "problem_id": "pkg-detonator",
                               "state": "deleted", "execution_target": "celesto_sandbox"}}
    monkeypatch.setattr(api, "db_list", lambda: list(store.values()))
    monkeypatch.setattr(api, "db_upsert", lambda b: store.setdefault(b["run_id"], b))
    monkeypatch.setattr(api, "_startup", lambda: None)
    return TestClient(api.app)


def test_health_and_seed(monkeypatch):
    c = client(monkeypatch)
    assert c.get("/health").json() == {"status": "ok"}
    assert "sbx-seeddemo1" in [r["sandbox_name"] for r in c.get("/api/runs").json()]


def test_post_valid_and_invalid(monkeypatch):
    c = client(monkeypatch)
    assert c.post("/api/runs", json=GOOD).status_code == 201
    assert c.post("/api/runs", json={**GOOD, "execution_target": "host"}).status_code == 400
    assert c.post("/api/runs", json={**GOOD, "state": "exploded"}).status_code == 400
    assert c.post("/api/runs", json={**GOOD, "sandbox_name": "sbx-SHORT"}).status_code == 400
    assert c.post("/api/runs", content=b"not json").status_code == 400
