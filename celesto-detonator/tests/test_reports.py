"""Grader-style checks for every file in the submission. These FAIL until you have run the real
eval/drills (make all) - that is intentional: nothing here is pre-filled with fake numbers."""
import json
import math
import re
from pathlib import Path



ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"^sbx-[a-z0-9]{8,}$")
CAPS = {"persistence", "snapshots", "celestofs", "browser", "published_ports", "network_policy",
        "safety_hooks", "host_mounts", "coding_agent_preset", "agentor_durable"}


def J(p):
    return json.loads((ROOT / p).read_text())


def test_compose_and_env():
    import yaml
    c = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for svc in ("api", "ledger"):
        hc = c["services"][svc]["healthcheck"]
        assert all(k in hc for k in ("interval", "timeout", "retries", "start_period"))
    assert "pg_isready" in json.dumps(c["services"]["ledger"]["healthcheck"])
    assert any("seeds" in v for v in c["services"]["ledger"]["volumes"])
    assert c["services"]["api"]["depends_on"]["ledger"]["condition"] == "service_healthy"
    env = (ROOT / ".env.example").read_text()
    for k in ("CELESTO_PROVIDER", "CELESTO_API_KEY", "LLM_API_KEY", "LLM_MODEL", "DATABASE_URL", "API_PORT"):
        assert re.search(rf"^{k}=", env, re.M), k
    assert not (ROOT / ".env").exists()
    assert not re.search(r"(sk-[A-Za-z0-9]{20,}|csk_[A-Za-z0-9]{10,})", env)


def test_seed_is_idempotent():
    s = (ROOT / "seeds/01_runs.sql").read_text()
    assert "sbx-seeddemo1" in s and "ON CONFLICT" in s and "deleted" in s and "celesto_sandbox" in s


def test_problem():
    p = J("reports/problem.json")
    assert len(p["who"]) >= 40 and len(p["agent_work"]) >= 40 and len(p["proof_output"]) >= 20
    assert p["idea_source"] in ("idea_bank", "original")


def test_capabilities():
    caps = J("reports/capabilities.json")["capabilities"]
    ids = [c["id"] for c in caps]
    assert len(caps) >= 2 and len(set(ids)) == len(ids) and set(ids) <= CAPS
    for c in caps:
        assert len(c["why"]) >= 80 and (ROOT / c["evidence_path"]).exists()


def test_command_log():
    lines = (ROOT / "logs/commands.jsonl").read_text().splitlines()
    assert lines
    for l in lines:
        r = json.loads(l)
        assert r["ts"] and NAME.match(r["sandbox_name"]) and r["command"].strip()
        assert r["decision"] in ("allow", "block") and r["execution_target"] == "celesto_sandbox"


def test_reliability():
    r = J("reports/reliability.json")
    runs = r["runs"]
    n = len(runs)
    assert n >= 20 and r["run_count"] == n
    names = [x["sandbox_name"] for x in runs]
    assert len(set(names)) == n and all(NAME.match(x) for x in names)
    for x in runs:
        assert x["fresh"] is True and isinstance(x["success"], bool)
        assert x["wall_clock_s"] >= 0 and x["boot_to_ready_s"] >= 0 and x["cost_usd"] >= 0
    assert abs(r["success_rate"] - sum(x["success"] for x in runs) / n) <= 0.001
    w = sorted(x["wall_clock_s"] for x in runs)
    med = (w[n // 2 - 1] + w[n // 2]) / 2 if n % 2 == 0 else w[n // 2]
    assert abs(r["median_wall_clock_s"] - med) <= 0.001
    assert abs(r["p90_wall_clock_s"] - w[math.ceil(0.9 * n) - 1]) <= 0.001
    b = sorted(x["boot_to_ready_s"] for x in runs)
    bm = (b[n // 2 - 1] + b[n // 2]) / 2 if n % 2 == 0 else b[n // 2]
    assert abs(r["median_boot_to_ready_s"] - bm) <= 0.001
    assert abs(r["total_cost_usd"] - sum(x["cost_usd"] for x in runs)) <= 0.01
    assert r["postmortem_path"] == "reports/postmortem.md"
    assert len((ROOT / r["postmortem_path"]).read_text()) >= 200


def test_lifecycle():
    l = J("reports/lifecycle.json")
    assert l["cleanup_on_success"] is True and l["cleanup_on_failure"] is True and l["cleanup_on_interrupt"] is True
    names = l["sandbox_names"]
    assert names and len(set(names)) == len(names) and all(NAME.match(x) for x in names)
    seen = (ROOT / "logs/commands.jsonl").read_text() + (ROOT / "reports/reliability.json").read_text()
    assert all(x in seen for x in names)


def test_containment():
    c = J("reports/containment.json")
    assert c["attack"] in ("prompt_injection_exfil", "destructive_command", "suspicious_package")
    assert c["blocked"] is True and c["host_untouched"] is True
    assert c["evidence_paths"] and all((ROOT / p).exists() for p in c["evidence_paths"])


def test_failure_policy():
    f = J("reports/failure_policy.json")
    assert f["failed_step"] == 7 and f["total_steps"] == 10 and f["policy"] in ("resume", "rollback", "fresh")
    assert len(f["rationale"]) >= 200 and f["trace_path"] == "reports/failure_trace.jsonl"
    ev = [json.loads(l) for l in (ROOT / f["trace_path"]).read_text().splitlines() if l.strip()]
    assert any(e.get("event") == "policy_applied" and e.get("policy") == f["policy"] for e in ev)


def test_concurrency():
    c = J("reports/concurrency.json")
    jobs = c["jobs"]
    names = [j["sandbox_name"] for j in jobs]
    assert len(jobs) >= 5 and len(set(names)) == len(names) and all(NAME.match(x) for x in names)
    assert all(j["started_at"] for j in jobs) and len(c["breakage_notes"]) >= 40


def test_readme_phrases_and_demo():
    t = (ROOT / "README.md").read_text()
    for p in ("Problem statement", "How I used Celesto", "Eval report", "Containment test", "State and failure design", "Setup"):
        assert p in t, p
    assert (ROOT / "demo/walkthrough.mp4").exists() or "http" in t.split("Demo")[-1]
