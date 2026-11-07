"""Best-effort client for the Run Ledger API. Ledger being down must never fail a detonation."""
import json
import urllib.request


def post_state(base_url: str, run_id: str, sandbox_name: str, state: str, problem_id: str = "pkg-detonator") -> bool:
    body = json.dumps({"run_id": run_id, "sandbox_name": sandbox_name, "problem_id": problem_id,
                       "state": state, "execution_target": "celesto_sandbox"}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/api/runs", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status == 201
    except Exception:
        return False
