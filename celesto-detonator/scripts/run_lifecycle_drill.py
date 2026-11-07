"""Proves cleanup on success, failure AND Ctrl-C (SIGINT sent to a real child run)."""
import json
import os
import signal
import subprocess
import sys
import time

from _common import *  # noqa

LOG = ROOT / "logs" / "commands.jsonl"


def exists_in_celesto(name: str):
    """True/False if `celesto computer list --json` worked, None if the CLI is unavailable."""
    try:
        out = subprocess.run(["celesto", "computer", "list", "--json"], capture_output=True, text=True, timeout=30)
        return name in out.stdout if out.returncode == 0 else None
    except Exception:
        return None


def main():
    cfg = Config.from_env()
    drills, names = {}, []
    ok = detonate("benign-demo", cfg, use_agent=False)
    names += ok["sandbox_names"]
    drills["success"] = bool(ok["ok"]) and not any(exists_in_celesto(n) for n in ok["sandbox_names"])
    bad = detonate("benign-demo", cfg, use_agent=False, hard_fail=True)
    names += bad["sandbox_names"]
    drills["failure"] = (not bad["ok"]) and not any(exists_in_celesto(n) for n in bad["sandbox_names"])

    before = len(LOG.read_text().splitlines()) if LOG.exists() else 0
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    p = subprocess.Popen([sys.executable, "-m", "detonator.cli", "benign-demo", "--no-agent"], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child_names, deadline = set(), time.time() + 120
    while time.time() < deadline and not any('pkg.tar.gz' in l for l in LOG.read_text().splitlines()[before:]):
        time.sleep(0.5)  # wait until the guest exists and the package is uploaded (i.e. mid-run)
    for l in LOG.read_text().splitlines()[before:]:
        child_names.add(json.loads(l)["sandbox_name"])
    p.send_signal(signal.SIGINT)
    try:
        _, err = p.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        p.kill(); err = "child did not exit after SIGINT"
    names += sorted(child_names)
    handler_ran = "deleting live sandboxes" in err and "[warn]" not in err
    still = [n for n in child_names if exists_in_celesto(n)]
    drills["interrupt"] = bool(child_names) and handler_ran and not still
    write_json(EVIDENCE / "lifecycle_drills.json", {"drills": drills, "sandbox_names": names, "child_stderr": err[-800:],
                                                    "list_check_used": exists_in_celesto("sbx-x") is not None})
    print(drills)


if __name__ == "__main__":
    main()
