"""The 10-step detonation pipeline.

 1 create   2 ready   3 prepare (shim + canaries)   4 baseline   5 upload package
 6 checkpoint (snapshot)   7 install under audit   <-- designed crash point
 8 import under audit   9 collect evidence   10 analyze + LLM investigate + write report

State machine: Created -> Ready -> Running -> Succeeded | MidTaskFailure -> (Resumed|RolledBack|FreshStart) -> ... -> Deleted
Every path ends in Deleted (finally block in run()).
"""
import base64
import hashlib
import json
import re
import secrets
import time
from pathlib import Path

from . import agent as agent_mod
from . import analyze, ledger_client
from .config import Config
from .sandbox import SandboxSession, StepFailure
from .trace import Trace

TOTAL_STEPS = 10
SHIM = (Path(__file__).parent / "guest_shim.py").read_text()
MODULE_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
AUDIT = "/var/log/detonation/audit.jsonl"


class Detonation:
    def __init__(self, cfg: Config, archive: Path, module: str, label: str = "unknown",
                 policy: str | None = None, inject_failure: bool = False, hard_fail: bool = False,
                 use_agent: bool = True, trace: Trace | None = None, session_factory=None,
                 run_id: str | None = None, report_dir: Path | None = None, extra_agent_cmds: list[str] | None = None):
        if not MODULE_RX.match(module):
            raise ValueError("bad module name")
        self.cfg, self.archive, self.module, self.label = cfg, Path(archive), module, label
        self.policy = policy or cfg.failure_policy
        self.inject_failure, self.hard_fail, self.use_agent = inject_failure, hard_fail, use_agent
        self.run_id = run_id or "run-" + secrets.token_hex(5)
        self.trace = trace or Trace(None, self.run_id)
        self.trace.run_id = self.run_id
        self.factory = session_factory or (lambda cfg, name=None: SandboxSession(cfg, name=name))
        self.report_dir = report_dir or (cfg.reports_dir / "detonations")
        self.sessions: list = []
        self.sb = None
        self.token = "canary-" + secrets.token_hex(8)
        self.aws_key = "AKIACANARY" + secrets.token_hex(6).upper()
        self.boot_to_ready_s = 0.0
        self.data: dict = {}
        self.error = ""
        self.ok = False
        self.applied_policy = None
        self.extra_agent_cmds = extra_agent_cmds or []

    # ---- helpers ------------------------------------------------------------------------
    def _post(self, state: str) -> None:
        if self.sb:
            ledger_client.post_state(self.cfg.ledger_url, self.run_id, self.sb.name, state)

    def _put(self, path: str, data: bytes) -> None:
        self.sb.run(f': > "{path}"')
        b64 = base64.b64encode(data).decode()
        for i in range(0, len(b64), 24000):
            r = self.sb.run(f'echo {b64[i:i+24000]} | base64 -d >> "{path}"')
            if not r.ok:
                raise StepFailure(f"upload failed: {r.stderr[:150]}")

    @property
    def _env(self) -> str:
        return (f"DETONATION_SANDBOX=1 AUDIT_LOG={AUDIT} PYTHONPATH=/opt/audit CANARY_TOKEN={self.token} "
                "PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1")

    # ---- steps --------------------------------------------------------------------------
    def s_create(self):
        self.sb = self.factory(self.cfg)
        self.sb.create()
        self.sessions.append(self.sb)
        self._post("created")

    def s_ready(self):
        self.boot_to_ready_s = self.sb.wait_ready()
        self._post("ready")

    def s_prepare(self):
        self.sb.run("mkdir -p /work /var/log/detonation /opt/audit \"$HOME/.aws\"")
        self._put("/opt/audit/sitecustomize.py", SHIM.encode())
        creds = f"[default]\naws_access_key_id={self.aws_key}\naws_secret_access_key={secrets.token_hex(20)}\n"
        self._put("$HOME/.aws/credentials", creds.encode())

    def s_baseline(self):
        self.sb.run("sleep 1; touch /var/log/detonation/baseline.marker; sleep 1")

    def s_upload(self):
        data = self.archive.read_bytes()
        self._put("/work/pkg.tar.gz", data)
        r = self.sb.run("sha256sum /work/pkg.tar.gz")
        if hashlib.sha256(data).hexdigest() not in r.stdout:
            raise StepFailure("package checksum mismatch after upload")

    def s_checkpoint(self):
        if self.sb.supports_snapshots:
            self.sb.snapshot("pre-detonation")
            self.trace.emit("snapshot_taken", step=6, snapshot_id="pre-detonation")
        else:
            self.trace.emit("snapshot_skipped", step=6, reason="provider has no snapshots")

    def _install(self, sabotage: bool) -> int:
        install = f"cd /work && {self._env} python3 -m pip install --no-cache-dir --no-index --no-build-isolation --no-deps /work/pkg.tar.gz"
        if sabotage:  # kill pip mid-install: leaves partial state, then we raise
            self.sb.run(f"cd /work && {self._env} timeout -s KILL 1 python3 -m pip install --no-cache-dir --no-index "
                        "--no-build-isolation --no-deps /work/pkg.tar.gz; sleep 1; pkill -9 -f pkg.tar.gz || true", timeout=30)
            raise StepFailure("simulated mid-install crash (pip killed after 1s)")
        r = self.sb.run(install, timeout=180)
        if r.exit_code in (124, 137):
            raise StepFailure(f"install timed out (exit {r.exit_code})")
        self.data["install_stderr_tail"] = r.stderr[-400:]
        return r.exit_code

    def s_install_with_recovery(self):
        self._post("running")
        self.trace.emit("step_started", step=7, attempt=1)
        try:
            if self.hard_fail:
                raise StepFailure("hard failure requested (both attempts fail)")
            self.data["install_exit_code"] = self._install(sabotage=self.inject_failure)
            return
        except StepFailure as e:
            self.trace.emit("step_failed", step=7, attempt=1, error=str(e), state="MidTaskFailure")
        policy = self.policy
        self.trace.emit("policy_selected", step=7, policy=policy)
        if policy == "rollback" and not self.sb.supports_snapshots:
            self.trace.emit("policy_fallback", from_policy="rollback", to_policy="fresh",
                            reason="provider has no snapshots; falling back to fresh")
            policy = "fresh"
        if policy == "resume":
            self.sb.run("rm -rf /work/build /work/*.egg-info; true")
            self.trace.emit("policy_applied", step=7, policy="resume", state="Resumed", detail="same disk, partial build dir cleaned")
        elif policy == "rollback":
            self.sb.restore("pre-detonation")
            self.sb.wait_ready()
            self.trace.emit("policy_applied", step=7, policy="rollback", state="RolledBack", detail="restored snapshot pre-detonation")
        elif policy == "fresh":
            old = self.sb
            old.delete()
            self._post("deleted")
            self.s_create()
            self.sb.wait_ready()
            self.s_prepare(); self.s_baseline(); self.s_upload(); self.s_checkpoint()
            self.trace.emit("policy_applied", step=7, policy="fresh", state="FreshStart",
                            detail=f"{old.name} deleted, new sandbox {self.sb.name}")
        else:
            raise ValueError(f"unknown policy {policy}")
        self.applied_policy = policy
        self.trace.emit("step_started", step=7, attempt=2)
        if self.hard_fail:
            raise StepFailure("hard failure requested (retry failed)")
        self.data["install_exit_code"] = self._install(sabotage=False)
        self.trace.emit("step_retry_succeeded", step=7)

    def s_import(self):
        r = self.sb.run(f'cd /tmp && {self._env} python3 -c "import {self.module}"', timeout=60)
        self.data["import_exit_code"] = r.exit_code

    def s_collect(self):
        sb = self.sb
        self.data["audit_text"] = sb.run(f"tail -n 8000 {AUDIT} 2>/dev/null; true").stdout
        fs = sb.run("find / -xdev -type f -newer /var/log/detonation/baseline.marker 2>/dev/null "
                    "| grep -v -e '^/proc' -e '^/sys' -e '^/var/log/detonation' | head -400; true").stdout
        self.data["fs_changes"] = [l for l in fs.splitlines() if l.startswith("/")]
        member = self.archive.name.removesuffix(".tar.gz") + "/README.md"
        self.data["readme"] = sb.run(f"tar -xzOf /work/pkg.tar.gz {shlex_quote(member)} 2>/dev/null | head -c 1500; true").stdout
        self.data["selfreport"] = sb.run("cat /tmp/.evil_demo_result 2>/dev/null; true").stdout.strip()

    def s_analyze(self):
        events = analyze.parse_events(self.data["audit_text"])
        rep = analyze.analyze(events, self.data["fs_changes"], [self.token, self.aws_key])
        rep.update(install_exit_code=self.data.get("install_exit_code"), import_exit_code=self.data.get("import_exit_code"))
        ag = agent_mod.investigate(self.cfg, self.sb, rep, self.data["readme"]) if self.use_agent else \
            {"mode": "disabled", "verdict": None, "summary": "", "turns": 0, "blocked_commands": 0}
        for c in self.extra_agent_cmds:  # red-team: commands an injected agent might issue
            res = self.sb.run(c, origin="agent", timeout=15)
            self.data.setdefault("redteam", []).append({"command": c, "blocked": res.blocked, "exit_code": res.exit_code})
        final = analyze.max_verdict(rep["verdict"], ag.get("verdict"))
        self.report = {
            "run_id": self.run_id, "label": self.label, "package": self.archive.name, "provider": self.cfg.provider,
            "network_mode": self.sb.network_mode, "network_enforced": self.sb.network_enforced,
            **rep, "analyzer_verdict": rep["verdict"], "agent": ag, "final_verdict": final,
            "selfreport": self.data["selfreport"], "fs_changes_sample": self.data["fs_changes"][:40],
            "redteam": self.data.get("redteam", []), "readme_excerpt": self.data["readme"][:300],
        }
        self.report.pop("verdict", None)

    # ---- driver -------------------------------------------------------------------------
    def run(self) -> dict:
        t0 = time.time()
        self.report = {}
        try:
            for n, fn in [(1, self.s_create), (2, self.s_ready), (3, self.s_prepare), (4, self.s_baseline),
                          (5, self.s_upload), (6, self.s_checkpoint), (7, self.s_install_with_recovery),
                          (8, self.s_import), (9, self.s_collect), (10, self.s_analyze)]:
                if n != 7:
                    self.trace.emit("step_started", step=n)
                fn()
                self.trace.emit("step_ok", step=n)
            self.ok = True
            self._post("succeeded")
        except Exception as e:  # KeyboardInterrupt is NOT caught: it propagates after the finally below
            self.error = f"{type(e).__name__}: {e}"
            self.trace.emit("run_failed", error=self.error, state="failed")
            self._post("failed")
        finally:
            self._delete_all()
        wall = time.time() - t0
        self.trace.emit("run_completed", success=self.ok, wall_clock_s=round(wall, 3))
        rep_path = None
        if self.ok:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            rep_path = self.report_dir / f"{self.run_id}.json"
            self.report.update(sandbox_names=[s.name for s in self.sessions], applied_policy=self.applied_policy)
            rep_path.write_text(json.dumps(self.report, indent=2))
        life = sum(s.lifetime_s for s in self.sessions)
        return {
            "run_id": self.run_id, "sandbox_name": self.sessions[0].name if self.sessions else "",
            "sandbox_names": [s.name for s in self.sessions], "ok": self.ok, "error": self.error,
            "verdict": self.report.get("final_verdict"), "report_path": str(rep_path) if rep_path else None,
            "wall_clock_s": round(wall, 3), "boot_to_ready_s": round(self.boot_to_ready_s, 3),
            "cost_usd": round(self.cfg.hourly_usd * life / 3600, 6), "applied_policy": self.applied_policy,
            "report": self.report,
        }

    def _delete_all(self):
        for s in self.sessions:
            if not s.deleted:
                s.delete()
                if s is self.sb:
                    self._post("deleted")
                    self.trace.emit("sandbox_deleted", sandbox_name=s.name, state="Deleted")
        # deleted-before-replacement sandboxes (fresh policy) were logged when replaced


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)
