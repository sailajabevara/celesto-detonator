"""The ONLY module that touches the Celesto SDK. Every command goes through run(), which
(1) applies the safety hook, (2) appends to logs/commands.jsonl, (3) executes inside the guest.
Nothing here ever executes a tool command on the host.

LIFECYCLE: delete() is idempotent and is called from try/finally in pipeline.py, from __exit__,
and from the SIGINT/SIGTERM handler (cleanup_all) so Ctrl-C never orphans a guest.
"""
import atexit
import secrets
import shlex
import signal
import sys
import threading
import time
from dataclasses import dataclass

from . import audit, hooks
from .config import Config


class StepFailure(Exception):
    """An infrastructure/step failure (not a finding about the package)."""


@dataclass
class Result:
    exit_code: int
    stdout: str
    stderr: str
    blocked: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def new_name() -> str:
    return "sbx-" + secrets.token_hex(5)  # sbx- + 10 lowercase hex chars


_live: dict[str, "SandboxSession"] = {}
_live_lock = threading.Lock()


def cleanup_all() -> None:
    with _live_lock:
        sessions = list(_live.values())
    for s in sessions:
        s.delete()


atexit.register(cleanup_all)


def install_signal_handlers() -> None:
    def _h(signum, _frame):
        print(f"\n[signal {signum}] deleting live sandboxes...", file=sys.stderr)
        cleanup_all()
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _h)
    signal.signal(signal.SIGTERM, _h)


def _construct(cls, **kw):
    """SDK signatures differ slightly between versions: drop unsupported kwargs (name) and note it."""
    try:
        return cls(**kw), True
    except TypeError:
        kw.pop("name", None)
        return cls(**kw), False


class SandboxSession:
    def __init__(self, cfg: Config, name: str | None = None, network_off: bool = True, vm_factory=None):
        self.cfg = cfg
        self.name = name or new_name()
        self.network_off = network_off
        self.vm_factory = vm_factory
        self.vm = None
        self._cm = None
        self.deleted = False
        self.t_create = 0.0
        self.t_deleted = 0.0
        self.name_param_supported = True

    # ---- capabilities -------------------------------------------------------------------
    @property
    def supports_snapshots(self) -> bool:
        return self.cfg.provider == "local"

    @property
    def network_enforced(self) -> bool:
        return self.cfg.provider == "local" and self.cfg.backend == "firecracker" and self.network_off

    @property
    def network_mode(self) -> str:
        return "off" if self.network_enforced else "default-internet (policy not available on this provider)"

    # ---- lifecycle ----------------------------------------------------------------------
    def create(self) -> None:
        self.t_create = time.time()
        if self.vm_factory:
            self.vm = self.vm_factory(self)
        elif self.cfg.provider == "cloud":
            from celesto import Computer
            c, self.name_param_supported = _construct(Computer, provider="cloud", name=self.name)
            self._cm = c
            self.vm = c.__enter__()
        else:
            from celesto import Celesto
            kw = {"backend": self.cfg.backend, "name": self.name}
            if self.cfg.backend == "firecracker":
                kw["comm_channel"] = "vsock"
                if self.network_off:
                    kw["internet_settings"] = {"mode": "off"}
            vm, self.name_param_supported = _construct(Celesto, **kw)
            vm.start()
            self.vm = vm
        with _live_lock:
            _live[self.name] = self

    def wait_ready(self, timeout: float = 90.0) -> float:
        """Boot probe. Returns seconds from create() start to first passing probe (boot-to-ready)."""
        probe = 'python3 -c "import sys, setuptools; print(sys.version_info[:2])" && python3 -m pip --version'
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            try:
                r = self.run(probe, origin="orchestrator", timeout=20)
                if r.ok:
                    return time.time() - self.t_create
                last = r.stderr or r.stdout
            except Exception as e:  # guest still booting
                last = repr(e)
            time.sleep(1)
        raise StepFailure(f"boot probe failed (guest needs python3+pip+setuptools): {last[:200]}")

    def run(self, command: str, origin: str = "orchestrator", timeout: int | None = 120) -> Result:
        decision, reason = hooks.check(command, origin)
        audit.log_command(self.name, command, decision, origin, reason)
        if decision == "block":
            return Result(126, "", f"BLOCKED by safety hook ({reason}); command never reached the guest.", True)
        cmd = f"timeout {int(timeout)} sh -c {shlex.quote(command)}" if timeout else command
        r = self.vm.run(cmd)
        return Result(getattr(r, "exit_code", 0 if getattr(r, "ok", True) else 1),
                      getattr(r, "stdout", "") or "", getattr(r, "stderr", "") or "")

    # ---- snapshots (local runtime only) -------------------------------------------------
    def snapshot(self, snapshot_id: str) -> None:
        if not self.supports_snapshots:
            raise StepFailure("snapshots need the local runtime")
        self.vm.snapshot(snapshot_id=snapshot_id, resume_source=True)

    def restore(self, snapshot_id: str) -> None:
        if not self.supports_snapshots:
            raise StepFailure("snapshots need the local runtime")
        from celesto import Celesto
        try:
            self.vm.stop()
        except Exception:
            pass
        try:
            self.vm.delete()
        except Exception:
            pass
        self.vm = Celesto.from_snapshot(snapshot_id, resume_vm=True, force=True)

    def delete(self) -> None:
        if self.deleted:
            return
        errors = []
        try:
            if self._cm is not None:
                self._cm.__exit__(None, None, None)
            elif self.vm is not None:
                for fn in ("stop", "delete"):
                    try:
                        getattr(self.vm, fn)()
                    except Exception as e:
                        errors.append(f"{fn}: {e!r}")
        finally:
            self.deleted = True
            self.t_deleted = time.time()
            with _live_lock:
                _live.pop(self.name, None)
        if errors:
            print(f"[warn] {self.name}: {errors}", file=sys.stderr)

    @property
    def lifetime_s(self) -> float:
        end = self.t_deleted or time.time()
        return max(0.0, end - self.t_create) if self.t_create else 0.0

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, *exc):
        self.delete()
        return False
