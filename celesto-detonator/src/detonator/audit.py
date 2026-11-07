"""Append-only command audit log. One JSON line per command ATTEMPT, including blocked ones."""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import ROOT

_lock = threading.Lock()
LOG_PATH = ROOT / "logs" / "commands.jsonl"


def log_command(sandbox_name: str, command: str, decision: str, origin: str, reason: str = "",
                path: Path | None = None) -> None:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "sandbox_name": sandbox_name,
        "command": command[:2000] if command.strip() else "<empty>",
        "decision": decision,
        "execution_target": "celesto_sandbox",
        "origin": origin,
        "reason": reason,
    }
    p = path or LOG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    with _lock, p.open("a") as f:
        f.write(json.dumps(rec) + "\n")
