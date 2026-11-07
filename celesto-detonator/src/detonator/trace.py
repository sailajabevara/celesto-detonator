"""JSONL trace of the run state machine (used for failure_trace.jsonl)."""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class Trace:
    def __init__(self, path: Path | None = None, run_id: str = ""):
        self.path, self.run_id, self.events, self._lock = path, run_id, [], threading.Lock()

    def emit(self, event: str, **kw) -> None:
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "run_id": self.run_id, "event": event, **kw}
        with self._lock:
            self.events.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as f:
                    f.write(json.dumps(rec) + "\n")
