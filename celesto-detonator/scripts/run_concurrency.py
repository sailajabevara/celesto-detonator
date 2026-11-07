"""Stretch: K jobs in parallel, each in its own uniquely named sandbox. Records what broke."""
import collections
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from _common import *  # noqa

K = int(sys.argv[1]) if len(sys.argv) > 1 else 5


def job(i):
    started = datetime.now(timezone.utc).isoformat()
    res = detonate("benign-demo", Config.from_env(), use_agent=False)
    return started, res


def main():
    install_signal_handlers()
    cfg = Config.from_env()
    if cfg.provider == "cloud":
        print("WARNING: free-trial cloud allows ONE sandbox; use the local runtime or a paid top-up for parallel jobs.")
    with ThreadPoolExecutor(K) as ex:
        out = list(ex.map(job, range(K)))
    jobs = [{"sandbox_name": r["sandbox_name"] or new_name(), "started_at": s, "ok": r["ok"], "error": r["error"],
             "wall_clock_s": r["wall_clock_s"], "boot_to_ready_s": r["boot_to_ready_s"]} for s, r in out]
    names = [j["sandbox_name"] for j in jobs]
    errs = collections.Counter(j["error"] for j in jobs if j["error"])
    notes = (f"Watched: name collisions ({len(names) - len(set(names))} found across {K} jobs), create/exec errors "
             f"({sum(errs.values())}: {dict(errs) or 'none'}), boot-to-ready spread "
             f"({min(j['boot_to_ready_s'] for j in jobs):.1f}-{max(j['boot_to_ready_s'] for j in jobs):.1f}s), "
             f"wall-clock spread ({min(j['wall_clock_s'] for j in jobs):.1f}-{max(j['wall_clock_s'] for j in jobs):.1f}s), "
             f"{sum(j['ok'] for j in jobs)}/{K} jobs succeeded. Shared state: none (per-job tmp dirs, per-run ids). "
             "Add your own observations (rate limits, host CPU/RAM pressure) here.")
    write_json(REPORTS / "concurrency.json", {"jobs": jobs, "breakage_notes": notes})
    print(notes)


if __name__ == "__main__":
    main()
