"""Step 7 of 10 crashes on purpose (pip killed mid-install). Recovery policy is applied and traced."""
from _common import *  # noqa
from detonator.trace import Trace

RATIONALE = {
 "rollback": ("Rollback. Step 7 (install) is the only step that executes untrusted code, so it is the step that can leave the guest "
  "in an unknown, half-written state (partial build dir, partial audit log, files from a killed setup.py). Resume would trust that "
  "state; a fresh sandbox would re-pay boot plus steps 2-6 (upload, canaries, baseline) every time. A snapshot taken at step 6 costs "
  "one checkpoint and restores a known-clean disk AND memory in one call, so retry sees exactly the pre-detonation world. The trade-off: "
  "snapshots need the local runtime, so on Celesto Cloud the code falls back to fresh and records the fallback in the trace."),
 "resume": ("Resume. Same disk is kept, only the partial build directory is cleaned before retrying step 7. Cheapest and simplest, "
  "but it trusts guest state after an untrusted process was killed mid-run: leftover files or a half-written audit log can change the "
  "verdict, so it is only safe when step 7 failures are infrastructure timeouts and not package behaviour."),
 "fresh": ("Fresh start. The failed guest is deleted and a new uniquely named guest repeats steps 2-6 before retrying step 7. Most "
  "reliable and works on every provider (no snapshot support needed), but it pays boot time and upload again on every failure, so it is "
  "the most expensive policy under frequent failures. Chosen when snapshots are unavailable or the guest itself is suspect."),
}


def main():
    install_signal_handlers()
    cfg = Config.from_env()
    trace_path = REPORTS / "failure_trace.jsonl"
    trace_path.unlink(missing_ok=True)
    res = detonate("benign-demo", cfg, inject_failure=True, use_agent=False, trace=Trace(trace_path))
    applied = res["applied_policy"]
    if not applied:
        raise SystemExit(f"policy was never applied (run ok={res['ok']} error={res['error']})")
    note = f" Measured on this drill: policy requested={cfg.failure_policy}, applied={applied}, run_ok={res['ok']}, wall={res['wall_clock_s']}s, sandboxes={res['sandbox_names']}."
    write_json(REPORTS / "failure_policy.json", {
        "failed_step": 7, "total_steps": 10, "policy": applied, "rationale": RATIONALE[applied] + note,
        "trace_path": "reports/failure_trace.jsonl"})
    write_json(EVIDENCE / "failure_drill.json", {k: v for k, v in res.items() if k != "report"})
    print("policy applied:", applied, "| run ok:", res["ok"])


if __name__ == "__main__":
    main()
