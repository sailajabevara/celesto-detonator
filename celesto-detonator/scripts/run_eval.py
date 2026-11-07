"""Reliability eval: N end-to-end runs, each on a FRESH uniquely-named sandbox. Stats computed from rows."""
import collections
import sys
import time

from _common import *  # noqa
from detonator import stats

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
ORDER = ["evil-demo", "benign-demo", "noisy-demo"]


def postmortem(rows: list[dict], cfg) -> str:
    fails = [r for r in rows if not r["success"]]
    by = collections.Counter((r["error"] or f"verdict mismatch: got {r['verdict']}, expected {r['expected']}") for r in fails)
    lines = [f"# Post-mortem ({len(rows)} fresh-sandbox runs, provider={cfg.provider}, agent={'LLM ' + cfg.llm_model if cfg.llm_enabled else 'scripted (no LLM)'})", "",
             f"Success: {len(rows) - len(fails)}/{len(rows)}. Failed rows are kept in reliability.json; none were removed.",
             "Success means: the run completed, a risk report was written, the final verdict matched the fixture's expected label, "
             "and the sandbox was deleted.", ""]
    if not fails:
        lines += ["## Failures", "", "No failures in this batch. What was watched: boot probe timeouts, upload checksum mismatches, "
                  "step-7 install timeouts, verdict mismatches (false positives on benign/noisy fixtures, false negatives on the malicious one), "
                  "and orphaned sandboxes after the run. A clean batch of this size does NOT prove a low failure rate; see the confidence note below."]
    else:
        lines += ["## Failures grouped by cause", ""] + [f"- {n}x {k}" for k, n in by.most_common()] + ["", "## Failed runs", ""]
        lines += [f"- `{r['sandbox_name']}` fixture={r['fixture']} verdict={r['verdict']} error={r['error'] or '-'}" for r in fails]
    lines += ["", "## Confidence note", "", f"With n={len(rows)}, one extra failure moves the rate by {100/len(rows):.1f} points. "
              "Treat the success rate as an estimate with wide error bars.", "",
              "## Manual analysis", "", "(Read the failures above and write your own root-cause notes here before submitting.)"]
    return "\n".join(lines) + "\n"


def main():
    install_signal_handlers()
    cfg = Config.from_env()
    rows, raw = [], []
    for i in range(N):
        fx = ORDER[i % len(ORDER)]
        t0 = time.time()
        res = detonate(fx, cfg, use_agent=True)
        expected = FIXTURES[fx][2]
        ok = bool(res["ok"] and res["verdict"] == expected)
        name = res["sandbox_name"] or new_name()  # run died before a sandbox existed: keep the row, honest flag
        rows.append({"sandbox_name": name, "fresh": True, "success": ok, "wall_clock_s": res["wall_clock_s"],
                     "boot_to_ready_s": res["boot_to_ready_s"], "cost_usd": res["cost_usd"],
                     "fixture": fx, "expected": expected, "verdict": res["verdict"], "error": res["error"],
                     "never_created": not res["sandbox_name"]})
        print(f"[{i+1}/{N}] {fx:12s} ok={ok} verdict={res['verdict']} wall={res['wall_clock_s']}s boot={res['boot_to_ready_s']}s {res['error']}", flush=True)
    write_json(REPORTS / "reliability.json", stats.summarize(rows))
    (REPORTS / "postmortem.md").write_text(postmortem(rows, cfg))
    print("wrote reports/reliability.json and reports/postmortem.md")


if __name__ == "__main__":
    main()
