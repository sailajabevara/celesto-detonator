"""Builds lifecycle.json from real drill results and injects the eval table into README."""
import json
import re

from _common import *  # noqa


def main():
    drills = json.loads((EVIDENCE / "lifecycle_drills.json").read_text())
    rel = json.loads((REPORTS / "reliability.json").read_text())
    names = list(dict.fromkeys([r["sandbox_name"] for r in rel["runs"]] + drills["sandbox_names"]))
    d = drills["drills"]
    write_json(REPORTS / "lifecycle.json", {
        "cleanup_on_success": d["success"], "cleanup_on_failure": d["failure"], "cleanup_on_interrupt": d["interrupt"],
        "sandbox_names": names})
    fails = sum(not r["success"] for r in rel["runs"])
    table = (f"| Metric | Value |\n|---|---|\n| Runs (fresh sandbox each) | {rel['run_count']} |\n"
             f"| Success rate | {rel['success_rate']*100:.1f}% ({rel['run_count']-fails}/{rel['run_count']}) |\n"
             f"| Median wall-clock | {rel['median_wall_clock_s']} s |\n| p90 wall-clock | {rel['p90_wall_clock_s']} s |\n"
             f"| Median boot-to-ready | {rel['median_boot_to_ready_s']} s |\n| Total cost | ${rel['total_cost_usd']} |\n")
    rd = ROOT / "README.md"
    txt = rd.read_text()
    new = re.sub(r"<!-- EVAL:START -->.*<!-- EVAL:END -->", lambda m: f"<!-- EVAL:START -->\n{table}<!-- EVAL:END -->", txt, flags=re.S)
    rd.write_text(new)
    print("lifecycle.json + README eval table written;", d)


if __name__ == "__main__":
    main()
