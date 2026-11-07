"""Reliability statistics with the exact rules the grader uses."""
import math


def median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def p90(xs: list[float]) -> float:
    s = sorted(xs)
    k = math.ceil(round(0.9 * len(s), 9))  # 1-based rank
    return s[k - 1]


def summarize(runs: list[dict], postmortem_path: str = "reports/postmortem.md") -> dict:
    n = len(runs)
    return {
        "run_count": n,
        "runs": runs,
        "success_rate": sum(1 for r in runs if r["success"]) / n,
        "median_wall_clock_s": round(median([r["wall_clock_s"] for r in runs]), 3),
        "p90_wall_clock_s": round(p90([r["wall_clock_s"] for r in runs]), 3),
        "median_boot_to_ready_s": round(median([r["boot_to_ready_s"] for r in runs]), 3),
        "total_cost_usd": round(sum(r["cost_usd"] for r in runs), 6),
        "postmortem_path": postmortem_path,
    }
