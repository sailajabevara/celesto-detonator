"""Turn raw guest audit events into a scored risk report. Deterministic: this is the ground truth.
The LLM agent may only RAISE severity, never lower it (see pipeline.final_verdict)."""
import json
import os
import re

SENSITIVE_READ = re.compile(r"(\.aws/|\.ssh/|\.gnupg/|\.netrc|\.docker/config|\.kube/|/etc/shadow|\.bash_history|\.git-credentials|\.npmrc|\.pypirc)")
PERSIST = re.compile(r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/cron|/var/spool/cron|/etc/profile\.d/|systemd|authorized_keys|rc\.local|/etc/init)")
WRITE_OK = ("/dev/", "/work/", "/tmp/pip-", "/tmp/tmp", "/root/.cache", "/root/.local", "/var/log/detonation",
            "site-packages", "dist-packages", "/usr/local/bin", "/usr/bin/", "/usr/local/lib/")
NOISE_EXEC = re.compile(r"^(python[\d.]*|pip[\d.]*|gcc|cc|c\+\+|g\+\+|ld|as|make|uname|ldconfig|git|lsb_release|getconf|ldd|which)$")
LOOPBACK = ("('127.", "('::1'", "('localhost'", "('0.0.0.0'")

def _benign_path(p: str) -> bool:
    """Ordinary install noise: known work dirs, or non-hidden temp files. Hidden dotfiles in /tmp are NOT noise."""
    if p.startswith(WRITE_OK) or any(m in p for m in ("site-packages", "dist-packages", "__pycache__")):
        return True
    return p.startswith("/tmp/") and not os.path.basename(p).startswith(".")


SEVERITY_ORDER = {"benign": 0, "suspicious": 1, "malicious": 2}


def parse_events(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def analyze(events: list[dict], fs_changes: list[str], canaries: list[str]) -> dict:
    findings: dict[str, dict] = {}

    def add(rule: str, points: int, detail: str, cap: int | None = None) -> None:
        f = findings.setdefault(rule, {"rule": rule, "points": 0, "count": 0, "examples": []})
        f["count"] += 1
        if cap is None or f["points"] + points <= cap:
            f["points"] += points
        if len(f["examples"]) < 3:
            f["examples"].append(detail[:200])

    canary_leaked = False
    for e in events:
        blob = json.dumps(e)
        if any(c and c in blob for c in canaries) and e["ev"] in ("urllib.Request", "socket.connect", "subprocess.Popen", "os.system"):
            canary_leaked = True
            add("canary_in_outbound_or_exec", 40, blob, cap=40)
        ev = e["ev"]
        if ev == "open":
            p, w = e.get("path", ""), e.get("write", False)
            if not w and SENSITIVE_READ.search(p):
                add("sensitive_file_read", 35, p, cap=35)
            if w and PERSIST.search(p):
                add("persistence_write", 30, p, cap=30)
            elif w and os.path.isabs(p) and not _benign_path(p):
                add("unexpected_write", 5, p, cap=15)
        elif ev == "socket.connect":
            a = e.get("addr", "")
            if not a.startswith(LOOPBACK):
                add("network_connect_attempt", 25, a, cap=25)
        elif ev == "urllib.Request":
            add("http_request_attempt", 10, e.get("url", ""), cap=10)
        elif ev == "socket.getaddrinfo":
            h = e.get("host", "")
            if "localhost" not in h and "127.0.0.1" not in h:
                add("dns_lookup", 5, h, cap=5)
        elif ev in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
            argv = e.get("argv") or [""]
            exe = os.path.basename(argv[0].split()[0]) if argv[0].split() else ""
            if ev == "os.system" or not NOISE_EXEC.match(exe):
                add("suspicious_subprocess", 10, " ".join(argv), cap=20)
        elif ev in ("os.remove", "os.rmdir", "shutil.rmtree"):
            p = e.get("path", "")
            if os.path.isabs(p) and not _benign_path(p):
                add("delete_outside_workdir", 10, p, cap=20)
    for p in fs_changes:
        if PERSIST.search(p) and "persistence_write" not in findings:
            add("persistence_write", 30, p, cap=30)

    score = min(100, sum(f["points"] for f in findings.values()))
    verdict = "malicious" if score >= 60 else "suspicious" if score >= 20 else "benign"
    return {"score": score, "verdict": verdict, "canary_leaked": canary_leaked,
            "findings": sorted(findings.values(), key=lambda f: -f["points"]), "event_count": len(events)}


def max_verdict(a: str, b: str | None) -> str:
    if b not in SEVERITY_ORDER:
        return a
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b
