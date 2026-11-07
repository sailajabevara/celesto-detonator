"""Host-side safety hook: runs BEFORE the guest sees a command and can block it.

Commands from the orchestrator (fixed strings in pipeline.py) are trusted and only audited.
Commands that come from the LLM agent (origin="agent") are untrusted and checked.
A system-prompt sentence cannot do this; code can.
"""
import re

_B = r"(^|[\s;|&(`$])"
RULES: list[tuple[str, re.Pattern]] = [
    ("network_tool", re.compile(_B + r"(curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|ftp)(\s|$)")),
    ("destructive_rm", re.compile(r"\brm\s+(-\w+\s+)*-\w*[rf]\w*\s+(/\*?|~|\$HOME\*?|\*)(\s|$)")),
    ("destructive_disk", re.compile(r"(\bmkfs\b|\bdd\s+.*of=/dev/|>\s*/dev/(sd|vd|nvme))")),
    ("fork_bomb", re.compile(r":\(\)\s*\{")),
    ("power", re.compile(_B + r"(shutdown|reboot|poweroff|halt)(\s|$)")),
    ("secret_path", re.compile(r"(\.aws|\.ssh|id_rsa|id_ed25519|\.netrc|\.gnupg|\.kube|/etc/shadow|/proc/[^\s]*/environ)")),
    ("env_dump", re.compile(r"(\bprintenv\b|(^|[;&|]\s*)env\s*($|\|)|\$CANARY|CANARY_TOKEN)")),
]


def check(command: str, origin: str = "agent") -> tuple[str, str]:
    """Return (decision, reason). decision is 'allow' or 'block'."""
    if origin == "orchestrator":
        return "allow", "trusted orchestrator command"
    for name, rx in RULES:
        if rx.search(command):
            return "block", name
    return "allow", ""
