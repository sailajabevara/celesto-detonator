"""FIXTURE - 'install noise': legitimate-but-busy build (reads OS info, runs a helper python, writes a build log)."""
import subprocess
import sys

from setuptools import setup

try:
    open("/etc/os-release").read()
    subprocess.run([sys.executable, "-c", "print('probing platform')"], check=False, capture_output=True)
    open("/work/noisy_build.log", "w").write("built ok\n")
except Exception:
    pass
setup(name="noisy-demo", version="0.1", packages=["noisy_demo"])
