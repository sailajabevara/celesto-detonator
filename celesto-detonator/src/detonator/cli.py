import argparse
import json
import sys

from .config import Config
from .fixtures_build import FIXTURES, build
from .pipeline import Detonation
from .sandbox import install_signal_handlers


def main(argv=None):
    ap = argparse.ArgumentParser(prog="detonator")
    ap.add_argument("fixture", choices=list(FIXTURES), help="built-in fixture package to detonate")
    ap.add_argument("--no-agent", action="store_true")
    ap.add_argument("--policy", choices=["resume", "rollback", "fresh"])
    ap.add_argument("--inject-failure", action="store_true", help="crash step 7 on purpose")
    a = ap.parse_args(argv)
    install_signal_handlers()
    cfg = Config.from_env()
    _, module, expected = FIXTURES[a.fixture]
    res = Detonation(cfg, build(a.fixture), module, label=expected, policy=a.policy,
                     inject_failure=a.inject_failure, use_agent=not a.no_agent).run()
    res.pop("report", None)
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
