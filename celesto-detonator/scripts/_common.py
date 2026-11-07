import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detonator.config import Config  # noqa: E402
from detonator.fixtures_build import FIXTURES, build  # noqa: E402
from detonator.pipeline import Detonation  # noqa: E402
from detonator.sandbox import install_signal_handlers, new_name  # noqa: E402

REPORTS = ROOT / "reports"
EVIDENCE = REPORTS / "evidence"


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")


def detonate(fixture: str, cfg: Config, **kw) -> dict:
    _, module, expected = FIXTURES[fixture]
    return Detonation(cfg, build(fixture), module, label=expected, **kw).run()
