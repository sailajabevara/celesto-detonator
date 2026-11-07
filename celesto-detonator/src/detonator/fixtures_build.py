"""Build deterministic sdist tarballs from fixtures/*/ using only the stdlib (no setuptools on host)."""
import io
import tarfile
from pathlib import Path

from .config import ROOT

FIXTURES = {
    # name: (dir, module, expected verdict)
    "evil-demo": ("evil_demo", "evil_demo", "malicious"),
    "benign-demo": ("benign_demo", "benign_demo", "benign"),
    "noisy-demo": ("noisy_demo", "noisy_demo", "benign"),
}


def build(name: str, out_dir: Path | None = None) -> Path:
    src = ROOT / "fixtures" / FIXTURES[name][0]
    out = (out_dir or ROOT / "fixtures" / "dist")
    out.mkdir(parents=True, exist_ok=True)
    top = f"{name}-0.1"
    path = out / f"{top}.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for f in sorted(src.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                data = f.read_bytes()
                ti = tarfile.TarInfo(f"{top}/{f.relative_to(src)}")
                ti.size, ti.mtime = len(data), 0
                tf.addfile(ti, io.BytesIO(data))
    return path


def build_all() -> dict[str, Path]:
    return {n: build(n) for n in FIXTURES}
