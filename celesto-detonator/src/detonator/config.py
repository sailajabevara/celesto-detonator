"""Environment-driven configuration. Reads .env if present (never committed)."""
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv() -> None:
    p = ROOT / ".env"
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


@dataclass
class Config:
    provider: str
    backend: str
    hourly_usd: float
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    ledger_url: str
    reports_dir: Path
    logs_dir: Path
    failure_policy: str

    @property
    def llm_enabled(self) -> bool:
        k = self.llm_api_key
        return bool(k) and not k.startswith("replace") and bool(self.llm_model) and not self.llm_model.startswith("replace")

    @classmethod
    def from_env(cls) -> "Config":
        _load_dotenv()
        g = os.environ.get
        provider = g("CELESTO_PROVIDER", "local")
        rd = Path(g("REPORTS_DIR", "reports"))
        rd = rd if rd.is_absolute() else ROOT / rd
        # Local runtime is free; cloud is billed per running hour.
        default_rate = "0.015" if provider == "cloud" else "0"
        return cls(
            provider=provider,
            backend=g("CELESTO_BACKEND", "firecracker"),
            hourly_usd=float(g("CELESTO_HOURLY_USD", default_rate)),
            llm_base_url=g("LLM_BASE_URL", ""),
            llm_api_key=g("LLM_API_KEY", ""),
            llm_model=g("LLM_MODEL", ""),
            ledger_url=g("LEDGER_URL", "http://localhost:8080"),
            reports_dir=rd,
            logs_dir=ROOT / "logs",
            failure_policy=g("FAILURE_POLICY", "rollback"),
        )
