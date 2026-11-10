from .bandit import BanditAdapter
from .base import AdapterError, AdapterOptions, NormalizedFinding, ParseResult
from .gitleaks import GitleaksAdapter
from .pip_audit import PipAuditAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter

ADAPTERS = {
    a.scanner: a
    for a in (BanditAdapter(), SemgrepAdapter(), PipAuditAdapter(), GitleaksAdapter(), TrivyAdapter())
}
SCANNER_CATEGORY = {name: a.category for name, a in ADAPTERS.items()}


def normalize_scanner_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


__all__ = [
    "ADAPTERS",
    "SCANNER_CATEGORY",
    "AdapterError",
    "AdapterOptions",
    "NormalizedFinding",
    "ParseResult",
    "normalize_scanner_name",
]
