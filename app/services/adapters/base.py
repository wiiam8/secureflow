"""Common model + helpers for scanner adapters.

Adapters are STRICT: a report that does not have the expected structure raises AdapterError,
which the ingest service turns into an integration error (fail-closed, never PASS).
Adapters never invent information the scanner did not provide.
"""
import hashlib
import re
from dataclasses import dataclass, field

MAX_TEXT = 2000


class AdapterError(Exception):
    """The report is missing, malformed or not what this adapter expects."""


@dataclass
class AdapterOptions:
    # Severity used when a scanner provides none (pip-audit, gitleaks). Configurable in the policy.
    default_severities: dict[str, str] = field(
        default_factory=lambda: {"dependency": "High", "secret": "High"}
    )
    # Trivy also reports language packages found in the image; pip-audit already covers those.
    trivy_include_lang_pkgs: bool = False


@dataclass
class NormalizedFinding:
    scanner: str
    category: str  # code | dependency | secret | container
    rule_id: str
    title: str
    description: str
    severity: str  # Critical | High | Medium | Low | Info
    fingerprint: str
    confidence: str | None = None  # HIGH | MEDIUM | LOW when the scanner provides it
    file_path: str | None = None
    line: int | None = None
    component: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    reference: str | None = None
    cwe: str | None = None


@dataclass
class ParseResult:
    findings: list[NormalizedFinding]
    notes: list[str] = field(default_factory=list)  # e.g. "2 files could not be parsed"


class FingerprintBuilder:
    """Builds stable identifiers. Identical keys inside one report get an occurrence suffix."""

    def __init__(self, scanner: str):
        self.scanner = scanner
        self._seen: dict[str, int] = {}

    def make(self, *parts: object) -> str:
        key = "|".join(str(p) for p in (self.scanner, *parts))
        n = self._seen.get(key, 0)
        self._seen[key] = n + 1
        return hashlib.sha256(f"{key}|#{n}".encode()).hexdigest()[:40]


def sha_short(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def clean_text(value: object, limit: int = MAX_TEXT) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def norm_path(path: object) -> str:
    p = clean_text(path, 500).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def map_severity(raw: object, table: dict[str, str], default: str, notes: list[str], scanner: str) -> str:
    key = str(raw or "").strip().upper()
    if key in table:
        return table[key]
    note = f"{scanner}: unrecognised severity '{clean_text(raw, 40)}' treated as {default}"
    if note not in notes:
        notes.append(note)
    return default


def as_int(value: object) -> int | None:
    try:
        n = int(value)  # type: ignore[arg-type]
        return n if n >= 0 else None
    except (TypeError, ValueError):
        return None


def require_dict(report: object, scanner: str) -> dict:
    if not isinstance(report, dict):
        raise AdapterError(f"{scanner} report must be a JSON object")
    return report


def require_list(container: dict, key: str, scanner: str) -> list:
    value = container.get(key)
    if not isinstance(value, list):
        raise AdapterError(f"{scanner} report is missing the '{key}' list")
    return value


def require_keys(item: object, keys: tuple[str, ...], scanner: str, where: str) -> dict:
    if not isinstance(item, dict):
        raise AdapterError(f"{scanner}: {where} is not an object")
    missing = [k for k in keys if k not in item]
    if missing:
        raise AdapterError(f"{scanner}: {where} is missing field(s): {', '.join(missing)}")
    return item


class BaseAdapter:
    scanner = ""
    category = ""

    def parse(self, report: object, options: AdapterOptions) -> ParseResult:  # pragma: no cover
        raise NotImplementedError
