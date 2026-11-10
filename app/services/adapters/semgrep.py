import re

from .base import (
    AdapterOptions,
    BaseAdapter,
    FingerprintBuilder,
    NormalizedFinding,
    ParseResult,
    as_int,
    clean_text,
    map_severity,
    norm_path,
    require_dict,
    require_keys,
    require_list,
    sha_short,
)

SEVERITY = {
    "CRITICAL": "Critical",
    "ERROR": "High",
    "HIGH": "High",
    "WARNING": "Medium",
    "MEDIUM": "Medium",
    "INFO": "Low",
    "LOW": "Low",
    "INVENTORY": "Info",
    "EXPERIMENT": "Info",
}
_CWE = re.compile(r"CWE-\d+", re.I)


def _first(value):
    if isinstance(value, list) and value:
        return value[0]
    return value


class SemgrepAdapter(BaseAdapter):
    scanner = "semgrep"
    category = "code"

    def parse(self, report: object, options: AdapterOptions) -> ParseResult:
        data = require_dict(report, "Semgrep")
        results = require_list(data, "results", "Semgrep")
        notes: list[str] = []
        fp = FingerprintBuilder(self.scanner)
        findings: list[NormalizedFinding] = []

        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            notes.append(f"Semgrep reported {len(errors)} error(s): results may be incomplete")

        for item in results:
            r = require_keys(item, ("check_id", "path", "start", "extra"), "Semgrep", "a result")
            extra = require_keys(r["extra"], ("severity", "message"), "Semgrep", "a result's 'extra'")
            start = r["start"] if isinstance(r["start"], dict) else {}
            meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}

            rule = clean_text(r["check_id"], 200)
            path = norm_path(r["path"])
            lines = extra.get("lines")
            # Semgrep OSS without login returns "requires login" instead of the code: fall back to
            # an occurrence index (stable against line shifts, unlike the line number).
            usable = isinstance(lines, str) and lines.strip() and lines.strip().lower() != "requires login"
            snippet = " ".join(lines.split()) if usable else ""
            fingerprint = fp.make(rule, path, sha_short(snippet) if snippet else "")

            cwe_raw = _first(meta.get("cwe"))
            m = _CWE.search(str(cwe_raw)) if cwe_raw else None
            conf = str(meta.get("confidence") or "").upper() or None
            short_rule = rule.rsplit(".", 1)[-1]
            findings.append(
                NormalizedFinding(
                    scanner=self.scanner,
                    category=self.category,
                    rule_id=rule,
                    title=short_rule.replace("-", " ").replace("_", " ").capitalize(),
                    description=clean_text(extra["message"]),
                    severity=map_severity(extra["severity"], SEVERITY, "Medium", notes, "Semgrep"),
                    confidence=conf if conf in ("HIGH", "MEDIUM", "LOW") else None,
                    file_path=path,
                    line=as_int(start.get("line")),
                    reference=clean_text(_first(meta.get("references")) or "", 300) or None,
                    cwe=m.group(0).upper() if m else None,
                    fingerprint=fingerprint,
                )
            )
        return ParseResult(findings, notes)
