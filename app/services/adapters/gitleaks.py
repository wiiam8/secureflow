"""Gitleaks adapter.

SECURITY: this adapter only reads the fields listed in SAFE_FIELDS. The `Secret`, `Match`,
`Author`, `Email` and `Message` fields are never read, copied or stored, even if present.
"""
from .base import (
    AdapterError,
    AdapterOptions,
    BaseAdapter,
    FingerprintBuilder,
    NormalizedFinding,
    ParseResult,
    as_int,
    clean_text,
    map_severity,
    norm_path,
    require_keys,
)

SAFE_FIELDS = ("RuleID", "Description", "File", "StartLine", "Commit", "SecretFingerprint")
SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}


class GitleaksAdapter(BaseAdapter):
    scanner = "gitleaks"
    category = "secret"

    def parse(self, report: object, options: AdapterOptions) -> ParseResult:
        # Gitleaks writes `[]` (or `null` in some versions) when nothing is found.
        if report is None:
            report = []
        if not isinstance(report, list):
            raise AdapterError("Gitleaks report must be a JSON array")

        notes: list[str] = []
        severity = map_severity(
            options.default_severities.get("secret", "High"), SEVERITY, "High", notes, "Gitleaks"
        )
        fp = FingerprintBuilder(self.scanner)
        findings: list[NormalizedFinding] = []

        for item in report:
            r = require_keys(item, ("RuleID", "File", "StartLine"), "Gitleaks", "a result")
            rule = clean_text(r["RuleID"], 100)
            path = norm_path(r["File"])
            # The CI script adds an HMAC of the secret (stable across line shifts, not reversible).
            secret_fp = clean_text(r.get("SecretFingerprint") or "", 64)
            fingerprint = fp.make(rule, path, secret_fp)
            commit = clean_text(r.get("Commit") or "", 12)
            desc = clean_text(r.get("Description") or "Potential secret detected")
            if commit:
                desc += f" (commit {commit})"
            findings.append(
                NormalizedFinding(
                    scanner=self.scanner,
                    category=self.category,
                    rule_id=rule,
                    title=f"Potential secret detected ({rule})",
                    description=desc,
                    severity=severity,
                    file_path=path,
                    line=as_int(r["StartLine"]),
                    reference=rule,
                    fingerprint=fingerprint,
                )
            )
        return ParseResult(findings, notes)
