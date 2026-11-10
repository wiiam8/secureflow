import hashlib

from .base import (
    AdapterError,
    AdapterOptions,
    BaseAdapter,
    NormalizedFinding,
    ParseResult,
    clean_text,
    map_severity,
    require_keys,
)

SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}


class PipAuditAdapter(BaseAdapter):
    """pip-audit reports known vulnerabilities but NO severity. The severity assigned here is the
    policy's `default_severities.dependency` (default High: fail safe). See docs/RISK_MODEL.md."""

    scanner = "pip-audit"
    category = "dependency"

    def parse(self, report: object, options: AdapterOptions) -> ParseResult:
        if isinstance(report, dict):
            deps = report.get("dependencies")
        else:
            deps = report  # older pip-audit versions emit a bare list
        if not isinstance(deps, list):
            raise AdapterError("pip-audit report is missing the 'dependencies' list")

        notes: list[str] = []
        severity = map_severity(
            options.default_severities.get("dependency", "High"), SEVERITY, "High", notes, "pip-audit"
        )
        findings: list[NormalizedFinding] = []
        by_key: dict[tuple[str, str], NormalizedFinding] = {}  # pip-audit repeats entries / uses several ids
        skipped = 0

        for dep in deps:
            d = require_keys(dep, ("name",), "pip-audit", "a dependency")
            if "skip_reason" in d and not d.get("vulns"):  # e.g. private package: no version, not audited
                skipped += 1
                continue
            require_keys(d, ("version",), "pip-audit", "a dependency")
            vulns = d.get("vulns")
            if not isinstance(vulns, list):
                raise AdapterError(f"pip-audit: dependency '{clean_text(d['name'], 60)}' has no 'vulns' list")
            name = clean_text(d["name"], 100)
            version = clean_text(d["version"], 50)
            for v in vulns:
                vv = require_keys(v, ("id",), "pip-audit", "a vulnerability")
                vuln_id = clean_text(vv["id"], 100)
                aliases = [clean_text(a, 60) for a in (vv.get("aliases") or []) if isinstance(a, str)]
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                fixes = [clean_text(x, 40) for x in (vv.get("fix_versions") or []) if isinstance(x, str)]
                canonical = cve or vuln_id  # stable even if pip-audit switches between PYSEC/GHSA ids
                key = (name.lower(), canonical)
                prev = by_key.get(key)
                if prev is not None:  # same vulnerability again: merge the known fixed versions
                    merged = dict.fromkeys([*(prev.fixed_version or "").split(", "), *fixes])
                    prev.fixed_version = ", ".join(x for x in merged if x) or None
                    continue
                nf = NormalizedFinding(
                    scanner=self.scanner,
                    category=self.category,
                    rule_id=vuln_id,
                    title=f"{name} {version}: {canonical}",
                    description=clean_text(vv.get("description") or f"Known vulnerability {vuln_id}"),
                    severity=severity,
                    component=f"{name}=={version}",
                    installed_version=version,
                    fixed_version=", ".join(fixes) or None,
                    reference=canonical,
                    fingerprint=hashlib.sha256(f"pip-audit|{name.lower()}|{canonical}".encode()).hexdigest()[:40],
                )
                by_key[key] = nf
                findings.append(nf)
        if skipped:
            notes.append(f"pip-audit skipped {skipped} dependency(ies) it could not audit")
        return ParseResult(findings, notes)
