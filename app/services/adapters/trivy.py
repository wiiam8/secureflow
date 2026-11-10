from .base import (
    AdapterError,
    AdapterOptions,
    BaseAdapter,
    FingerprintBuilder,
    NormalizedFinding,
    ParseResult,
    clean_text,
    map_severity,
    require_dict,
    require_keys,
)

SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Low"}


class TrivyAdapter(BaseAdapter):
    scanner = "trivy"
    category = "container"

    def parse(self, report: object, options: AdapterOptions) -> ParseResult:
        data = require_dict(report, "Trivy")
        if "SchemaVersion" not in data and "Results" not in data and "ArtifactName" not in data:
            raise AdapterError("Trivy report does not look like Trivy JSON (no SchemaVersion/Results)")
        results = data.get("Results")
        if results is None:
            results = []  # Trivy omits `Results` when the image is clean
        if not isinstance(results, list):
            raise AdapterError("Trivy report: 'Results' must be a list")

        notes: list[str] = []
        fp = FingerprintBuilder(self.scanner)
        findings: list[NormalizedFinding] = []
        skipped_lang = 0
        seen_keys: set[tuple] = set()

        for res in results:
            r = require_keys(res, ("Target",), "Trivy", "a result")
            vulns = r.get("Vulnerabilities") or []
            if not isinstance(vulns, list):
                raise AdapterError("Trivy: 'Vulnerabilities' must be a list")
            target = clean_text(r["Target"], 200)
            if r.get("Class") == "lang-pkgs" and not options.trivy_include_lang_pkgs:
                skipped_lang += len(vulns)  # pip-audit already covers Python packages
                continue
            for v in vulns:
                vv = require_keys(v, ("VulnerabilityID", "PkgName", "Severity"), "Trivy", "a vulnerability")
                vuln_id = clean_text(vv["VulnerabilityID"], 100)
                pkg = clean_text(vv["PkgName"], 100)
                installed = clean_text(vv.get("InstalledVersion") or "", 60) or None
                dedupe_key = (target, pkg, vuln_id, installed)
                if dedupe_key in seen_keys:  # same vulnerability listed twice
                    continue
                seen_keys.add(dedupe_key)
                cwes = vv.get("CweIDs")
                findings.append(
                    NormalizedFinding(
                        scanner=self.scanner,
                        category=self.category,
                        rule_id=vuln_id,
                        title=clean_text(vv.get("Title") or f"{pkg}: {vuln_id}", 300),
                        description=clean_text(vv.get("Description") or f"{vuln_id} in {pkg}"),
                        severity=map_severity(vv["Severity"], SEVERITY, "Medium", notes, "Trivy"),
                        file_path=None,
                        component=f"{pkg}@{installed}" if installed else pkg,
                        installed_version=installed,
                        fixed_version=clean_text(vv.get("FixedVersion") or "", 100) or None,
                        reference=vuln_id,
                        cwe=clean_text(cwes[0], 20) if isinstance(cwes, list) and cwes else None,
                        fingerprint=fp.make(target, pkg, vuln_id),  # unique after the dedupe above
                    )
                )
        if skipped_lang:
            notes.append(f"Trivy: {skipped_lang} language-package finding(s) ignored (covered by pip-audit)")
        return ParseResult(findings, notes)
