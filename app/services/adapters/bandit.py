import re

from .base import (
    AdapterError,
    AdapterOptions,
    BaseAdapter,
    FingerprintBuilder,
    ParseResult,
    NormalizedFinding,
    as_int,
    clean_text,
    map_severity,
    norm_path,
    require_dict,
    require_keys,
    require_list,
    sha_short,
)

SEVERITY = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNDEFINED": "Low"}
# Rules whose message/snippet embeds the hardcoded password itself.
HARDCODED_PASSWORD_RULES = {"B105", "B106", "B107"}
_QUOTED = re.compile(r"""(['"])(?:(?!\1).)*\1""")
_NUMBERED = re.compile(r"^(\d+)\s?(.*)$")


def redact_quoted(text: str) -> str:
    return _QUOTED.sub("'<redacted>'", text)


def flagged_lines(code: str, line_range: list) -> str:
    """Bandit's `code` holds the flagged line plus context, each prefixed by its line number.
    Keep only the flagged line(s), so edits to neighbouring lines don't change the fingerprint."""
    wanted = {as_int(n) for n in (line_range or [])}
    kept = []
    for raw in code.splitlines():
        m = _NUMBERED.match(raw)
        if m and as_int(m.group(1)) in wanted:
            kept.append(" ".join(m.group(2).split()))
    return "\n".join(kept)


class BanditAdapter(BaseAdapter):
    scanner = "bandit"
    category = "code"

    def parse(self, report: object, options: AdapterOptions) -> ParseResult:
        data = require_dict(report, "Bandit")
        results = require_list(data, "results", "Bandit")
        notes: list[str] = []
        fp = FingerprintBuilder(self.scanner)
        findings: list[NormalizedFinding] = []

        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            notes.append(f"Bandit could not analyse {len(errors)} file(s): results may be incomplete")

        for item in results:
            r = require_keys(
                item, ("test_id", "filename", "issue_severity", "issue_text", "line_number"), "Bandit", "a result"
            )
            test_id = clean_text(r["test_id"], 20)
            path = norm_path(r["filename"])
            text = clean_text(r["issue_text"])
            if test_id in HARDCODED_PASSWORD_RULES:
                text = redact_quoted(text)  # never keep the literal password
                fingerprint = fp.make(test_id, path)  # don't hash a low-entropy secret-bearing line
            else:
                snippet = flagged_lines(str(r.get("code") or ""), r.get("line_range") or [])
                fingerprint = fp.make(test_id, path, sha_short(snippet) if snippet else "")

            cwe = r.get("issue_cwe")
            cwe_id = f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else None
            conf = str(r.get("issue_confidence") or "").upper() or None
            findings.append(
                NormalizedFinding(
                    scanner=self.scanner,
                    category=self.category,
                    rule_id=test_id,
                    title=f"{test_id}: {clean_text(r.get('test_name') or '', 80).replace('_', ' ')}".strip(": "),
                    description=text,
                    severity=map_severity(r["issue_severity"], SEVERITY, "Medium", notes, "Bandit"),
                    confidence=conf if conf in ("HIGH", "MEDIUM", "LOW") else None,
                    file_path=path,
                    line=as_int(r["line_number"]),
                    reference=clean_text(r.get("more_info") or "", 300) or None,
                    cwe=cwe_id,
                    fingerprint=fingerprint,
                )
            )
        return ParseResult(findings, notes)
