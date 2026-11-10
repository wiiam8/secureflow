import json

import pytest

from app.services.adapters import ADAPTERS, AdapterError, AdapterOptions
from tests.conftest import load

O = AdapterOptions()
SECRET = "7c9e2f41ab8d03e65f1a9b4c7d2e8f30"


def parse(name, data, opts=O):
    return ADAPTERS[name].parse(data, opts)


# ---- Bandit ---------------------------------------------------------------------------------
def test_bandit_real_report():
    res = parse("bandit", load("bandit_real.json"))
    assert len(res.findings) == 8
    sev = sorted(f.severity for f in res.findings)
    assert sev == ["High"] * 3 + ["Low"] * 2 + ["Medium"] * 3
    b602 = next(f for f in res.findings if f.rule_id == "B602")
    assert b602.category == "code" and b602.file_path == "app/main.py" and b602.line == 30
    assert b602.cwe == "CWE-78" and b602.confidence == "HIGH"


def test_bandit_hardcoded_password_never_kept():
    res = parse("bandit", load("bandit_real.json"))
    blob = json.dumps([f.__dict__ for f in res.findings])
    assert "SuperSecret123" not in blob
    assert "<redacted>" in next(f for f in res.findings if f.rule_id == "B105").description


def test_bandit_fingerprint_survives_line_shift():
    base = load("bandit_real.json")
    shifted = json.loads(json.dumps(base))
    for r in shifted["results"]:
        r["line_number"] += 7
        r["line_range"] = [n + 7 for n in r["line_range"]]
        r["code"] = "\n".join(
            f"{int(l.split(' ', 1)[0]) + 7} {l.split(' ', 1)[1] if ' ' in l else ''}" for l in r["code"].splitlines()
        )
    a = {f.fingerprint for f in parse("bandit", base).findings}
    b = {f.fingerprint for f in parse("bandit", shifted).findings}
    assert a == b


def test_bandit_identical_issues_stay_distinct():
    item = {"test_id": "B101", "test_name": "assert_used", "filename": "a.py", "issue_severity": "LOW",
            "issue_confidence": "HIGH", "issue_text": "assert", "line_number": 3, "line_range": [3], "code": "3 assert x\n"}
    res = parse("bandit", {"results": [item, dict(item, line_number=9, line_range=[9], code="9 assert x\n")]})
    assert len({f.fingerprint for f in res.findings}) == 2


@pytest.mark.parametrize("bad", [None, [], "x", 3, {}, {"results": None}, {"results": "x"},
                                 {"results": [{"test_id": "B1"}]}, {"results": ["str"]}])
def test_bandit_rejects_malformed(bad):
    with pytest.raises(AdapterError):
        parse("bandit", bad)


def test_bandit_unknown_severity_is_noted_not_dropped():
    item = {"test_id": "B1", "filename": "a.py", "issue_severity": "WEIRD", "issue_text": "t", "line_number": 1}
    res = parse("bandit", {"results": [item]})
    assert res.findings[0].severity == "Medium" and any("unrecognised severity" in n for n in res.notes)


# ---- Gitleaks -------------------------------------------------------------------------------
def test_gitleaks_real_report_secret_never_leaves_adapter():
    res = parse("gitleaks", load("gitleaks_real_UNSANITIZED.json"))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert (f.category, f.severity, f.file_path, f.line, f.rule_id) == ("secret", "High", "app/main.py", 16, "generic-api-key")
    assert SECRET not in json.dumps(f.__dict__)


def test_gitleaks_empty_and_null_are_clean():
    assert parse("gitleaks", []).findings == []
    assert parse("gitleaks", None).findings == []


@pytest.mark.parametrize("bad", [{}, "x", {"a": 1}, [{"RuleID": "r"}], ["str"]])
def test_gitleaks_rejects_malformed(bad):
    with pytest.raises(AdapterError):
        parse("gitleaks", bad)


def test_gitleaks_severity_comes_from_policy_options():
    res = parse("gitleaks", load("gitleaks_real_UNSANITIZED.json"), AdapterOptions(default_severities={"secret": "Critical"}))
    assert res.findings[0].severity == "Critical"


# ---- pip-audit ------------------------------------------------------------------------------
def test_pip_audit_real_report_is_deduplicated():
    res = parse("pip-audit", load("pip_audit_real.json"))
    assert len(res.findings) == 23  # pip-audit listed 44 entries
    assert len({f.fingerprint for f in res.findings}) == 23
    f = next(x for x in res.findings if x.reference == "CVE-2023-30861")
    assert f.component == "flask==2.0.1" and f.fixed_version == "2.2.5, 2.3.2" and f.severity == "High"


def test_pip_audit_configurable_default_severity():
    res = parse("pip-audit", load("pip_audit_real.json"), AdapterOptions(default_severities={"dependency": "Medium"}))
    assert {f.severity for f in res.findings} == {"Medium"}


def test_pip_audit_clean_and_skipped():
    assert parse("pip-audit", {"dependencies": [{"name": "x", "version": "1", "vulns": []}]}).findings == []
    res = parse("pip-audit", {"dependencies": [{"name": "mine", "skip_reason": "not on PyPI"}]})
    assert res.findings == []


@pytest.mark.parametrize("bad", [None, "x", {}, {"dependencies": "x"}, {"dependencies": [{"name": "x"}]},
                                 {"dependencies": [{"name": "x", "version": "1"}]}])
def test_pip_audit_rejects_malformed(bad):
    with pytest.raises(AdapterError):
        parse("pip-audit", bad)


# ---- Semgrep --------------------------------------------------------------------------------
def test_semgrep_real_report():
    res = parse("semgrep", load("semgrep_real.json"))
    assert len(res.findings) == 2
    a = next(f for f in res.findings if f.rule_id.endswith("subprocess-shell-true"))
    assert (a.severity, a.cwe, a.confidence, a.line) == ("High", "CWE-78", "HIGH", 30)
    assert next(f for f in res.findings if f.rule_id.endswith("yaml-unsafe-load")).severity == "Medium"


def test_semgrep_without_code_still_gets_distinct_stable_fingerprints():
    base = load("semgrep_real.json")
    fps = [f.fingerprint for f in parse("semgrep", base).findings]
    assert len(set(fps)) == 2
    assert fps == [f.fingerprint for f in parse("semgrep", base).findings]


@pytest.mark.parametrize("bad", [None, [], {}, {"results": [{"check_id": "x"}]}])
def test_semgrep_rejects_malformed(bad):
    with pytest.raises(AdapterError):
        parse("semgrep", bad)


# ---- Trivy ----------------------------------------------------------------------------------
def test_trivy_os_packages_only_and_deduplicated():
    res = parse("trivy", load("trivy_handwritten.json"))
    assert len(res.findings) == 3  # duplicate zlib entry merged, python lang-pkgs ignored (pip-audit covers them)
    assert any("ignored" in n for n in res.notes)
    crit = next(f for f in res.findings if f.reference == "CVE-2019-1010022")
    assert crit.severity == "Critical" and crit.category == "container" and crit.component == "libc6@2.28-10+deb10u2"


def test_trivy_can_include_language_packages():
    res = parse("trivy", load("trivy_handwritten.json"), AdapterOptions(trivy_include_lang_pkgs=True))
    assert len(res.findings) == 4


def test_trivy_clean_image_has_no_results_key():
    assert parse("trivy", {"SchemaVersion": 2, "ArtifactName": "x"}).findings == []


@pytest.mark.parametrize("bad", [None, [], {}, {"foo": 1}, {"SchemaVersion": 2, "Results": "x"},
                                 {"Results": [{"Target": "t", "Vulnerabilities": [{"PkgName": "p"}]}]}])
def test_trivy_rejects_malformed(bad):
    with pytest.raises(AdapterError):
        parse("trivy", bad)
