"""Adapters checked against REAL scanner output (Trivy, Semgrep with registry rules).

The expectations are derived from the report itself, so they stay valid whatever the exact content.
Add the real reports as tests/fixtures/trivy_real.json and tests/fixtures/semgrep_registry_real.json.
"""
from pathlib import Path

import pytest

from app.constants import SEVERITIES
from app.services.adapters import ADAPTERS, AdapterOptions
from tests.conftest import FIX, load

O = AdapterOptions()
need = lambda name: pytest.mark.skipif(not (Path(FIX) / name).exists(), reason=f"{name} not in tests/fixtures")


def parse(name, data, opts=O):
    return ADAPTERS[name].parse(data, opts)


# ---- Trivy ------------------------------------------------------------------------------------
@need("trivy_real.json")
def test_trivy_real_report_is_parsed():
    data = load("trivy_real.json")
    res = parse("trivy", data)

    # expected = unique (target, package, CVE, installed version) of OS packages only
    expected = {
        (r["Target"], v["PkgName"], v["VulnerabilityID"], v.get("InstalledVersion"))
        for r in data.get("Results", [])
        if r.get("Class") != "lang-pkgs"
        for v in (r.get("Vulnerabilities") or [])
    }
    assert len(res.findings) == len(expected)
    assert len({f.fingerprint for f in res.findings}) == len(res.findings)  # stable and distinct
    assert all(f.category == "container" and f.severity in SEVERITIES for f in res.findings)
    assert all(f.component and f.reference for f in res.findings)
    assert not any("unrecognised severity" in n for n in res.notes)


@need("trivy_real.json")
def test_trivy_real_report_language_packages_are_optional():
    data = load("trivy_real.json")
    base = parse("trivy", data).findings
    with_lang = parse("trivy", data, AdapterOptions(trivy_include_lang_pkgs=True)).findings
    assert len(with_lang) >= len(base)


# ---- Semgrep (registry rules) -----------------------------------------------------------------
@need("semgrep_registry_real.json")
def test_semgrep_registry_report_is_parsed():
    data = load("semgrep_registry_real.json")
    res = parse("semgrep", data)

    assert len(res.findings) == len(data["results"])
    assert len({f.fingerprint for f in res.findings}) == len(res.findings)
    assert all(f.category == "code" and f.severity in SEVERITIES for f in res.findings)
    assert all(f.file_path and f.rule_id for f in res.findings)
    assert not any("unrecognised severity" in n for n in res.notes)


@need("semgrep_registry_real.json")
def test_semgrep_registry_fingerprints_are_stable():
    data = load("semgrep_registry_real.json")
    a = [f.fingerprint for f in parse("semgrep", data).findings]
    b = [f.fingerprint for f in parse("semgrep", data).findings]
    assert a == b