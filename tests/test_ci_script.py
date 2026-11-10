import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "secureflow_ci.py"
spec = importlib.util.spec_from_file_location("secureflow_ci", SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for k in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_HEAD_REF", "GITHUB_SERVER_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SECUREFLOW_URL", "http://sf.test")
    monkeypatch.setenv("SECUREFLOW_TOKEN", "sf_testtoken")
    monkeypatch.setenv("GITHUB_SHA", "abc1234def")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_RUN_ID", "5")


def ok_file(tmp_path, name="r.json", data=None):
    p = tmp_path / name
    p.write_text(json.dumps({"results": []} if data is None else data))
    return str(p)


def run_main(monkeypatch, tmp_path, response, args=None):
    """Runs main() with the network replaced by `response` = (json, error)."""
    sent = {}

    def fake_post(url, token, payload, timeout, retries):
        sent.update(url=url, token=token, payload=payload)
        return response

    monkeypatch.setattr(ci, "post", fake_post)
    code = ci.main(args if args is not None else ["--report", f"bandit={ok_file(tmp_path)}"])
    return code, sent


@pytest.mark.parametrize("decision,code", [("PASS", 0), ("WARN", 0), ("BLOCK", 1), ("ERROR", 2)])
def test_exit_code_follows_decision(monkeypatch, tmp_path, decision, code):
    got, _ = run_main(monkeypatch, tmp_path, ({"decision": decision, "reasons": []}, None))
    assert got == code


@pytest.mark.parametrize("response", [
    (None, "cannot reach the API"),
    (None, "HTTP 401: bad token"),
    ({"unexpected": True}, None),
    ({"decision": "MAYBE"}, None),
    ("string", None),
])
def test_any_integration_failure_is_exit_2(monkeypatch, tmp_path, response):
    assert run_main(monkeypatch, tmp_path, response)[0] == 2


def test_missing_configuration_or_inputs_are_exit_2(monkeypatch, tmp_path):
    monkeypatch.delenv("SECUREFLOW_TOKEN")
    assert ci.main(["--report", f"bandit={ok_file(tmp_path)}"]) == 2
    monkeypatch.setenv("SECUREFLOW_TOKEN", "t")
    assert ci.main([]) == 2  # no report given
    monkeypatch.delenv("GITHUB_SHA")
    assert ci.main(["--report", f"bandit={ok_file(tmp_path)}"]) == 2  # no commit


def test_missing_empty_and_invalid_files_are_reported_as_client_errors(monkeypatch, tmp_path):
    empty = tmp_path / "e.json"; empty.write_text("")
    bad = tmp_path / "b.json"; bad.write_text("{nope")
    args = ["--report", f"bandit={tmp_path/'gone.json'}", "--report", f"gitleaks={empty}", "--report", f"pip-audit={bad}",
            "--report", f"semgrep={ok_file(tmp_path)}"]
    _, sent = run_main(monkeypatch, tmp_path, ({"decision": "ERROR", "reasons": []}, None), args)
    errs = {e["scanner"]: e["error"] for e in sent["payload"]["client_errors"]}
    assert set(errs) == {"bandit", "gitleaks", "pip-audit"}
    assert "not found" in errs["bandit"] and "empty" in errs["gitleaks"] and "not valid JSON" in errs["pip-audit"]
    assert [r["scanner"] for r in sent["payload"]["reports"]] == ["semgrep"]


def test_gitleaks_secret_is_removed_before_upload(monkeypatch, tmp_path):
    raw = json.loads((FIX / "gitleaks_real_UNSANITIZED.json").read_text())
    secret = raw[0]["Secret"]
    path = tmp_path / "g.json"; path.write_text(json.dumps(raw))
    _, sent = run_main(monkeypatch, tmp_path, ({"decision": "PASS", "reasons": []}, None), ["--report", f"gitleaks={path}"])
    wire = json.dumps(sent["payload"])
    assert secret not in wire and '"Secret"' not in wire and '"Match"' not in wire
    item = sent["payload"]["reports"][0]["report"][0]
    assert len(item["SecretFingerprint"]) == 16 and item["RuleID"] == "generic-api-key"


def test_secret_fingerprint_is_stable_and_not_reversible(monkeypatch):
    a = ci.sanitize_gitleaks([{"RuleID": "r", "File": "f", "StartLine": 1, "Secret": "s3cr3t"}], "tok")
    b = ci.sanitize_gitleaks([{"RuleID": "r", "File": "f", "StartLine": 99, "Secret": "s3cr3t"}], "tok")
    c = ci.sanitize_gitleaks([{"RuleID": "r", "File": "f", "StartLine": 1, "Secret": "other"}], "tok")
    assert a[0]["SecretFingerprint"] == b[0]["SecretFingerprint"] != c[0]["SecretFingerprint"]
    assert "s3cr3t" not in json.dumps(a)


def test_run_metadata_comes_from_github_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    _, sent = run_main(monkeypatch, tmp_path, ({"decision": "PASS", "reasons": []}, None))
    p = sent["payload"]
    assert (p["ci_run_id"], p["ci_run_attempt"], p["commit_sha"], p["branch"], p["event"]) == ("5", 3, "abc1234def", "main", "push")
    assert p["ci_run_url"] == "https://github.com/org/repo/actions/runs/5" and sent["url"] == "http://sf.test/api/v1/ingest"


def test_dry_run_sends_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ci, "post", lambda *a, **k: pytest.fail("must not call the network"))
    assert ci.main(["--dry-run", "--report", f"bandit={ok_file(tmp_path)}"]) == 0
    assert json.loads(capsys.readouterr().out)["reports"][0]["scanner"] == "bandit"
