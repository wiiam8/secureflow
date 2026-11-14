"""Fail-closed scenarios: an integration problem must never end as PASS (exit code 2)."""
import importlib.util
import json
import socket
from pathlib import Path

import pytest

from tests.conftest import CLEAN

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "secureflow_ci.py"
spec = importlib.util.spec_from_file_location("secureflow_ci_scenarios", SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def free_closed_port() -> int:
    """A local port on which nobody is listening (simulates a stopped API)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def ci_env(monkeypatch):
    for k in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_HEAD_REF", "GITHUB_SERVER_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SECUREFLOW_TOKEN", "sf_testtoken")
    monkeypatch.setenv("GITHUB_SHA", "abc1234def")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_RUN_ID", "1")


def test_api_down_is_exit_2_on_a_real_socket(monkeypatch, tmp_path, ci_env, capsys):
    """Scenario e: nothing listens on the port -> ERROR, never PASS (no mock of the network)."""
    monkeypatch.setenv("SECUREFLOW_URL", f"http://127.0.0.1:{free_closed_port()}")
    report = tmp_path / "bandit.json"
    report.write_text(json.dumps({"results": []}))
    code = ci.main(["--report", f"bandit={report}", "--retries", "0", "--timeout", "2"])
    captured = capsys.readouterr()
    assert code == 2
    assert "FAIL-CLOSED" in captured.out + captured.err


# ---- the server rejects malformed reports of every supported scanner -----------------------------
@pytest.mark.parametrize("scanner", ["pip-audit", "semgrep", "trivy"])
@pytest.mark.parametrize("bad", [{"oops": 1}, [1, 2], "text", None])
def test_malformed_optional_scanner_report_is_error(pipeline, scanner, bad):
    reports = {**CLEAN, scanner: bad}
    body = pipeline.run(reports).json()
    assert body["decision"] == "ERROR" and body["exit_code"] == 2
    assert any(x["type"] == "integration_error" for x in body["reasons"])


def test_empty_valid_report_is_not_an_error(pipeline):
    """Counter-check: a well-formed report with zero findings is a legitimate PASS."""
    body = pipeline.run(CLEAN).json()
    assert body["decision"] == "PASS" and body["exit_code"] == 0