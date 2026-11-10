#!/usr/bin/env python3
"""SecureFlow CI client: uploads scanner reports and enforces the decision.

Pure standard library (runs on any GitHub runner, no pip install needed).

Usage (inside the pipeline, after the scanners ran):
    python secureflow_ci.py --report bandit=bandit.json --report gitleaks=gitleaks.json

Environment:
    SECUREFLOW_URL     base URL of the API, e.g. https://secureflow.example.org
    SECUREFLOW_TOKEN   project integration token (GitHub secret)
    GITHUB_*           run metadata, read automatically on GitHub Actions

Exit codes (the pipeline step fails on anything but 0):
    0  PASS or WARN        1  BLOCK        2  ERROR (integration error, FAIL-CLOSED)

FAIL-CLOSED: API unreachable, bad token, missing/invalid report file, malformed response... all exit 2.
Nothing here can turn a failure into a PASS.

SECURITY: for Gitleaks the `Secret`, `Match`, `Author`, `Email` and `Message` fields are removed
BEFORE upload, and an HMAC fingerprint of the secret is added so tracking still works without the
secret ever leaving the runner.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

EXIT_PASS, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2
GITLEAKS_DROP = ("Secret", "Match", "Author", "Email", "Message", "Date")
RETRY_STATUS = {502, 503, 504}


def log(msg: str) -> None:
    print(f"[secureflow] {msg}", file=sys.stderr, flush=True)


def sanitize_gitleaks(report, token: str):
    """Remove secret values; add SecretFingerprint = HMAC(token, secret)[:16]."""
    if report is None:
        return []
    if not isinstance(report, list):
        return report  # let the server reject it
    clean = []
    for item in report:
        if not isinstance(item, dict):
            clean.append(item)
            continue
        secret = str(item.get("Secret") or "")
        out = {k: v for k, v in item.items() if k not in GITLEAKS_DROP}
        if secret:
            out["SecretFingerprint"] = hmac.new(token.encode(), secret.encode(), hashlib.sha256).hexdigest()[:16]
        clean.append(out)
    return clean


def load_report(scanner: str, path: str, token: str):
    """Return (report, None) or (None, error_message)."""
    if not os.path.isfile(path):
        return None, f"report file not found: {path}"
    try:
        size = os.path.getsize(path)
        if size == 0:
            return None, f"report file is empty: {path}"
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"cannot read {path}: {exc.__class__.__name__}"
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON ({exc.msg} at line {exc.lineno})"
    if scanner == "gitleaks":
        data = sanitize_gitleaks(data, token)
    return data, None


def build_payload(args, token: str) -> dict:
    env = os.environ
    payload = {
        "ci_provider": "github-actions" if env.get("GITHUB_ACTIONS") else "ci",
        "ci_run_id": args.run_id or env.get("GITHUB_RUN_ID") or str(int(time.time())),
        "ci_run_attempt": int(args.run_attempt or env.get("GITHUB_RUN_ATTEMPT") or 1),
        "commit_sha": args.commit or env.get("GITHUB_SHA") or "",
        "branch": args.branch or env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME") or "",
        "event": env.get("GITHUB_EVENT_NAME") or None,
        "repository": env.get("GITHUB_REPOSITORY") or None,
        "reports": [],
        "client_errors": [],
    }
    if env.get("GITHUB_SERVER_URL") and env.get("GITHUB_REPOSITORY") and env.get("GITHUB_RUN_ID"):
        payload["ci_run_url"] = f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    versions = dict(v.split("=", 1) for v in (args.version or []) if "=" in v)

    for spec in args.report:
        if "=" not in spec:
            payload["client_errors"].append({"scanner": spec, "error": "invalid --report, expected scanner=path"})
            continue
        scanner, path = spec.split("=", 1)
        scanner = scanner.strip().lower()
        report, err = load_report(scanner, path.strip(), token)
        if err:
            payload["client_errors"].append({"scanner": scanner, "error": err})
        else:
            entry = {"scanner": scanner, "report": report}
            if versions.get(scanner):
                entry["version"] = versions[scanner]
            payload["reports"].append(entry)
    return payload


def post(url: str, token: str, payload: dict, timeout: int, retries: int):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "secureflow-ci/1.0"},
    )
    last = "no attempt"
    for attempt in range(1, retries + 2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL is operator-supplied)
                return json.loads(resp.read().decode()), None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            last = f"HTTP {exc.code}: {detail}"
            if exc.code not in RETRY_STATUS:
                return None, last
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last = f"cannot reach the API ({exc.__class__.__name__}: {getattr(exc, 'reason', exc)})"
        except json.JSONDecodeError:
            return None, "the API answered with something that is not JSON"
        if attempt <= retries:
            time.sleep(min(2 ** attempt, 8))
    return None, last


def github_summary(result: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    icon = {"PASS": "✅", "WARN": "⚠️", "BLOCK": "⛔", "ERROR": "🟣"}.get(result.get("decision"), "")
    lines = [f"## {icon} SecureFlow decision: {result.get('decision')}", ""]
    s = result.get("summary") or {}
    if s:
        lines.append(f"Findings: **{s.get('total', 0)}** · new {s.get('new', 0)} · resolved {s.get('resolved', 0)}")
        lines.append("")
    for r in (result.get("reasons") or [])[:25]:
        lines.append(f"- {r.get('message')}")
    if result.get("dashboard_url"):
        lines += ["", f"[Open in SecureFlow]({result['dashboard_url']})"]
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Upload scanner reports to SecureFlow and enforce the decision.")
    p.add_argument("--report", action="append", default=[], metavar="SCANNER=PATH", help="repeatable")
    p.add_argument("--version", action="append", metavar="SCANNER=VERSION", help="scanner version (optional)")
    p.add_argument("--url", default=os.environ.get("SECUREFLOW_URL", ""))
    p.add_argument("--commit"), p.add_argument("--branch"), p.add_argument("--run-id"), p.add_argument("--run-attempt")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--retries", type=int, default=2, help="retries on network error / 502-504")
    p.add_argument("--dry-run", action="store_true", help="build the payload, print it (secrets removed) and exit")
    args = p.parse_args(argv)

    token = os.environ.get("SECUREFLOW_TOKEN", "")
    if not args.dry_run and (not args.url or not token):
        log("ERROR: SECUREFLOW_URL and SECUREFLOW_TOKEN must be set. FAIL-CLOSED.")
        return EXIT_ERROR
    if not args.report:
        log("ERROR: no --report given, nothing to evaluate. FAIL-CLOSED.")
        return EXIT_ERROR

    payload = build_payload(args, token or "dry-run")
    if not payload["commit_sha"] or not payload["branch"]:
        log("ERROR: commit SHA or branch missing (are GITHUB_SHA / GITHUB_REF_NAME set?). FAIL-CLOSED.")
        return EXIT_ERROR
    for ce in payload["client_errors"]:
        log(f"problem with {ce['scanner']}: {ce['error']}")
    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return EXIT_PASS

    result, err = post(args.url.rstrip("/") + "/api/v1/ingest", token, payload, args.timeout, args.retries)
    if err or not isinstance(result, dict) or result.get("decision") not in ("PASS", "WARN", "BLOCK", "ERROR"):
        log(f"ERROR: {err or 'unexpected response from the API'}. FAIL-CLOSED: the pipeline must not proceed.")
        github_summary({"decision": "ERROR", "reasons": [{"message": err or "unexpected API response"}]})
        return EXIT_ERROR

    decision = result["decision"]
    log(f"Decision: {decision}" + (" (replay of an earlier evaluation)" if result.get("replay") else ""))
    for r in (result.get("reasons") or [])[:25]:
        log(f"  - {r.get('message')}")
    if result.get("dashboard_url"):
        log(f"Details: {result['dashboard_url']}")
    github_summary(result)
    if decision == "WARN" and os.environ.get("GITHUB_ACTIONS"):
        print("::warning title=SecureFlow::Warnings detected, review required (see the step summary).", flush=True)
    return {"PASS": EXIT_PASS, "WARN": EXIT_PASS, "BLOCK": EXIT_BLOCK}.get(decision, EXIT_ERROR)


if __name__ == "__main__":
    sys.exit(main())
