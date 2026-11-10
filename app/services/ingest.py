"""The heart of SecureFlow: report ingestion -> normalization -> risk -> policy -> decision.

FAIL-CLOSED: anything that prevents a trustworthy evaluation (malformed report, unsupported
scanner, required scanner missing, CI-side failure, no report at all) yields decision ERROR.
It is never silently turned into PASS.
"""
import hashlib
import json
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Decision, Finding, IntegrationToken, PipelineRun, Project, RunFinding, ScanReport, utcnow
from app.schemas import IngestPayload
from app.services.adapters import ADAPTERS, AdapterError, AdapterOptions, normalize_scanner_name
from app.services.audit import audit
from app.services.findings import is_excepted
from app.services.policies import get_active_policy
from app.services.policy_engine import EvalItem, PolicyRules, evaluate
from app.services.reconciliation import reconcile
from app.services.risk_engine import compute_risk

EXIT_CODES = {"PASS": 0, "WARN": 0, "BLOCK": 1, "ERROR": 2}


@dataclass
class IngestOutcome:
    run: PipelineRun
    decision: Decision
    replay: bool


def _find_run(db: Session, project_id: int, payload: IngestPayload) -> PipelineRun | None:
    return db.scalar(
        select(PipelineRun).where(
            PipelineRun.project_id == project_id,
            PipelineRun.ci_run_id == payload.ci_run_id,
            PipelineRun.ci_run_attempt == payload.ci_run_attempt,
        )
    )


def _report_hash(report: object) -> str:
    try:
        blob = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        blob = repr(report)
    return hashlib.sha256(blob.encode()).hexdigest()


def process_ingest(db: Session, project: Project, token: IntegrationToken, payload: IngestPayload) -> IngestOutcome:
    # Idempotency: the same CI run + attempt is evaluated once; retries get the stored decision.
    existing = _find_run(db, project.id, payload)
    if existing is not None and existing.decision is not None:
        return IngestOutcome(existing, existing.decision, True)

    policy_row = get_active_policy(db, project)
    policy = PolicyRules.model_validate(policy_row.rules)
    actor = f"token:{token.prefix}"
    now = utcnow()

    run = PipelineRun(
        project_id=project.id,
        ci_provider=payload.ci_provider,
        ci_run_id=payload.ci_run_id,
        ci_run_attempt=payload.ci_run_attempt,
        commit_sha=payload.commit_sha.lower(),
        branch=payload.branch,
        event=payload.event or "",
        repository=payload.repository or "",
        ci_run_url=payload.ci_run_url or "",
        received_at=now,
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError:  # concurrent identical request: return the winner's result
        db.rollback()
        existing = _find_run(db, project.id, payload)
        if existing is not None and existing.decision is not None:
            return IngestOutcome(existing, existing.decision, True)
        raise

    # ---- 1. parse every report with its adapter ------------------------------------------
    options = AdapterOptions(default_severities=dict(policy.default_severities))
    errors: list[str] = []
    notes: list[str] = []
    parsed = {}
    failed: set[str] = set()
    seen: set[str] = set()

    for rep in payload.reports:
        name = normalize_scanner_name(rep.scanner)
        report = ScanReport(run_id=run.id, scanner=name, version=rep.version or "", sha256=_report_hash(rep.report))
        db.add(report)
        if name in seen:
            report.status, report.message = "error", "duplicate report for this scanner"
            errors.append(f"{name}: duplicate report in the same upload")
            continue
        seen.add(name)
        adapter = ADAPTERS.get(name)
        if adapter is None:
            report.status, report.message = "error", "unsupported scanner"
            errors.append(f"{name}: unsupported scanner (supported: {', '.join(ADAPTERS)})")
            failed.add(name)
            continue
        try:
            result = adapter.parse(rep.report, options)
        except AdapterError as exc:
            report.status, report.message = "error", str(exc)[:1000]
            errors.append(f"{name}: invalid report - {exc}")
            failed.add(name)
            continue
        report.status, report.findings_count = "ok", len(result.findings)
        report.message = "; ".join(result.notes)[:1000]
        notes.extend(result.notes)
        parsed[name] = result

    for ce in payload.client_errors:
        name = normalize_scanner_name(ce.scanner)
        if name in failed or name in parsed:
            pass  # already accounted for
        else:
            db.add(ScanReport(run_id=run.id, scanner=name, status="error", message=f"[CI] {ce.error}"[:1000]))
            failed.add(name)
        errors.append(f"{name}: {ce.error} (reported by the CI script)")

    for required in policy.required_scanners:
        if required not in parsed and required not in failed:
            errors.append(f"{required}: required scanner report is missing")
    if not parsed and not errors:
        errors.append("no scan report was received")
    db.flush()

    # ---- 2. reconcile (only scanners whose report parsed correctly) ------------------------
    reconciled = []
    resolved_total = 0
    for name, result in parsed.items():
        rec = reconcile(db, project.id, run.branch, run, name, result.findings, now)
        reconciled.extend(rec.items)
        resolved_total += rec.resolved

    # ---- 3. exceptions: expired ones go back to Open, then score every finding --------------
    today = now.date()
    for r in reconciled:
        f = r.finding
        if f.status == "Accepted" and f.accepted_until is not None and f.accepted_until < today:
            f.status, f.status_by, f.status_at = "Open", "system", now
            f.status_reason, f.accepted_until = "Risk exception expired", None
            audit(db, "system", "exception.expired", project.id, "finding", f.id, {})

    eval_items: list[EvalItem] = []
    run_findings: list[RunFinding] = []
    for r in reconciled:
        f = r.finding
        score, factors = compute_risk(f.severity, f.confidence, f.category, f.file_path, f.fixed_version, policy.risk)
        excepted = is_excepted(f, policy, today)
        run_findings.append(
            RunFinding(
                run_id=run.id,
                finding_id=f.id,
                lifecycle=r.lifecycle,
                severity=f.severity,
                risk_score=score,
                factors=factors,
                excepted=excepted,
            )
        )
        eval_items.append(
            EvalItem(
                finding_id=f.id,
                title=f.title,
                severity=f.severity,
                category=f.category,
                scanner=f.scanner,
                risk=score,
                location=f.location,
                excepted=excepted,
                exception_note=f"until {f.accepted_until}, by {f.status_by}" if excepted else "",
            )
        )

    # ---- 4. decide -------------------------------------------------------------------------
    if errors:
        result_name = "ERROR"
        reasons = [{"type": "integration_error", "message": e} for e in errors]
        reasons.append(
            {"type": "info", "message": "Fail-closed: an integration error is never treated as PASS."}
        )
    else:
        outcome = evaluate(policy, eval_items, notes)
        result_name, reasons = outcome.decision, outcome.reasons
        for rf in run_findings:
            rf.triggered_rules = outcome.triggered.get(rf.finding_id, [])
    db.add_all(run_findings)

    by_sev = Counter(i.severity for i in eval_items)
    by_cat = Counter(i.category for i in eval_items)
    lifecycle = Counter(r.lifecycle for r in reconciled)
    summary = {
        "total": len(eval_items),
        "by_severity": dict(by_sev),
        "by_category": dict(by_cat),
        "new": lifecycle.get("new", 0),
        "persisting": lifecycle.get("persisting", 0),
        "reappeared": lifecycle.get("reappeared", 0),
        "resolved": resolved_total,
        "excepted": sum(1 for i in eval_items if i.excepted),
        "max_risk": max((i.risk for i in eval_items), default=0),
        "scanners": [
            {"scanner": rp.scanner, "status": rp.status, "findings": rp.findings_count}
            for rp in db.scalars(select(ScanReport).where(ScanReport.run_id == run.id).order_by(ScanReport.id))
        ],
    }
    decision = Decision(
        run_id=run.id,
        result=result_name,
        policy_id=policy_row.id,
        policy_version=policy_row.version,
        reasons=reasons,
        summary=summary,
    )
    db.add(decision)
    audit(
        db,
        actor,
        "report.received",
        project.id,
        "run",
        run.id,
        {"commit": run.commit_sha[:12], "branch": run.branch, "scanners": sorted(seen)},
    )
    audit(
        db,
        "system",
        "decision.made",
        project.id,
        "run",
        run.id,
        {"result": result_name, "policy_version": policy_row.version, "findings": len(eval_items)},
    )
    db.flush()
    db.refresh(run)
    return IngestOutcome(run, decision, False)
