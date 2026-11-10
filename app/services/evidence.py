"""Audit evidence export for one run (GRC): who/what/when/which policy/which exceptions."""
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.models import AuditEvent, Finding, PipelineRun, Policy, RunFinding, utcnow
from app.services.controls import CONTROLS, DISCLAIMER, GATE_CONTROLS, controls_for_category


def build_evidence(db: Session, run: PipelineRun) -> dict:
    dec = run.decision
    policy = db.get(Policy, dec.policy_id) if dec and dec.policy_id else None
    rfs = list(db.scalars(select(RunFinding).where(RunFinding.run_id == run.id).order_by(RunFinding.risk_score.desc())))

    findings = []
    for rf in rfs:
        f: Finding = rf.finding
        findings.append(
            {
                "finding_id": f.id,
                "scanner": f.scanner,
                "category": f.category,
                "rule": f.rule_id,
                "title": f.title,
                "severity": rf.severity,
                "risk_score": rf.risk_score,
                "risk_factors": rf.factors,
                "location": f.location,
                "reference": f.reference,
                "lifecycle": rf.lifecycle,
                "status": f.status,
                "excepted": rf.excepted,
                "rules_triggered": rf.triggered_rules,
                "controls": [c["id"] for c in controls_for_category(f.category)],
            }
        )

    exceptions = [
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "approved_by": f.exception_by,
            "reason": f.reason,
            "valid_until": f.until,
        }
        for f in (
            _Exc(x["finding_id"], x["title"], db.get(Finding, x["finding_id"]))
            for x in findings
            if x["excepted"]
        )
    ]

    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.project_id == run.project_id, AuditEvent.entity_type == "run", AuditEvent.entity_id == str(run.id))
        .order_by(AuditEvent.id)
    )
    evidence = {
        "generated_at": utcnow().isoformat() + "Z",
        "generator": f"SecureFlow {__version__}",
        "disclaimer": DISCLAIMER,
        "project": {"id": run.project_id, "name": run.project.name, "repository": run.repository or run.project.repo_url},
        "run": {
            "id": run.id,
            "ci_provider": run.ci_provider,
            "ci_run_id": run.ci_run_id,
            "ci_run_attempt": run.ci_run_attempt,
            "ci_run_url": run.ci_run_url,
            "commit": run.commit_sha,
            "branch": run.branch,
            "event": run.event,
            "received_at": run.received_at.isoformat() + "Z",
        },
        "scanners": [
            {"scanner": r.scanner, "version": r.version, "status": r.status, "findings": r.findings_count,
             "report_sha256": r.sha256, "message": r.message}
            for r in run.reports
        ],
        "policy": {"version": dec.policy_version if dec else None, "rules": policy.rules if policy else None},
        "decision": {"result": dec.result, "reasons": dec.reasons, "summary": dec.summary} if dec else None,
        "exceptions_in_effect": exceptions,
        "findings": findings,
        "control_evidence": {
            "gate_controls": [{"id": c, **CONTROLS[c]} for c in GATE_CONTROLS],
            "note": "An automated security gate evaluated this change before delivery.",
        },
        "audit_trail": [
            {"ts": e.ts.isoformat() + "Z", "actor": e.actor, "action": e.action, "details": e.details} for e in events
        ],
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    evidence["evidence_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    return evidence


class _Exc:
    def __init__(self, finding_id: int, title: str, f: Finding | None):
        self.finding_id = finding_id
        self.title = title
        self.exception_by = f.status_by if f else ""
        self.reason = f.status_reason if f else ""
        self.until = f.accepted_until.isoformat() if f and f.accepted_until else None
