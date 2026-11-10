"""Read-side helpers for the dashboard (counts, trends, SLA)."""
from collections import Counter
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.constants import SEVERITIES
from app.models import Finding, PipelineRun, Project, utcnow
from app.services.findings import is_excepted
from app.services.policies import get_active_policy
from app.services.policy_engine import PolicyRules

ACTIVE_STATUSES = ("Open", "In Review", "Accepted")


def active_findings(db: Session, project_id: int, branch: str | None = None) -> list[Finding]:
    q = select(Finding).where(Finding.project_id == project_id, Finding.present.is_(True))
    if branch:
        q = q.where(Finding.branch == branch)
    return list(db.scalars(q))


def sla_status(finding: Finding, policy: PolicyRules, today=None) -> dict | None:
    """Remediation deadline = first_seen + SLA days of its severity. Excepted findings are paused."""
    today = today or utcnow().date()
    days = policy.sla_days.get(finding.severity)  # type: ignore[call-overload]
    if days is None or finding.status in ("Resolved",) or is_excepted(finding, policy, today):
        return None
    due = finding.first_seen.date() + timedelta(days=days)
    return {"due": due, "overdue": due < today, "days_left": (due - today).days}


def project_overview(db: Session, project: Project) -> dict:
    policy = PolicyRules.model_validate(get_active_policy(db, project).rules)
    today = utcnow().date()
    findings = active_findings(db, project.id)
    open_f = [f for f in findings if f.status in ("Open", "In Review")]
    by_sev = Counter(f.severity for f in open_f)
    by_cat = Counter(f.category for f in open_f)
    overdue = [f for f in findings if (s := sla_status(f, policy, today)) and s["overdue"]]

    runs = list(
        db.scalars(
            select(PipelineRun).where(PipelineRun.project_id == project.id).order_by(PipelineRun.id.desc()).limit(20)
        ).unique()
    )
    runs.reverse()
    trend = [
        {
            "label": f"#{r.id}",
            "decision": r.decision.result if r.decision else "ERROR",
            "total": (r.decision.summary or {}).get("total", 0) if r.decision else 0,
            "max_risk": (r.decision.summary or {}).get("max_risk", 0) if r.decision else 0,
        }
        for r in runs
    ]
    decisions = Counter(t["decision"] for t in trend)
    return {
        "policy": policy,
        "open_total": len(open_f),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "by_category": dict(by_cat),
        "overdue": len(overdue),
        "excepted": sum(1 for f in findings if is_excepted(f, policy, today)),
        "trend": trend,
        "decisions": dict(decisions),
        "last_run": runs[-1] if runs else None,
    }
