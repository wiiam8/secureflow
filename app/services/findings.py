"""Finding triage: status changes and risk exceptions (the GRC "risk acceptance" workflow)."""
from datetime import date, timedelta

from sqlalchemy.orm import Session

from app.constants import MANUAL_STATUSES
from app.models import Finding, User, utcnow
from app.services import permissions
from app.services.audit import audit
from app.services.policies import get_active_policy
from app.services.policy_engine import PolicyRules

MIN_REASON = 10


class StatusError(ValueError):
    pass


class StatusForbidden(PermissionError):
    pass


def is_excepted(finding: Finding, policy: PolicyRules, today: date | None = None) -> bool:
    """An exception changes how a finding is *treated*; it never deletes the finding."""
    today = today or utcnow().date()
    return bool(
        finding.status == "Accepted"
        and finding.accepted_until
        and finding.accepted_until >= today
        and policy.exceptions.allowed
        and finding.category not in policy.exceptions.forbidden_categories
    )


def set_status(
    db: Session,
    finding: Finding,
    actor: User,
    new_status: str,
    reason: str = "",
    accepted_until: date | None = None,
) -> Finding:
    if new_status == "Resolved":
        raise StatusError("'Resolved' is set automatically when a finding disappears from a scan.")
    if new_status not in MANUAL_STATUSES:
        raise StatusError(f"Unknown status '{new_status}'.")
    if not permissions.can_set_status(actor, new_status):
        raise StatusForbidden("Your role cannot set this status (risk acceptance needs a security officer).")

    reason = (reason or "").strip()
    if new_status == "Accepted":
        from app.models import Project  # local import: avoids a cycle at module load

        policy = PolicyRules.model_validate(get_active_policy(db, db.get(Project, finding.project_id)).rules)
        if not policy.exceptions.allowed:
            raise StatusError("This project's policy does not allow risk exceptions.")
        if finding.category in policy.exceptions.forbidden_categories:
            raise StatusError(f"Findings of category '{finding.category}' cannot be accepted (policy).")
        if len(reason) < MIN_REASON:
            raise StatusError(f"A justification of at least {MIN_REASON} characters is required.")
        today = utcnow().date()
        if accepted_until is None or accepted_until <= today:
            raise StatusError("An expiry date in the future is required.")
        if accepted_until > today + timedelta(days=policy.exceptions.max_days):
            raise StatusError(f"The exception cannot last more than {policy.exceptions.max_days} days (policy).")
        finding.accepted_until = accepted_until
    else:
        finding.accepted_until = None

    old = finding.status
    finding.status = new_status
    finding.status_reason = reason
    finding.status_by = f"user:{actor.username}"
    finding.status_at = utcnow()
    audit(
        db,
        f"user:{actor.username}",
        "finding.status_changed",
        finding.project_id,
        "finding",
        finding.id,
        {
            "from": old,
            "to": new_status,
            "reason": reason[:300],
            "until": finding.accepted_until.isoformat() if finding.accepted_until else None,
        },
    )
    return finding
