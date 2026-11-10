from sqlalchemy.orm import Session

from app.models import AuditEvent


def audit(
    db: Session,
    actor: str,
    action: str,
    project_id: int | None = None,
    entity_type: str = "",
    entity_id: object = "",
    details: dict | None = None,
) -> None:
    """Record a traceability event. `details` must never contain secrets or code excerpts."""
    db.add(
        AuditEvent(
            actor=actor[:120],
            action=action,
            project_id=project_id,
            entity_type=entity_type,
            entity_id=str(entity_id),
            details=details or {},
        )
    )
