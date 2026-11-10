"""Role + project-membership checks, shared by the REST API and the web UI."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.constants import MANUAL_STATUSES
from app.models import Project, ProjectMember, User


def is_admin(user: User) -> bool:
    return user.role == "admin"


def is_privileged(user: User) -> bool:
    """Administrators and security officers see every project."""
    return user.role in ("admin", "security")


def can_view_project(db: Session, user: User, project: Project) -> bool:
    if is_privileged(user):
        return True
    return db.get(ProjectMember, (project.id, user.id)) is not None


def can_create_project(user: User) -> bool:
    return is_privileged(user)


def can_manage_tokens(user: User) -> bool:
    return is_privileged(user)


def can_edit_policy(user: User) -> bool:
    return is_privileged(user)


def can_manage_members(user: User) -> bool:
    return is_admin(user)


def can_set_status(user: User, new_status: str) -> bool:
    if new_status not in MANUAL_STATUSES:
        return False
    if is_privileged(user):
        return True
    return new_status in ("Open", "In Review")  # developers can flag for review, never accept risk


def can_view_audit(user: User) -> bool:
    return is_privileged(user)


def accessible_projects(db: Session, user: User) -> list[Project]:
    q = select(Project).order_by(Project.name)
    if not is_privileged(user):
        q = q.join(ProjectMember, ProjectMember.project_id == Project.id).where(ProjectMember.user_id == user.id)
    return list(db.scalars(q))
