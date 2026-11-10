import copy

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import IntegrationToken, Project, ProjectMember, User, utcnow
from app.security import generate_integration_token
from app.services.audit import audit
from app.services.policies import create_policy_version
from app.services.policy_engine import DEFAULT_POLICY


class ConflictError(ValueError):
    pass


def create_project(
    db: Session, creator: User, name: str, description: str = "", repo_url: str = "", default_branch: str = "main"
) -> Project:
    name = name.strip()
    if not name or len(name) > 120:
        raise ValueError("Project name is required (max 120 characters).")
    if repo_url and not repo_url.startswith(("https://", "http://")):
        raise ValueError("Repository URL must start with http:// or https://")
    project = Project(
        name=name,
        description=description.strip()[:2000],
        repo_url=repo_url.strip()[:255],
        default_branch=(default_branch.strip() or "main")[:100],
        created_by=creator.id,
    )
    db.add(project)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(f"A project named '{name}' already exists.") from exc
    db.add(ProjectMember(project_id=project.id, user_id=creator.id))
    create_policy_version(db, project, copy.deepcopy(DEFAULT_POLICY), f"user:{creator.username}", "initial policy")
    audit(db, f"user:{creator.username}", "project.created", project.id, "project", project.id, {"name": name})
    return project


def create_token(db: Session, project: Project, actor: User, label: str = "") -> tuple[str, IntegrationToken]:
    raw, prefix, token_hash = generate_integration_token()
    tok = IntegrationToken(
        project_id=project.id,
        label=label.strip()[:100],
        prefix=prefix,
        token_hash=token_hash,
        created_by=actor.id,
    )
    db.add(tok)
    db.flush()
    audit(db, f"user:{actor.username}", "token.created", project.id, "token", tok.id, {"prefix": prefix})
    return raw, tok  # `raw` is shown once and never stored


def revoke_token(db: Session, project: Project, token_id: int, actor: User) -> IntegrationToken:
    tok = db.get(IntegrationToken, token_id)
    if tok is None or tok.project_id != project.id:
        raise LookupError("Token not found")
    if tok.revoked_at is None:
        tok.revoked_at = utcnow()
        audit(db, f"user:{actor.username}", "token.revoked", project.id, "token", tok.id, {"prefix": tok.prefix})
    return tok


def list_tokens(db: Session, project: Project) -> list[IntegrationToken]:
    return list(
        db.scalars(
            select(IntegrationToken).where(IntegrationToken.project_id == project.id).order_by(IntegrationToken.id.desc())
        )
    )


def add_member(db: Session, project: Project, user: User, actor: User) -> None:
    if db.get(ProjectMember, (project.id, user.id)) is None:
        db.add(ProjectMember(project_id=project.id, user_id=user.id))
        audit(db, f"user:{actor.username}", "member.added", project.id, "user", user.id, {"username": user.username})


def remove_member(db: Session, project: Project, user: User, actor: User) -> None:
    link = db.get(ProjectMember, (project.id, user.id))
    if link is not None:
        db.delete(link)
        audit(db, f"user:{actor.username}", "member.removed", project.id, "user", user.id, {"username": user.username})
