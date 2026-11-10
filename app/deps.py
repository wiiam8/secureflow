from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import IntegrationToken, Project, User, utcnow
from app.security import hash_token, read_access_token
from app.services import permissions


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    """REST: Bearer access token. Web UI: signed session cookie."""
    uid = None
    bearer = _bearer(request)
    if bearer:
        uid = read_access_token(bearer)
    elif "session" in request.scope:
        uid = request.session.get("uid")
    if not uid:
        return None
    user = db.get(User, uid)
    return user if user and user.is_active else None


def current_user(user: User | None = Depends(current_user_optional)) -> User:
    if user is None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_role(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient role")
        return user

    return dep


def get_project_for_user(project_id: int, user: User, db: Session) -> Project:
    project = db.get(Project, project_id)
    # Same answer for "does not exist" and "not yours": no project enumeration.
    if project is None or not permissions.can_view_project(db, user, project):
        raise HTTPException(404, "Project not found")
    return project


def integration_token(request: Request, db: Session = Depends(get_db)) -> IntegrationToken:
    raw = _bearer(request)
    if not raw:
        raise HTTPException(401, "Missing integration token", headers={"WWW-Authenticate": "Bearer"})
    tok = db.scalar(select(IntegrationToken).where(IntegrationToken.token_hash == hash_token(raw)))
    if tok is None or not tok.active:
        raise HTTPException(401, "Invalid or revoked integration token", headers={"WWW-Authenticate": "Bearer"})
    tok.last_used_at = utcnow()
    return tok
