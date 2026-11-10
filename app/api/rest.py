"""REST API for humans and scripts (Bearer access token from /api/v1/auth/login)."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import current_user, get_project_for_user
from app.models import Decision, Finding, PipelineRun, Policy, User
from app.schemas import (
    FindingOut,
    LoginIn,
    ProjectIn,
    ProjectOut,
    StatusIn,
    TokenCreateIn,
    TokenCreateOut,
    TokenOut,
)
from app.security import DUMMY_HASH, create_access_token, login_limiter, verify_password
from app.services import permissions
from app.services.audit import audit
from app.services.evidence import build_evidence
from app.services.findings import StatusError, StatusForbidden, set_status
from app.services.policies import PolicyValidationError, create_policy_version, get_active_policy, list_policy_versions
from app.services.projects import ConflictError, create_project, create_token, list_tokens, revoke_token

router = APIRouter(prefix="/api/v1", tags=["rest"])


# ---- auth -------------------------------------------------------------------------------------
@router.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn, db: Session = Depends(get_db)):
    key = data.username.lower()
    if login_limiter.blocked(key):
        raise HTTPException(429, "Too many failed attempts, try again later")
    user = db.scalar(select(User).where(func.lower(User.username) == key))
    ok = verify_password(user.password_hash if user else DUMMY_HASH, data.password)
    if not (user and ok and user.is_active):
        login_limiter.fail(key)
        raise HTTPException(401, "Invalid credentials")
    login_limiter.reset(key)
    return TokenOut(access_token=create_access_token(user.id), role=user.role)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role}


# ---- projects ---------------------------------------------------------------------------------
@router.get("/projects", response_model=list[ProjectOut])
def projects(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return permissions.accessible_projects(db, user)


@router.post("/projects", response_model=ProjectOut, status_code=201)
def new_project(data: ProjectIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not permissions.can_create_project(user):
        raise HTTPException(403, "Only administrators and security officers can create projects")
    try:
        project = create_project(db, user, data.name, data.description, data.repo_url, data.default_branch)
    except ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return project


@router.post("/projects/{project_id}/tokens", response_model=TokenCreateOut, status_code=201)
def new_token(
    project_id: int, data: TokenCreateIn, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_manage_tokens(user):
        raise HTTPException(403, "Only administrators and security officers can manage tokens")
    raw, tok = create_token(db, project, user, data.label)
    db.commit()
    return TokenCreateOut(id=tok.id, prefix=tok.prefix, token=raw)


@router.get("/projects/{project_id}/tokens")
def tokens(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_manage_tokens(user):
        raise HTTPException(403, "Forbidden")
    return [
        {"id": t.id, "prefix": t.prefix, "label": t.label, "active": t.active, "created_at": t.created_at,
         "last_used_at": t.last_used_at}
        for t in list_tokens(db, project)
    ]


@router.delete("/projects/{project_id}/tokens/{token_id}", status_code=204)
def delete_token(project_id: int, token_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_manage_tokens(user):
        raise HTTPException(403, "Forbidden")
    try:
        revoke_token(db, project, token_id, user)
    except LookupError as exc:
        raise HTTPException(404, "Token not found") from exc
    db.commit()
    return Response(status_code=204)


# ---- policy -----------------------------------------------------------------------------------
@router.get("/projects/{project_id}/policy")
def get_policy(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    pol = get_active_policy(db, project)
    return {"version": pol.version, "rules": pol.rules, "created_by": pol.created_by, "created_at": pol.created_at}


@router.get("/projects/{project_id}/policy/versions")
def policy_versions(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    return [
        {"version": p.version, "active": p.is_active, "comment": p.comment, "created_by": p.created_by,
         "created_at": p.created_at}
        for p in list_policy_versions(db, project)
    ]


@router.put("/projects/{project_id}/policy")
def put_policy(project_id: int, rules: dict, comment: str = "", user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_edit_policy(user):
        raise HTTPException(403, "Only administrators and security officers can change the policy")
    try:
        pol = create_policy_version(db, project, rules, f"user:{user.username}", comment)
    except PolicyValidationError as exc:
        raise HTTPException(422, {"message": "Invalid policy", "errors": exc.errors}) from exc
    db.commit()
    return {"version": pol.version}


# ---- runs & findings --------------------------------------------------------------------------
@router.get("/projects/{project_id}/runs")
def runs(project_id: int, limit: int = Query(30, ge=1, le=200), user: User = Depends(current_user),
         db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    rows = db.scalars(
        select(PipelineRun).where(PipelineRun.project_id == project.id).order_by(PipelineRun.id.desc()).limit(limit)
    ).unique()
    return [_run_out(r) for r in rows]


def _run_out(r: PipelineRun) -> dict:
    return {
        "id": r.id,
        "commit": r.commit_sha,
        "branch": r.branch,
        "ci_run_id": r.ci_run_id,
        "received_at": r.received_at,
        "decision": r.decision.result if r.decision else None,
        "policy_version": r.decision.policy_version if r.decision else None,
        "summary": r.decision.summary if r.decision else None,
    }


def _run_for_user(run_id: int, user: User, db: Session) -> PipelineRun:
    run = db.get(PipelineRun, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    get_project_for_user(run.project_id, user, db)
    return run


@router.get("/runs/{run_id}")
def run_detail(run_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    run = _run_for_user(run_id, user, db)
    out = _run_out(run)
    out["reasons"] = run.decision.reasons if run.decision else []
    return out


@router.get("/runs/{run_id}/evidence")
def run_evidence(run_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    run = _run_for_user(run_id, user, db)
    return build_evidence(db, run)


@router.get("/projects/{project_id}/findings", response_model=list[FindingOut])
def findings(
    project_id: int,
    status: str | None = None,
    severity: str | None = None,
    branch: str | None = None,
    present: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    project = get_project_for_user(project_id, user, db)
    q = select(Finding).where(Finding.project_id == project.id)
    if status:
        q = q.where(Finding.status == status)
    if severity:
        q = q.where(Finding.severity == severity)
    if branch:
        q = q.where(Finding.branch == branch)
    if present is not None:
        q = q.where(Finding.present.is_(present))
    return list(db.scalars(q.order_by(Finding.id.desc()).limit(limit)))


@router.patch("/findings/{finding_id}/status", response_model=FindingOut)
def patch_status(finding_id: int, data: StatusIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    get_project_for_user(finding.project_id, user, db)
    try:
        set_status(db, finding, user, data.status, data.reason, data.accepted_until)
    except StatusForbidden as exc:
        raise HTTPException(403, str(exc)) from exc
    except StatusError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return finding


@router.get("/health", tags=["meta"])
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok"}
