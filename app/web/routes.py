"""Server-rendered dashboard. Session cookie auth + CSRF token on every POST."""
import json
from datetime import date, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.constants import CATEGORIES, ROLE_LABELS, ROLES, SEVERITIES, STATUSES
from app.database import get_db
from app.deps import current_user_optional, get_project_for_user
from app.models import AuditEvent, Decision, Finding, PipelineRun, Project, RunFinding, User
from app.security import (
    DUMMY_HASH,
    check_csrf,
    get_csrf_token,
    hash_password,
    login_limiter,
    verify_password,
)
from app.services import permissions
from app.services.audit import audit
from app.services.controls import CATEGORY_CONTROLS, CONTROLS, DISCLAIMER, GATE_CONTROLS
from app.services.evidence import build_evidence
from app.services.findings import StatusError, StatusForbidden, set_status
from app.services.policies import PolicyValidationError, create_policy_version, get_active_policy, list_policy_versions
from app.services.policy_engine import PolicyRules
from app.services.projects import (
    ConflictError,
    add_member,
    create_project,
    create_token,
    list_tokens,
    remove_member,
    revoke_token,
)
from app.services.stats import project_overview, sla_status

BASE = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
router = APIRouter(include_in_schema=False)

PAGE = 25


def fmt_dt(v: datetime | None) -> str:
    return v.strftime("%Y-%m-%d %H:%M") if v else "-"


templates.env.filters["dt"] = fmt_dt
templates.env.globals.update(ROLE_LABELS=ROLE_LABELS, SEVERITIES=SEVERITIES, CATEGORIES=CATEGORIES, STATUSES=STATUSES)


def render(request: Request, name: str, user: User | None, status_code: int = 200, **ctx):
    flashes = request.session.pop("flash", []) if "session" in request.scope else []
    return templates.TemplateResponse(
        request,
        name,
        {"user": user, "csrf_token": get_csrf_token(request.session), "flashes": flashes, "perm": permissions, **ctx},
        status_code=status_code,
    )


def flash(request: Request, message: str, kind: str = "success") -> None:
    request.session.setdefault("flash", []).append({"kind": kind, "text": message})


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def web_user(request: Request, user: User | None = Depends(current_user_optional)) -> User:
    if user is None:
        # Not a 401 page: send the browser to the login form.
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def csrf_ok(request: Request, token: str) -> None:
    if not check_csrf(request.session, token):
        raise HTTPException(403, "Invalid or missing CSRF token")


# ---- auth -------------------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, user: User | None = Depends(current_user_optional)):
    if user:
        return redirect("/")
    return render(request, "login.html", None)


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    key = username.strip().lower()
    if login_limiter.blocked(key):
        return render(request, "login.html", None, 429, error="Too many failed attempts. Try again in a few minutes.")
    user = db.scalar(select(User).where(func.lower(User.username) == key))
    ok = verify_password(user.password_hash if user else DUMMY_HASH, password)
    if not (user and ok and user.is_active):
        login_limiter.fail(key)
        return render(request, "login.html", None, 401, error="Invalid username or password.")
    login_limiter.reset(key)
    request.session.clear()  # new session on login (prevents fixation)
    request.session["uid"] = user.id
    audit(db, f"user:{user.username}", "auth.login", None, "user", user.id)
    db.commit()
    return redirect("/")


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    csrf_ok(request, csrf_token)
    request.session.clear()
    return redirect("/login")


# ---- dashboard --------------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def home(request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    cards = []
    for p in permissions.accessible_projects(db, user):
        last = db.scalar(select(PipelineRun).where(PipelineRun.project_id == p.id).order_by(PipelineRun.id.desc()).limit(1))
        ov = project_overview(db, p)
        cards.append({"project": p, "last": last, "ov": ov})
    return render(request, "dashboard.html", user, cards=cards)


@router.get("/projects/new", response_class=HTMLResponse)
def project_new_form(request: Request, user: User = Depends(web_user)):
    if not permissions.can_create_project(user):
        raise HTTPException(403, "Forbidden")
    return render(request, "project_new.html", user, form={})


@router.post("/projects/new")
def project_new_submit(
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    repo_url: str = Form(""),
    default_branch: str = Form("main"),
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    if not permissions.can_create_project(user):
        raise HTTPException(403, "Forbidden")
    form = {"name": name, "description": description, "repo_url": repo_url, "default_branch": default_branch}
    try:
        project = create_project(db, user, name, description, repo_url, default_branch)
    except (ConflictError, ValueError) as exc:
        return render(request, "project_new.html", user, 422, form=form, error=str(exc))
    db.commit()
    flash(request, "Project created. Generate an integration token in Settings to connect your pipeline.")
    return redirect(f"/projects/{project.id}/settings")


# ---- project pages ----------------------------------------------------------------------------
@router.get("/projects/{project_id}", response_class=HTMLResponse)
def project_page(project_id: int, request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    ov = project_overview(db, project)
    runs = list(
        db.scalars(
            select(PipelineRun).where(PipelineRun.project_id == project.id).order_by(PipelineRun.id.desc()).limit(8)
        ).unique()
    )
    chart = {"trend": ov["trend"], "severity": ov["by_severity"], "decisions": ov["decisions"]}
    return render(request, "project.html", user, project=project, ov=ov, runs=runs, chart_json=json.dumps(chart))


@router.get("/projects/{project_id}/runs", response_class=HTMLResponse)
def runs_page(
    project_id: int, request: Request, page: int = 1, user: User = Depends(web_user), db: Session = Depends(get_db)
):
    project = get_project_for_user(project_id, user, db)
    page = max(1, page)
    total = db.scalar(select(func.count()).select_from(PipelineRun).where(PipelineRun.project_id == project.id)) or 0
    runs = list(
        db.scalars(
            select(PipelineRun)
            .where(PipelineRun.project_id == project.id)
            .order_by(PipelineRun.id.desc())
            .offset((page - 1) * PAGE)
            .limit(PAGE)
        ).unique()
    )
    return render(request, "runs.html", user, project=project, runs=runs, page=page, pages=max(1, -(-total // PAGE)))


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_page(run_id: int, request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    run = db.get(PipelineRun, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    project = get_project_for_user(run.project_id, user, db)
    rfs = list(
        db.scalars(select(RunFinding).where(RunFinding.run_id == run.id).order_by(RunFinding.risk_score.desc()))
    )
    return render(request, "run.html", user, project=project, run=run, rfs=rfs, dec=run.decision)


@router.get("/runs/{run_id}/evidence.json")
def run_evidence(run_id: int, user: User = Depends(web_user), db: Session = Depends(get_db)):
    run = db.get(PipelineRun, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    get_project_for_user(run.project_id, user, db)
    audit(db, f"user:{user.username}", "evidence.exported", run.project_id, "run", run.id)
    db.commit()
    return JSONResponse(
        build_evidence(db, run),
        headers={"Content-Disposition": f'attachment; filename="secureflow-evidence-run-{run.id}.json"'},
    )


@router.get("/projects/{project_id}/findings", response_class=HTMLResponse)
def findings_page(
    project_id: int,
    request: Request,
    status: str = "",
    severity: str = "",
    category: str = "",
    branch: str = "",
    scope: str = "current",
    page: int = 1,
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    project = get_project_for_user(project_id, user, db)
    q = select(Finding).where(Finding.project_id == project.id)
    if scope == "current":
        q = q.where(Finding.present.is_(True))
    if status in STATUSES:
        q = q.where(Finding.status == status)
    if severity in SEVERITIES:
        q = q.where(Finding.severity == severity)
    if category in CATEGORIES:
        q = q.where(Finding.category == category)
    if branch:
        q = q.where(Finding.branch == branch)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = list(db.scalars(q.order_by(Finding.id.desc()).limit(2000)))
    rows.sort(key=lambda f: (sev_order.get(f.severity, 9), -f.id))
    page = max(1, page)
    window = rows[(page - 1) * PAGE : page * PAGE]
    branches = list(db.scalars(select(Finding.branch).where(Finding.project_id == project.id).distinct()))
    policy = PolicyRules.model_validate(get_active_policy(db, project).rules)
    sla = {f.id: sla_status(f, policy) for f in window}
    return render(
        request,
        "findings.html",
        user,
        project=project,
        findings=window,
        sla=sla,
        total=total,
        page=page,
        pages=max(1, -(-min(total, 2000) // PAGE)),
        branches=branches,
        f={"status": status, "severity": severity, "category": category, "branch": branch, "scope": scope},
    )


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_page(finding_id: int, request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    project = get_project_for_user(finding.project_id, user, db)
    history = list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.entity_type == "finding", AuditEvent.entity_id == str(finding.id))
            .order_by(AuditEvent.id.desc())
        )
    )
    last_rf = db.scalar(select(RunFinding).where(RunFinding.finding_id == finding.id).order_by(RunFinding.id.desc()).limit(1))
    policy = PolicyRules.model_validate(get_active_policy(db, project).rules)
    return render(
        request,
        "finding.html",
        user,
        project=project,
        finding=finding,
        history=history,
        rf=last_rf,
        sla=sla_status(finding, policy),
        controls=[{"id": c, **CONTROLS[c]} for c in CATEGORY_CONTROLS.get(finding.category, [])],
        policy=policy,
    )


@router.post("/findings/{finding_id}/status")
def finding_status(
    finding_id: int,
    request: Request,
    status: str = Form(""),
    reason: str = Form(""),
    accepted_until: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    get_project_for_user(finding.project_id, user, db)
    until = None
    if accepted_until.strip():
        try:
            until = date.fromisoformat(accepted_until.strip())
        except ValueError:
            flash(request, "Invalid expiry date (use YYYY-MM-DD).", "danger")
            return redirect(f"/findings/{finding.id}")
    try:
        set_status(db, finding, user, status, reason, until)
        db.commit()
        flash(request, f"Status set to {status}.")
    except StatusForbidden as exc:
        flash(request, str(exc), "danger")
    except StatusError as exc:
        flash(request, str(exc), "danger")
    return redirect(f"/findings/{finding.id}")


@router.get("/projects/{project_id}/controls", response_class=HTMLResponse)
def controls_page(project_id: int, request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    findings = [f for f in db.scalars(select(Finding).where(Finding.project_id == project.id, Finding.present.is_(True)))]
    rows = []
    for cid, meta in CONTROLS.items():
        cats = [c for c, ids in CATEGORY_CONTROLS.items() if cid in ids]
        related = [f for f in findings if f.category in cats and f.status in ("Open", "In Review")]
        gate = cid in GATE_CONTROLS
        rows.append(
            {"id": cid, **meta, "categories": cats, "gate": gate, "open": len(related),
             "critical_high": sum(1 for f in related if f.severity in ("Critical", "High"))}
        )
    last_run = db.scalar(select(PipelineRun).where(PipelineRun.project_id == project.id).order_by(PipelineRun.id.desc()).limit(1))
    return render(request, "controls.html", user, project=project, rows=rows, disclaimer=DISCLAIMER, last_run=last_run)


@router.get("/projects/{project_id}/audit", response_class=HTMLResponse)
def audit_page(
    project_id: int, request: Request, page: int = 1, user: User = Depends(web_user), db: Session = Depends(get_db)
):
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_view_audit(user):
        raise HTTPException(403, "Forbidden")
    page = max(1, page)
    total = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.project_id == project.id)) or 0
    events = list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.project_id == project.id)
            .order_by(AuditEvent.id.desc())
            .offset((page - 1) * 50)
            .limit(50)
        )
    )
    return render(request, "audit.html", user, project=project, events=events, page=page, pages=max(1, -(-total // 50)))


# ---- settings: tokens, policy, members --------------------------------------------------------
def _settings_ctx(db: Session, project: Project, user: User, **extra) -> dict:
    pol = get_active_policy(db, project)
    members = {m.id for m in project.members}
    users = list(db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.username)))
    return {
        "project": project,
        "tokens": list_tokens(db, project) if permissions.can_manage_tokens(user) else [],
        "policy": pol,
        "policy_text": extra.pop("policy_text", None) or json.dumps(pol.rules, indent=2),
        "versions": list_policy_versions(db, project),
        "members": [u for u in users if u.id in members],
        "candidates": [u for u in users if u.id not in members],
        **extra,
    }


@router.get("/projects/{project_id}/settings", response_class=HTMLResponse)
def settings_page(project_id: int, request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    project = get_project_for_user(project_id, user, db)
    return render(request, "settings.html", user, **_settings_ctx(db, project, user))


@router.post("/projects/{project_id}/tokens")
def token_create(
    project_id: int,
    request: Request,
    label: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_manage_tokens(user):
        raise HTTPException(403, "Forbidden")
    raw, _ = create_token(db, project, user, label)
    db.commit()
    # Rendered directly (not via redirect/session): the token is shown exactly once.
    return render(request, "settings.html", user, **_settings_ctx(db, project, user, new_token=raw))


@router.post("/projects/{project_id}/tokens/{token_id}/revoke")
def token_revoke(
    project_id: int,
    token_id: int,
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_manage_tokens(user):
        raise HTTPException(403, "Forbidden")
    try:
        revoke_token(db, project, token_id, user)
        db.commit()
        flash(request, "Token revoked.")
    except LookupError:
        flash(request, "Token not found.", "danger")
    return redirect(f"/projects/{project.id}/settings")


@router.post("/projects/{project_id}/policy")
def policy_save(
    project_id: int,
    request: Request,
    policy_json: str = Form(""),
    comment: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_edit_policy(user):
        raise HTTPException(403, "Only administrators and security officers can change the policy")
    try:
        data = json.loads(policy_json)
        if not isinstance(data, dict):
            raise ValueError("policy must be a JSON object")
        pol = create_policy_version(db, project, data, f"user:{user.username}", comment)
    except (json.JSONDecodeError, ValueError, PolicyValidationError) as exc:
        errs = exc.errors if isinstance(exc, PolicyValidationError) else [str(exc)]
        db.rollback()
        return render(
            request, "settings.html", user, 422, **_settings_ctx(db, project, user, policy_text=policy_json, policy_errors=errs)
        )
    db.commit()
    flash(request, f"Policy saved as version {pol.version}. It applies to the next pipeline run.")
    return redirect(f"/projects/{project.id}/settings")


@router.post("/projects/{project_id}/members")
def member_change(
    project_id: int,
    request: Request,
    user_id: int = Form(0),
    action: str = Form("add"),
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    project = get_project_for_user(project_id, user, db)
    if not permissions.can_manage_members(user):
        raise HTTPException(403, "Only administrators can manage members")
    target = db.get(User, user_id)
    if target is None:
        flash(request, "User not found.", "danger")
    elif action == "remove":
        remove_member(db, project, target, user)
        db.commit()
        flash(request, f"{target.username} removed from the project.")
    else:
        add_member(db, project, target, user)
        db.commit()
        flash(request, f"{target.username} added to the project.")
    return redirect(f"/projects/{project.id}/settings")


# ---- user administration ----------------------------------------------------------------------
@router.get("/admin/users", response_class=HTMLResponse)
def users_page(request: Request, user: User = Depends(web_user), db: Session = Depends(get_db)):
    if not permissions.is_admin(user):
        raise HTTPException(403, "Forbidden")
    users = list(db.scalars(select(User).order_by(User.username)))
    return render(request, "users.html", user, users=users, roles=ROLES)


@router.post("/admin/users")
def user_create(
    request: Request,
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    role: str = Form("developer"),
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    if not permissions.is_admin(user):
        raise HTTPException(403, "Forbidden")
    username, email = username.strip(), email.strip()
    problem = None
    if not (3 <= len(username) <= 64) or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        problem = "Username: 3-64 characters (letters, digits, . _ -)."
    elif "@" not in email or len(email) > 255:
        problem = "A valid e-mail is required."
    elif len(password) < 12:
        problem = "Password must be at least 12 characters."
    elif role not in ROLES:
        problem = "Unknown role."
    elif db.scalar(select(User).where(func.lower(User.username) == username.lower())):
        problem = "That username already exists."
    elif db.scalar(select(User).where(func.lower(User.email) == email.lower())):
        problem = "That e-mail already exists."
    if problem:
        flash(request, problem, "danger")
        return redirect("/admin/users")
    u = User(username=username, email=email, password_hash=hash_password(password), role=role)
    db.add(u)
    db.flush()
    audit(db, f"user:{user.username}", "user.created", None, "user", u.id, {"username": username, "role": role})
    db.commit()
    flash(request, f"User {username} created.")
    return redirect("/admin/users")


@router.post("/admin/users/{user_id}/toggle")
def user_toggle(
    user_id: int,
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(web_user),
    db: Session = Depends(get_db),
):
    csrf_ok(request, csrf_token)
    if not permissions.is_admin(user):
        raise HTTPException(403, "Forbidden")
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if target.id == user.id:
        flash(request, "You cannot deactivate your own account.", "danger")
    else:
        target.is_active = not target.is_active
        audit(db, f"user:{user.username}", "user.toggled", None, "user", target.id, {"active": target.is_active})
        db.commit()
        flash(request, f"{target.username} is now {'active' if target.is_active else 'deactivated'}.")
    return redirect("/admin/users")
