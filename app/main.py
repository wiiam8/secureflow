import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.api import ingest_api, rest
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import User
from app.security import hash_password
from app.web import routes as web

log = logging.getLogger("secureflow")
BASE = Path(__file__).resolve().parent

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)

# Swagger UI (/docs) charge ses fichiers depuis un CDN et exécute un script inline :
# il reçoit donc une CSP plus souple. Toutes les autres pages gardent la CSP stricte.
DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'"
)


def bootstrap_admin() -> None:
    """Create the first administrator when the database has no user."""
    with SessionLocal() as db:
        if (db.scalar(select(func.count()).select_from(User)) or 0) > 0:
            return
        password = settings.admin_password
        generated = not password
        if generated:
            password = secrets.token_urlsafe(14)
        db.add(
            User(
                username=settings.admin_username,
                email=settings.admin_email,
                password_hash=hash_password(password),
                role="admin",
            )
        )
        db.commit()
        if generated:
            log.warning("=" * 60)
            log.warning("First administrator created: %s / %s", settings.admin_username, password)
            log.warning("Change it, this message is shown only once.")
            log.warning("=" * 60)
        else:
            log.warning("First administrator '%s' created from ADMIN_PASSWORD.", settings.admin_username)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_for_runtime()
    if settings.database_url.startswith("sqlite") and not (BASE.parent / "migrations").exists():
        Base.metadata.create_all(engine)
    bootstrap_admin()
    yield


app = FastAPI(
    title="SecureFlow",
    version=__version__,
    description="Normalization, risk scoring and explainable PASS/WARN/BLOCK decisions for CI/CD pipelines.",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="sf_session",
    max_age=8 * 3600,
    same_site="lax",
    https_only=settings.cookie_secure,
)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    csp = DOCS_CSP if request.url.path == "/docs" else CSP
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if not request.url.path.startswith("/static"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    wants_html = not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", "")
    if exc.status_code == 303 and exc.headers and "Location" in exc.headers:
        return RedirectResponse(exc.headers["Location"], status_code=303)
    if wants_html:
        from app.web.routes import templates

        return templates.TemplateResponse(
            request,
            "error.html",
            {"user": None, "csrf_token": "", "flashes": [], "code": exc.status_code, "detail": str(exc.detail)},
            status_code=exc.status_code,
        )
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


app.include_router(ingest_api.router)
app.include_router(rest.router)
app.include_router(web.router)