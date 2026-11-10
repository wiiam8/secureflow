"""Passwords, tokens, CSRF and a tiny login rate limiter."""
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import settings

_ph = PasswordHasher()
TOKEN_PREFIX = "sf_"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


DUMMY_HASH = hash_password("not-a-real-password")  # burn the same time for unknown users


# ---- integration tokens (pipeline -> API) -------------------------------------------------
def hash_token(raw: str) -> str:
    # High-entropy random token: a fast SHA-256 is appropriate (no need for a slow KDF).
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_integration_token() -> tuple[str, str, str]:
    """Return (raw_token, prefix, sha256_hash). The raw token is shown once, never stored."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:11], hash_token(raw)


# ---- user access tokens (REST API for humans/scripts) -------------------------------------
def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key, salt="secureflow-access-token")


def create_access_token(user_id: int) -> str:
    return _serializer().dumps({"uid": user_id})


def read_access_token(token: str) -> int | None:
    try:
        data = _serializer().loads(token, max_age=settings.access_token_ttl_minutes * 60)
        return int(data["uid"])
    except (BadSignature, SignatureExpired, KeyError, ValueError, TypeError):
        return None


# ---- CSRF (server-rendered forms, session cookie) -----------------------------------------
def get_csrf_token(session: dict) -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf(session: dict, submitted: str | None) -> bool:
    expected = session.get("csrf")
    return bool(expected and submitted and hmac.compare_digest(expected, submitted))


# ---- login rate limiting (in-memory, per process) ------------------------------------------
class LoginLimiter:
    def __init__(self) -> None:
        self._attempts: dict[str, deque] = defaultdict(deque)

    def _prune(self, key: str) -> deque:
        q = self._attempts[key]
        cutoff = time.monotonic() - settings.login_window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= settings.login_max_attempts

    def fail(self, key: str) -> None:
        self._prune(key).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


login_limiter = LoginLimiter()
