"""Pydantic schemas for the REST API."""
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanner: str = Field(min_length=1, max_length=40)
    version: str | None = Field(None, max_length=50)
    report: Any  # raw scanner JSON (required key; the adapter validates its structure)


class ClientError(BaseModel):
    """A problem detected by the CI script itself (report file missing, not valid JSON...)."""

    model_config = ConfigDict(extra="forbid")

    scanner: str = Field(min_length=1, max_length=40)
    error: str = Field(min_length=1, max_length=500)


class IngestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ci_provider: str = Field("github-actions", max_length=40)
    ci_run_id: str = Field(min_length=1, max_length=64)
    ci_run_attempt: int = Field(1, ge=1, le=1000)
    commit_sha: str = Field(pattern=r"^[0-9a-fA-F]{7,64}$")
    branch: str = Field(min_length=1, max_length=255)
    event: str | None = Field(None, max_length=50)
    repository: str | None = Field(None, max_length=255)
    ci_run_url: str | None = Field(None, max_length=500)
    reports: list[ReportIn] = Field(default_factory=list, max_length=20)
    client_errors: list[ClientError] = Field(default_factory=list, max_length=20)

    @field_validator("ci_run_url")
    @classmethod
    def _http_only(cls, v):
        # Shown as a link in the dashboard: never allow javascript:, data:, ...
        if v and not v.startswith(("https://", "http://")):
            raise ValueError("ci_run_url must start with http:// or https://")
        return v


class IngestResponse(BaseModel):
    run_id: int
    decision: str  # PASS | WARN | BLOCK | ERROR
    exit_code: int  # suggested exit code for the CI step: 0 PASS/WARN, 1 BLOCK, 2 ERROR
    replay: bool = False
    policy_version: int | None = None
    reasons: list[dict]
    summary: dict
    dashboard_url: str


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field("", max_length=2000)
    repo_url: str = Field("", max_length=255)
    default_branch: str = Field("main", max_length=100)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    repo_url: str
    default_branch: str
    created_at: datetime


class TokenCreateIn(BaseModel):
    label: str = Field("", max_length=100)


class TokenCreateOut(BaseModel):
    id: int
    prefix: str
    token: str  # shown only once
    note: str = "Store this token now (e.g. as a GitHub secret). It cannot be displayed again."


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    branch: str
    scanner: str
    category: str
    rule_id: str
    title: str
    severity: str
    confidence: str | None
    file_path: str | None
    line: int | None
    component: str | None
    fixed_version: str | None
    reference: str | None
    cwe: str | None
    present: bool
    status: str
    status_reason: str
    accepted_until: date | None
    first_seen: datetime
    last_seen: datetime
    seen_count: int


class StatusIn(BaseModel):
    status: str
    reason: str = Field("", max_length=1000)
    accepted_until: date | None = None
