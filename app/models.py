"""Relational model. All timestamps are naive UTC (same behaviour on SQLite and PostgreSQL)."""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="developer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    repo_url: Mapped[str] = mapped_column(String(255), default="")
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    members: Mapped[list[User]] = relationship(secondary="project_members", lazy="selectin")


class ProjectMember(Base):
    __tablename__ = "project_members"

    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)


class IntegrationToken(Base):
    """Per-project token used by the pipeline. Only the SHA-256 hash is stored."""

    __tablename__ = "integration_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    label: Mapped[str] = mapped_column(String(100), default="")
    prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("project_id", "version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    rules: Mapped[dict] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    comment: Mapped[str] = mapped_column(String(300), default="")
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    __table_args__ = (
        UniqueConstraint("project_id", "ci_run_id", "ci_run_attempt", name="uq_run_identity"),
        Index("ix_runs_project_received", "project_id", "received_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    ci_provider: Mapped[str] = mapped_column(String(40), default="github-actions")
    ci_run_id: Mapped[str] = mapped_column(String(64))
    ci_run_attempt: Mapped[int] = mapped_column(Integer, default=1)
    commit_sha: Mapped[str] = mapped_column(String(64))
    branch: Mapped[str] = mapped_column(String(255))
    event: Mapped[str] = mapped_column(String(50), default="")
    repository: Mapped[str] = mapped_column(String(255), default="")
    ci_run_url: Mapped[str] = mapped_column(String(500), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    project: Mapped[Project] = relationship(lazy="joined")
    reports: Mapped[list[ScanReport]] = relationship(back_populates="run", lazy="selectin")
    decision: Mapped[Decision | None] = relationship(back_populates="run", uselist=False, lazy="joined")


class ScanReport(Base):
    """Metadata about a received report. The raw report is NOT stored (it may contain secrets)."""

    __tablename__ = "scan_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id"), index=True)
    scanner: Mapped[str] = mapped_column(String(40))
    version: Mapped[str] = mapped_column(String(50), default="")
    status: Mapped[str] = mapped_column(String(10))  # ok | error
    message: Mapped[str] = mapped_column(Text, default="")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")

    run: Mapped[PipelineRun] = relationship(back_populates="reports")


class Finding(Base):
    """A tracked issue, unique per (project, branch, fingerprint) and followed across runs."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "branch", "fingerprint", name="uq_finding_identity"),
        Index("ix_findings_project_branch_present", "project_id", "branch", "present"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    branch: Mapped[str] = mapped_column(String(255))
    fingerprint: Mapped[str] = mapped_column(String(64))

    scanner: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(20))
    rule_id: Mapped[str] = mapped_column(String(200), default="")
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    component: Mapped[str | None] = mapped_column(String(300), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reference: Mapped[str | None] = mapped_column(String(300), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True)

    first_seen_run_id: Mapped[int | None] = mapped_column(ForeignKey("pipeline_runs.id"), nullable=True)
    last_seen_run_id: Mapped[int | None] = mapped_column(ForeignKey("pipeline_runs.id"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    present: Mapped[bool] = mapped_column(Boolean, default=True)  # seen in the latest run of its scanner
    seen_count: Mapped[int] = mapped_column(Integer, default=1)
    reappeared_count: Mapped[int] = mapped_column(Integer, default=0)

    status: Mapped[str] = mapped_column(String(12), default="Open")
    status_reason: Mapped[str] = mapped_column(Text, default="")
    status_by: Mapped[str] = mapped_column(String(100), default="")
    status_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    accepted_until: Mapped[date | None] = mapped_column(Date, nullable=True)

    @property
    def location(self) -> str:
        if self.file_path:
            return f"{self.file_path}:{self.line}" if self.line else self.file_path
        return self.component or "-"


class RunFinding(Base):
    """Snapshot of a finding as evaluated in one run (score, factors, rules triggered)."""

    __tablename__ = "run_findings"
    __table_args__ = (UniqueConstraint("run_id", "finding_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    lifecycle: Mapped[str] = mapped_column(String(12))  # new | persisting | reappeared
    severity: Mapped[str] = mapped_column(String(10))
    risk_score: Mapped[float] = mapped_column(Float)
    factors: Mapped[dict] = mapped_column(JSON, default=dict)
    excepted: Mapped[bool] = mapped_column(Boolean, default=False)
    triggered_rules: Mapped[list] = mapped_column(JSON, default=list)

    finding: Mapped[Finding] = relationship(lazy="joined")


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id"), unique=True)
    result: Mapped[str] = mapped_column(String(10))  # PASS | WARN | BLOCK | ERROR
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("policies.id"), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    run: Mapped[PipelineRun] = relationship(back_populates="decision")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_project_ts", "project_id", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(120))  # user:<name> | token:<prefix> | system
    action: Mapped[str] = mapped_column(String(80))
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    entity_type: Mapped[str] = mapped_column(String(40), default="")
    entity_id: Mapped[str] = mapped_column(String(40), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
