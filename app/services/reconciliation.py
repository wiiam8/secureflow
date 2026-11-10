"""Reconciliation: follow the same finding across runs.

Findings are tracked per (project, branch, fingerprint). Each run a finding is:
  new         first time seen on this branch
  persisting  seen before and still present
  reappeared  had disappeared (Resolved) and is back
and findings of a scanner that are absent from its latest report become Resolved.
Matching is conservative: only an identical fingerprint is treated as the same problem.
"""
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, PipelineRun
from app.services.adapters import NormalizedFinding

CHUNK = 500


@dataclass
class Reconciled:
    finding: Finding
    lifecycle: str
    normalized: NormalizedFinding


@dataclass
class ReconcileResult:
    items: list[Reconciled]
    resolved: int


def _copy_fields(f: Finding, nf: NormalizedFinding) -> None:
    f.category = nf.category
    f.rule_id = nf.rule_id
    f.title = nf.title[:500]
    f.description = nf.description
    f.severity = nf.severity
    f.confidence = nf.confidence
    f.file_path = nf.file_path
    f.line = nf.line
    f.component = nf.component
    f.installed_version = nf.installed_version
    f.fixed_version = nf.fixed_version
    f.reference = nf.reference
    f.cwe = nf.cwe


def _accepted_siblings(db: Session, project_id: int, branch: str, fingerprints: list[str], today) -> dict[str, Finding]:
    """An exception granted on another branch carries over to the same finding here."""
    found: dict[str, Finding] = {}
    for i in range(0, len(fingerprints), CHUNK):
        chunk = fingerprints[i : i + CHUNK]
        rows = db.scalars(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.branch != branch,
                Finding.fingerprint.in_(chunk),
                Finding.status == "Accepted",
                Finding.accepted_until >= today,
            )
        )
        for r in rows:
            found.setdefault(r.fingerprint, r)
    return found


def reconcile(
    db: Session,
    project_id: int,
    branch: str,
    run: PipelineRun,
    scanner: str,
    normalized: list[NormalizedFinding],
    now: datetime,
) -> ReconcileResult:
    existing = {
        f.fingerprint: f
        for f in db.scalars(
            select(Finding).where(Finding.project_id == project_id, Finding.branch == branch, Finding.scanner == scanner)
        )
    }
    unique: dict[str, NormalizedFinding] = {}
    for nf in normalized:
        unique.setdefault(nf.fingerprint, nf)

    new_fps = [fp for fp in unique if fp not in existing]
    siblings = _accepted_siblings(db, project_id, branch, new_fps, now.date()) if new_fps else {}

    items: list[Reconciled] = []
    for fp, nf in unique.items():
        f = existing.get(fp)
        if f is None:
            f = Finding(
                project_id=project_id,
                branch=branch,
                fingerprint=fp,
                scanner=scanner,
                first_seen_run_id=run.id,
                first_seen=now,
                seen_count=1,
            )
            _copy_fields(f, nf)
            sib = siblings.get(fp)
            if sib is not None:
                f.status = "Accepted"
                f.accepted_until = sib.accepted_until
                f.status_by = sib.status_by
                f.status_at = now
                f.status_reason = f"[inherited from branch '{sib.branch}'] {sib.status_reason}"[:1000]
            else:
                f.status = "Open"
            db.add(f)
            lifecycle = "new"
        else:
            if not f.present:
                lifecycle = "reappeared"
                f.reappeared_count += 1
                f.status = "Open"
                f.status_reason = ""
                f.status_by = "system"
                f.status_at = now
                f.accepted_until = None
            else:
                lifecycle = "persisting"
            _copy_fields(f, nf)
            f.seen_count += 1
        f.present = True
        f.last_seen = now
        f.last_seen_run_id = run.id
        items.append(Reconciled(f, lifecycle, nf))

    resolved = 0
    for fp, f in existing.items():
        if fp not in unique and f.present:
            f.present = False
            f.status = "Resolved"
            f.status_reason = f"Not detected in run #{run.id}"
            f.status_by = "system"
            f.status_at = now
            f.accepted_until = None
            resolved += 1

    db.flush()  # assign ids to new findings
    return ReconcileResult(items, resolved)
