import copy

from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models import Policy, Project
from app.services.audit import audit
from app.services.policy_engine import DEFAULT_POLICY, PolicyRules


class PolicyValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_policy(data: dict) -> PolicyRules:
    try:
        return PolicyRules.model_validate(data)
    except ValidationError as exc:
        msgs = []
        for e in exc.errors():
            loc = ".".join(str(x) for x in e["loc"]) or "policy"
            msgs.append(f"{loc}: {e['msg']}")
        raise PolicyValidationError(msgs) from exc


def get_active_policy(db: Session, project: Project) -> Policy:
    pol = db.scalar(
        select(Policy).where(Policy.project_id == project.id, Policy.is_active.is_(True)).order_by(Policy.version.desc())
    )
    if pol is None:  # should not happen (created with the project) but never run without a policy
        pol = create_policy_version(db, project, copy.deepcopy(DEFAULT_POLICY), "system", "default policy")
    return pol


def list_policy_versions(db: Session, project: Project) -> list[Policy]:
    return list(db.scalars(select(Policy).where(Policy.project_id == project.id).order_by(Policy.version.desc())))


def create_policy_version(db: Session, project: Project, data: dict, actor: str, comment: str = "") -> Policy:
    rules = validate_policy(data).model_dump(mode="json")
    last = db.scalar(select(func.max(Policy.version)).where(Policy.project_id == project.id)) or 0
    db.execute(update(Policy).where(Policy.project_id == project.id).values(is_active=False))
    pol = Policy(
        project_id=project.id,
        version=last + 1,
        rules=rules,
        is_active=True,
        comment=comment[:300],
        created_by=actor,
    )
    db.add(pol)
    db.flush()
    audit(
        db,
        actor,
        "policy.changed",
        project.id,
        "policy",
        pol.id,
        {"version": pol.version, "comment": comment[:300]},
    )
    return pol
