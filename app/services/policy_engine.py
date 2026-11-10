"""Policy model + decision engine.

A policy is plain data (JSON), validated strictly, versioned per project. The engine is a pure
function: (policy, evaluated findings) -> decision + human-readable justification.
Integration errors (missing/invalid report, API down) never reach this engine: they are
FAIL_CLOSED and produce the ERROR decision in the ingest service.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.constants import SEVERITY_RANK
from app.services.adapters import ADAPTERS, normalize_scanner_name

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
Category = Literal["code", "dependency", "secret", "container"]


class Rule(BaseModel):
    """A rule matches a finding when ALL of its conditions hold."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = Field(None, max_length=30)
    description: str = Field("", max_length=300)
    severity: list[Severity] | None = None
    categories: list[Category] | None = None
    scanners: list[str] | None = None
    min_risk: float | None = Field(None, ge=0)

    @field_validator("severity", "categories", "scanners", mode="before")
    @classmethod
    def _single_to_list(cls, v):
        return [v] if isinstance(v, str) else v

    @model_validator(mode="after")
    def _needs_condition(self):
        if all(x is None for x in (self.severity, self.categories, self.scanners, self.min_risk)):
            raise ValueError("a rule needs at least one condition (severity, categories, scanners, min_risk)")
        return self


class RiskConfig(BaseModel):
    """Inputs of R = S x C x E. Every neutral default is 1.0 and is documented in docs/RISK_MODEL.md."""

    model_config = ConfigDict(extra="forbid")

    confidence_factors: dict[str, float] = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}
    neutral_confidence: float = Field(1.0, gt=0, le=3)  # used when the scanner gives no confidence
    category_weights: dict[Category, float] = {"secret": 1.5}  # missing category -> 1.0 (neutral)
    exposed_paths: list[str] = []  # glob patterns, e.g. "app/api/*" -> exposure factor
    exposed_weight: float = Field(1.5, gt=0, le=3)
    fix_available_weight: float = Field(1.2, gt=0, le=3)  # a fix exists: no reason to defer

    @field_validator("confidence_factors", "category_weights")
    @classmethod
    def _positive(cls, v):
        for k, x in v.items():
            if not 0 < x <= 3:
                raise ValueError(f"factor for '{k}' must be in ]0, 3]")
        return v


class ExceptionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool = True
    max_days: int = Field(90, ge=1, le=365)
    forbidden_categories: list[Category] = ["secret"]  # a leaked secret must be rotated, not accepted


class IntegrationErrorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    behavior: Literal["FAIL_CLOSED"] = "FAIL_CLOSED"  # the only supported behaviour, on purpose


class PolicyRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field("Policy", max_length=120)
    version: int | None = None  # informational: the real version is managed by the database
    required_scanners: list[str] = []
    blocking_rules: list[Rule] = []
    warning_rules: list[Rule] = []
    default_decision: Literal["PASS", "WARN"] = "PASS"
    warn_on_scanner_notes: bool = True  # partial scans (unparsable files...) -> at least WARN
    integration_error: IntegrationErrorConfig = IntegrationErrorConfig()
    default_severities: dict[Category, Severity] = {"dependency": "High", "secret": "High"}
    risk: RiskConfig = RiskConfig()
    exceptions: ExceptionsConfig = ExceptionsConfig()
    sla_days: dict[Severity, int] = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}

    @field_validator("required_scanners")
    @classmethod
    def _known_scanners(cls, v):
        names = [normalize_scanner_name(s) for s in v]
        unknown = [n for n in names if n not in ADAPTERS]
        if unknown:
            raise ValueError(f"unknown scanner(s): {', '.join(unknown)} (supported: {', '.join(ADAPTERS)})")
        return list(dict.fromkeys(names))

    @field_validator("sla_days")
    @classmethod
    def _sla_positive(cls, v):
        if any(d < 1 for d in v.values()):
            raise ValueError("SLA days must be >= 1")
        return v

    def rule_id(self, kind: str, index: int) -> str:
        rules = self.blocking_rules if kind == "BLOCK" else self.warning_rules
        return rules[index].id or f"{'B' if kind == 'BLOCK' else 'W'}{index + 1}"


DEFAULT_POLICY: dict = {
    "name": "Baseline Python Project",
    "required_scanners": ["bandit", "gitleaks"],
    "blocking_rules": [
        {"id": "B1", "description": "Any Critical finding blocks the delivery", "severity": ["Critical"]},
        {
            "id": "B2",
            "description": "High findings in secrets or dependencies block the delivery",
            "severity": ["High"],
            "categories": ["secret", "dependency"],
        },
    ],
    "warning_rules": [
        {"id": "W1", "description": "High or Medium findings need a review", "severity": ["High", "Medium"]}
    ],
    "default_decision": "PASS",
    "warn_on_scanner_notes": True,
    "integration_error": {"behavior": "FAIL_CLOSED"},
    "default_severities": {"dependency": "High", "secret": "High"},
    "risk": {
        "confidence_factors": {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5},
        "neutral_confidence": 1.0,
        "category_weights": {"secret": 1.5},
        "exposed_paths": [],
        "exposed_weight": 1.5,
        "fix_available_weight": 1.2,
    },
    "exceptions": {"allowed": True, "max_days": 90, "forbidden_categories": ["secret"]},
    "sla_days": {"Critical": 7, "High": 30, "Medium": 90, "Low": 180},
}


@dataclass
class EvalItem:
    finding_id: int
    title: str
    severity: str
    category: str
    scanner: str
    risk: float
    location: str
    excepted: bool = False
    exception_note: str = ""


@dataclass
class PolicyOutcome:
    decision: str
    reasons: list[dict] = field(default_factory=list)
    triggered: dict[int, list[str]] = field(default_factory=dict)  # finding_id -> rule ids


def rule_matches(rule: Rule, item: EvalItem) -> bool:
    if rule.severity is not None and item.severity not in rule.severity:
        return False
    if rule.categories is not None and item.category not in rule.categories:
        return False
    if rule.scanners is not None and item.scanner not in [normalize_scanner_name(s) for s in rule.scanners]:
        return False
    if rule.min_risk is not None and item.risk < rule.min_risk:
        return False
    return True


MAX_REASONS = 100


def evaluate(policy: PolicyRules, items: list[EvalItem], notes: list[str] | None = None) -> PolicyOutcome:
    out = PolicyOutcome(decision=policy.default_decision)
    block_reasons: list[dict] = []
    warn_reasons: list[dict] = []
    excepted_reasons: list[dict] = []

    ordered = sorted(items, key=lambda i: (-SEVERITY_RANK.get(i.severity, 0), -i.risk, i.finding_id))
    for item in ordered:
        hits: list[tuple[str, str, Rule]] = []
        for idx, rule in enumerate(policy.blocking_rules):
            if rule_matches(rule, item):
                hits.append(("BLOCK", policy.rule_id("BLOCK", idx), rule))
        if not any(h[0] == "BLOCK" for h in hits):
            for idx, rule in enumerate(policy.warning_rules):
                if rule_matches(rule, item):
                    hits.append(("WARN", policy.rule_id("WARN", idx), rule))
        if not hits:
            continue

        kind, rid, rule = hits[0]
        out.triggered.setdefault(item.finding_id, []).extend(h[1] for h in hits)
        base = {
            "rule": rid,
            "rule_description": rule.description,
            "finding_id": item.finding_id,
            "severity": item.severity,
            "category": item.category,
            "scanner": item.scanner,
            "risk": item.risk,
            "location": item.location,
        }
        msg = f"{item.severity} {item.category} finding '{item.title}' at {item.location}"
        if item.excepted:
            excepted_reasons.append(
                {**base, "type": "excepted", "message": f"[{rid}] {msg} - excepted ({item.exception_note}); "
                                                        f"would have triggered {kind}"}
            )
        elif kind == "BLOCK":
            block_reasons.append({**base, "type": "blocking", "message": f"[{rid}] {msg}"})
        else:
            warn_reasons.append({**base, "type": "warning", "message": f"[{rid}] {msg}"})

    reasons = block_reasons + warn_reasons
    if block_reasons:
        out.decision = "BLOCK"
    elif warn_reasons:
        out.decision = "WARN"

    if notes and policy.warn_on_scanner_notes:
        for n in notes:
            reasons.append({"type": "scanner_note", "message": f"Partial or degraded scan: {n}"})
        if out.decision == "PASS":
            out.decision = "WARN"

    if out.decision == "PASS":
        reasons.append({"type": "info", "message": "No blocking or warning rule was triggered."})
    reasons += excepted_reasons

    if len(reasons) > MAX_REASONS:
        extra = len(reasons) - MAX_REASONS
        reasons = reasons[:MAX_REASONS] + [{"type": "info", "message": f"... and {extra} more (see run findings)."}]
    out.reasons = reasons
    return out
