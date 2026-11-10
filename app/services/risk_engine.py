"""Explainable risk score:  R = S x C x E

S = normalized severity value   (Critical 5, High 4, Medium 3, Low 2, Info 1)
C = confidence factor           (neutral 1.0 when the scanner gives none)
E = exposure/context factor     (product of explicit, verifiable rules; neutral 1.0 when unknown)

This is an internal ranking score, NOT a recalculated CVSS and NOT a universal risk measure.
Every factor is stored with the score so the dashboard can show exactly how it was obtained.
"""
from fnmatch import fnmatch

from app.constants import SEVERITY_RANK
from app.services.policy_engine import RiskConfig

MAX_E = 3.0


def compute_risk(
    severity: str,
    confidence: str | None,
    category: str,
    file_path: str | None,
    fixed_version: str | None,
    cfg: RiskConfig,
) -> tuple[float, dict]:
    s = SEVERITY_RANK.get(severity, 1)

    if confidence and confidence.upper() in cfg.confidence_factors:
        c = cfg.confidence_factors[confidence.upper()]
        c_note = f"scanner confidence {confidence.upper()}"
    else:
        c = cfg.neutral_confidence
        c_note = "neutral default (scanner gave no confidence)"

    parts: list[dict] = []
    e = 1.0
    cat_w = cfg.category_weights.get(category)  # type: ignore[arg-type]
    if cat_w is not None and cat_w != 1.0:
        e *= cat_w
        parts.append({"name": f"category '{category}'", "value": cat_w})
    if file_path and any(fnmatch(file_path, pat) for pat in cfg.exposed_paths):
        e *= cfg.exposed_weight
        parts.append({"name": "exposed path", "value": cfg.exposed_weight})
    if fixed_version and cfg.fix_available_weight != 1.0:
        e *= cfg.fix_available_weight
        parts.append({"name": "fix available", "value": cfg.fix_available_weight})
    e = min(e, MAX_E)
    if not parts:
        parts.append({"name": "no contextual rule applies (neutral)", "value": 1.0})

    score = round(s * c * e, 2)
    factors = {
        "formula": "R = S x C x E",
        "S": s,
        "S_label": severity,
        "C": c,
        "C_note": c_note,
        "E": round(e, 3),
        "E_parts": parts,
    }
    return score, factors
