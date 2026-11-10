# Risk model: R = S × C × E

An **internal ranking score**. It orders findings and feeds optional `min_risk` policy rules.
It is not a recalculated CVSS and not a universal measure of risk. Every factor is stored with the
score and shown on the finding page, so any decision can be explained.

| Factor | Meaning | Value | Neutral default (information missing) |
|---|---|---|---|
| **S** severity | normalized severity | Critical 5 · High 4 · Medium 3 · Low 2 · Info 1 | n/a (every finding has a severity) |
| **C** confidence | scanner's own confidence | HIGH 1.0 · MEDIUM 0.8 · LOW 0.5 (policy `risk.confidence_factors`) | **1.0** (`risk.neutral_confidence`) |
| **E** exposure / context | product of verifiable rules below, capped at 3.0 | see below | **1.0** |

E is the product of whichever of these apply (each is configurable in the policy):

- category weight, e.g. `secret` ×1.5 (`risk.category_weights`)
- exposed path, a glob such as `app/api/*` ×1.5 (`risk.exposed_paths`, `risk.exposed_weight`)
- fix available ×1.2: the scanner reports a fixed version, so there is no reason to defer (`risk.fix_available_weight`)

If none applies, E = 1.0 and the UI says *"no contextual rule applies (neutral)"*.

## Where severity comes from

| Scanner | Severity source |
|---|---|
| Bandit | `issue_severity` (HIGH/MEDIUM/LOW); confidence from `issue_confidence` |
| Semgrep | `extra.severity` (ERROR→High, WARNING→Medium, INFO→Low); confidence from rule metadata when present |
| Trivy | `Severity` (UNKNOWN→Low) |
| **pip-audit** | **none provided.** Uses `default_severities.dependency` from the policy (default **High**, fail safe) |
| **Gitleaks** | **none provided.** Uses `default_severities.secret` (default **High**) |

A severity SecureFlow does not recognise is mapped to a safe default **and** recorded as a scanner note,
which raises the decision to at least WARN (`warn_on_scanner_notes`).

## Worked example

Gitleaks finds a key in `app/api/keys.py`; policy has `exposed_paths: ["app/api/*"]`.
S = 4 (High default) · C = 1.0 (neutral, Gitleaks gives none) · E = 1.5 (secret) × 1.5 (exposed path) = 2.25
→ **R = 9.0**.
