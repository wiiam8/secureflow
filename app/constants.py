"""Shared vocabulary. Kept in one place so adapters, engines and UI agree."""

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {s: 5 - i for i, s in enumerate(SEVERITIES)}  # Critical=5 ... Info=1

CATEGORIES = ["code", "dependency", "secret", "container"]

STATUSES = ["Open", "In Review", "Accepted", "Resolved"]
# Resolved is only ever set by the system, when a finding disappears from a scan.
MANUAL_STATUSES = ["Open", "In Review", "Accepted"]

ROLES = ["admin", "security", "developer"]
ROLE_LABELS = {"admin": "Administrator", "security": "Security officer", "developer": "Developer"}

DECISIONS = ["PASS", "WARN", "BLOCK", "ERROR"]
# ERROR = integration error (missing/invalid report, ...). Fail-closed: never PASS.

LIFECYCLES = ["new", "persisting", "reappeared"]
