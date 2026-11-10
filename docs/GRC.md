# GRC layer

SecureFlow produces **evidence that supports** controls. It never states that an organisation is *compliant*
or *certified*: that is an assessor's judgement.

| What | Where |
|---|---|
| **Control mapping** (ISO 27001:2022 Annex A + NIST CSF 2.0, tags only) | `app/services/controls.py`, "Controls (GRC)" tab |
| **Risk acceptance workflow**: justification (≥10 chars), mandatory expiry (≤ policy `max_days`, default 90), only Security officer/Admin, secrets can never be accepted, expiry returns the finding to blocking | finding page, `PATCH /findings/{id}/status` |
| **Remediation SLA**: deadline = first seen + days per severity (policy `sla_days`), overdue counters, paused while excepted | project overview, findings list |
| **Policy governance**: versioned, who/when/why, each decision records the policy version | Settings tab |
| **Audit trail**: logins, tokens, policy changes, status changes, reports, decisions | "Audit trail" tab (Security/Admin) |
| **Evidence export per run** (JSON + SHA-256): commit, scanners and report hashes, policy, decision, exceptions in effect, findings with controls, audit events | "Download evidence" on a run |

Mapping used: code → A.8.28, A.8.29, ID.RA-01, PR.PS-06 · dependency → A.8.8, A.5.21, ID.RA-01 ·
secret → A.5.17, PR.AA-01 · container → A.8.8, A.8.9, ID.RA-01 · the gate itself → A.8.25, A.8.32, A.8.29, PR.PS-06, ID.RA-06.
Verify these against the standards before citing them in your report.
