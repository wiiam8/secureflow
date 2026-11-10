# Fixtures

| File | Origin |
|---|---|
| bandit_real.json | REAL output: Bandit 1.9.4 on demo-target/app |
| pip_audit_real.json | REAL output: pip-audit 2.10.1 on demo-target/requirements.txt (44 entries = 23 unique vulnerabilities) |
| semgrep_real.json | REAL output: Semgrep 1.184.0, local rules (OSS without login => `lines` is "requires login") |
| gitleaks_real_UNSANITIZED.json | REAL output: Gitleaks 8.18.4. Contains the demo's FAKE secret. Git-ignored on purpose. |
| trivy_handwritten.json | HAND-WRITTEN following Trivy's documented JSON schema. No Trivy binary or image was available when this was built. Replace it with a real report (`trivy image --format json`) as soon as you can. |
