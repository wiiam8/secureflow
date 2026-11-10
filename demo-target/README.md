# demo-target

**Intentionally vulnerable** Flask app used to exercise SecureFlow. Contains deliberate weaknesses
(SQL/command injection, unsafe YAML, weak hash, debug server), outdated dependencies, and **fake** secrets.
Never deploy it, never reuse its code.

Push the contents of this folder to its own GitHub repo, add the secrets `SECUREFLOW_URL` and `SECUREFLOW_TOKEN`,
and every push runs `.github/workflows/secureflow.yml`. `scripts/secureflow_ci.py` is a copy of the CI client in the
SecureFlow repo (`scripts/`): keep them in sync.

To make the pipeline pass: remove `DEMO_API_KEY`/`DB_PASSWORD`, bump the dependencies in `requirements.txt`, and fix the
High findings Bandit reports.
