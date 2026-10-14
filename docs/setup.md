# Setup

## Requirements

- Python 3.12
- PostgreSQL 16 + pgvector (production); SQLite is used automatically for tests
  and local dev
- Docker + Docker Compose (sandbox, OOB listener, lab targets)

## One-command setup

```bash
pip install -e .
deslop init          # generates .env with secrets + a dashboard password
docker compose up -d
```

`deslop init` prints the dashboard password once. Options:
`--llm-provider anthropic|openai|ollama|none`, `--llm-model ...`, `--user ...`,
`--env prod`, `--force`.

## Manual / local dev

```bash
python -m venv .venv
. .venv/Scripts/activate        # Windows;  .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e . --no-deps
pytest
```

For client-side (XSS / open-redirect) verification, install the browser once:

```bash
python -m playwright install chromium
```

## HTTPS

```bash
DESLOP_DOMAIN=vdp.example.com docker compose --profile https up -d
```

Caddy issues and renews a Let's Encrypt certificate automatically and adds
security headers. For local testing use `DESLOP_DOMAIN=localhost`.

## LLM provider (your choice)

Set in `.env`:

- `DESLOP_LLM_PROVIDER=none` — no LLM; the offline raw-HTTP parser is used and
  reports without explicit request text go to human review. Fully local.
- `DESLOP_LLM_PROVIDER=ollama` + `DESLOP_LLM_MODEL=...` — local models.
- `DESLOP_LLM_PROVIDER=openai` + `DESLOP_LLM_MODEL=...` (+ optional
  `DESLOP_OPENAI_BASE_URL`) — any OpenAI-compatible endpoint.
- `DESLOP_LLM_PROVIDER=anthropic` + `DESLOP_LLM_MODEL=...`.

Embeddings default to the local multilingual `BAAI/bge-m3`. If the model is not
installed, DeSlop degrades to a deterministic hashing embedder so nothing breaks.

## Program configuration

1. Copy `config/programs/example-acme-cloud.yaml`.
2. Edit scope, staging host map, test accounts, bounty table, and replies.
3. Drop it in `config/programs/`. The `id` field inside the file is authoritative.

## Staging environment (required for reproduction)

- A staging environment with dummy data, separate from production.
- At least two test accounts with the same role and one with a different role.
- Automated login for validator accounts (including OTP handling in staging).
- The sandbox IP allowlisted in the staging WAF / rate limiter.
- A data reset / seed script or endpoint.

## The `doctor` command

```bash
deslop doctor <program_id>
```

Checks, with fix instructions for any failure:

- staging is reachable from the sandbox
- each test account can log in and has the expected role
- accounts with the same role are truly distinct identities
- egress to hosts outside the allowlist is actually blocked
- the OOB listener receives callbacks
- the data reset script runs
- email sending works (if the status page is enabled)

**Reproduction is refused until all required checks pass.** Note that the
egress-blocked check is designed to run *inside* the sandbox; on a developer host
with open egress it will correctly report NOT READY.

## Dashboard auth

Set `DESLOP_DASHBOARD_USER` and `DESLOP_DASHBOARD_PASSWORD_HASH`. Generate a hash:

```python
from deslop.web.auth import hash_password
print(hash_password("your-password"))
```
