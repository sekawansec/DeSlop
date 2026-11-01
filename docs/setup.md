# Setup

## Requirements

- Python 3.12
- PostgreSQL 16 + pgvector (production); SQLite is used automatically for tests
  and local dev
- Docker + Docker Compose (web app, Postgres, OOB listener, lab targets)

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

For client-side (XSS / open-redirect) verification, install the browser once
(the Docker image already includes it):

```bash
python -m playwright install chromium
```

## HTTPS

```bash
DESLOP_DOMAIN=vdp.example.com \
  docker compose -f docker-compose.yml -f deploy/docker-compose.https.yml \
  --profile https up -d
```

The Caddy service is defined in the second file, so both are needed. Caddy
issues and renews a Let's Encrypt certificate automatically and adds
security headers. For local testing use `DESLOP_DOMAIN=localhost`.

## LLM provider (your choice)

Set in `.env`:

- `DESLOP_LLM_PROVIDER=none` — no LLM; the offline raw-HTTP parser is used and
  reports without explicit request text go to human review. Fully local.
- `DESLOP_LLM_PROVIDER=ollama` + `DESLOP_LLM_MODEL=...` — local models.
- `DESLOP_LLM_PROVIDER=openai` + `DESLOP_LLM_MODEL=...` (+ optional
  `DESLOP_OPENAI_BASE_URL`) — any OpenAI-compatible endpoint.
- `DESLOP_LLM_PROVIDER=anthropic` + `DESLOP_LLM_MODEL=...`.

Duplicate detection currently always uses the built-in hashing embedder
(lexical similarity). The `DESLOP_EMBEDDING_*` settings (default `BAAI/bge-m3`)
are accepted but not used by the live pipeline, and `sentence-transformers` is
not a dependency.

## Program configuration

1. Copy `config/programs/example-acme-cloud.yaml`.
2. Edit scope, staging host map, test accounts, bounty table, and replies.
3. Drop it in `config/programs/`. The `id` field inside the file is authoritative.

Notes on policy fields:

- `in_scope`/`out_of_scope` entries accept `domain` (apex + subdomains),
  `wildcard` (`*.example.com`, subdomains only), `ip_range`, `url`, `app_id`.
  URL-shaped values are normalized to host patterns automatically.
- `allowed_egress_hosts` lists staging-side hosts the executor may reach (the
  staging `base_url` and `host_map` targets are always allowed). Bare hosts
  cover their subdomains; `*.domain` is supported; URL values are reduced to
  their host.
- `allow_production: false` (default) keeps reproduction off production hosts;
  a triager can still approve it per report (`approve_production` decision).
- `test_accounts[].owned_markers` — secrets that appear only in that account's
  own data on staging (e.g. a unique string in its invoices or profile). The
  IDOR verifier proves a claim only when a marker owned by one account shows
  up in a response returned to a different account (or an unauthenticated
  request). Without `owned_markers`, IDOR verdicts stay `inconclusive`.
- `canary` — `{enabled, token, owner, required_for: [bug classes]}`. Plant the
  token in staging, inside the `owner` account's data; claims in the listed
  classes that never surface it get a reviewer note. Setting `owner` also lets
  the IDOR verifier treat the canary as victim-owned proof.
- `evidence_requirements` — per-class checklist overrides
  (`{bug_class, expect: [check names]}`), see `deslop.intake.evidence`.

## OOB listener reachability (required for SSRF proof)

`DESLOP_OOB_BASE_URL` is used twice: report callback hosts (`*.oob.test`,
interactsh `oast.*`, `interact.sh`, `burpcollaborator.net`, `oastify.com`) are
rewritten to it, and the SSRF verifier polls the same URL for hits. It must
therefore be reachable **both from DeSlop and from the staging environment** —
staging is what makes the outbound callback. In Docker Compose the default
`http://oob:8080` satisfies both because everything shares a network; for a
remote staging, use a routable address (e.g. the host's IP) that staging can
fetch, not `localhost`.

## Staging environment (required for reproduction)

- A staging environment with dummy data, separate from production.
- At least two test accounts with the same role and one with a different role.
- Automated login for validator accounts (including OTP handling in staging).
- The IP of the host running DeSlop allowlisted in the staging WAF / rate
  limiter.
- A data reset / seed script or endpoint.

## The `doctor` command

```bash
deslop doctor <program_id>
```

Checks, with fix instructions for any failure:

- staging is reachable from where doctor runs
- each test account can log in and has the expected role
- accounts with the same role are truly distinct identities
- egress to hosts outside the allowlist is actually blocked
- the OOB listener is healthy
- the data reset script runs
- email sending works (if the status page is enabled)

The command exits non-zero when a required check fails, but **it is advisory:
the pipeline does not consult it before reproducing a report.** The
egress-blocked check opens a real connection to the probe host, so on any host
with open internet access it reports NOT READY; it only passes where egress is
actually firewalled.

## Dashboard auth

The dashboard uses HTTP Basic auth, so serve it over HTTPS outside your own
machine.

On a fresh install the first-run wizard creates the admin account. The wizard
is unauthenticated, so it closes itself after it finishes (`/setup` then
returns 403), and it never opens if `DESLOP_DASHBOARD_PASSWORD_HASH` is already
set. To run it again, delete `data/setup.json` and `data/setup.env` (in Docker:
`/app/data/`) and restart the app.

Or set `DESLOP_DASHBOARD_USER` and `DESLOP_DASHBOARD_PASSWORD_HASH` yourself.
Generate a hash:

```python
from deslop.web.auth import hash_password
print(hash_password("your-password"))
```
