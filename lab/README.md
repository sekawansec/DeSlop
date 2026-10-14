# DeSlop Lab

Intentionally vulnerable targets used to develop and evaluate DeSlop's
reproduction and verification pipeline.

> Everything here is DELIBERATELY INSECURE. Run only on an isolated network.

## Services

| Service    | Port (host) | Purpose |
|------------|-------------|---------|
| `lab-app`  | 18000       | Custom FastAPI target with known IDOR, reflected XSS, stored XSS, SSRF and open redirect bugs. |
| `oob`      | 18080       | Self-hosted out-of-band listener; proves SSRF when a callback carries a unique per-run token. |
| `juice-shop` | 13000     | OWASP Juice Shop, an additional realistic target for manual/exploratory testing. |
| `dvwa`     | 14000       | DVWA (Damn Vulnerable Web Application). MariaDB-backed, security level `low`. |
| `dvwa-db`  | (internal)  | MariaDB backend for DVWA (not exposed on the host). |

## Run

```bash
docker compose -f lab/docker-compose.yml up -d
```

Then:

- Lab app:      http://localhost:18000
- OOB listener: http://localhost:18080/healthz
- Juice Shop:   http://localhost:13000
- DVWA:         http://localhost:14000

## DVWA

DVWA runs with `DEFAULT_SECURITY_LEVEL=low` so the planted vulnerabilities are
exploitable. First-run setup (creates the schema and users) is automated; if the
database is empty, open http://localhost:14000/setup.php and click
**Create / Reset Database**.

- Login: **admin / password**
- Accounts: `admin`/`password`, `gordonb`/`abc123`, `1337`/`charley`,
  `pablo`/`letmein`, `smithy`/`password`
- Login requires the `user_token` anti-CSRF field (DeSlop handles this via
  `login.csrf_field` in `config/programs/dvwa.yaml`).

Handled by DeSlop (`config/programs/dvwa.yaml` + `lab/recipes/dvwa_recipes.py`):

| Bug class | Endpoint | Proof expected by the verifier |
|-----------|----------|-------------------------------|
| Reflected XSS | `GET /vulnerabilities/xss_r/?name=` | Payload executes in a headless browser and sets a unique marker title. |
| OS command injection | `POST /vulnerabilities/exec/` (`ip=127.0.0.1; id`) | Response contains the output of `id` (`uid=... gid=...`). |


## Lab accounts (lab-app)

| user  | role  | tenant     | password   |
|-------|-------|------------|------------|
| alice | user  | tenant-one | alice-pass |
| bob   | user  | tenant-one | bob-pass   |
| carol | user  | tenant-two | carol-pass |
| admin | admin | tenant-one | admin-pass |

## Planted bugs

| Bug class | Endpoint | Proof expected by the verifier |
|-----------|----------|-------------------------------|
| IDOR | `GET /api/invoices/{id}` | Account B reads an invoice owned by account A; account A's `secret` field appears in B's response. |
| Reflected XSS | `GET /search?q=` | Payload executes in a headless browser and sets `document.title` to a unique marker. |
| Stored XSS | `POST /api/comments` → `GET /comments` | Same, after the comment is persisted and viewed. |
| SSRF | `GET /api/fetch?url=` | A callback with the unique per-run token reaches the OOB listener. |
| Open redirect | `GET /redirect?next=` | The browser is actually redirected to the marker domain. |

## Reset

The lab app exposes `POST /__test__/reset` to clear sessions and comments.
