# DeSlop

DeSlop is a self-hosted filter for self-managed VDP and bug bounty programs.

It exists because LLMs made it nearly free to produce vulnerability reports
that *look* plausible but don't actually reproduce, and a human still has to
read all of them. DeSlop puts the friction back at intake, then replays each
report against your staging environment so a triager mostly sees submissions
that already come with proof.

Two things it will not do: reject a report on its own (a report that fails
reproduction is deprioritized, never closed), and decide anything with an LLM
(whether a bug is proven is always decided by deterministic code looking at
recorded traffic).


## How a report moves through it

1. **Intake** — the submission form (`/submit`) requires reproduction steps
   plus at least one artifact: a raw HTTP request, a HAR file, or a runnable
   PoC. It also requires a self-reproduction attestation and offers an
   optional AI-assistance disclosure and YouTube PoC link. A deterministic
   per-class checklist (SSRF wants an OOB callback, IDOR wants two accounts)
   turns missing pieces into follow-up questions.
2. **Filtering** — scope checks, excluded classes, prompt-injection scan,
   duplicate detection against existing reports (lexical similarity of
   title, class and endpoint — not a semantic model, see Known gaps).
3. **Parsing** — an LLM (or the offline raw-HTTP parser when no LLM is
   configured) turns the report into a locked list of steps. Nothing
   improvises later; reproduction runs exactly what the report claims.
4. **Validation** — deterministic policy checks. Out-of-scope or destructive
   steps are blocked before a single request is sent.
5. **Execution** — the locked steps are sent by the web app process itself,
   which refuses any host outside the program's egress allowlist. There is
   no container or network isolation around it (see Known gaps). Plans that
   point at in-scope *production* hosts stop at `needs_human_review` until a
   triager records `approve_production`.
6. **Verification** — a per-bug-class verifier reads the recorded
   request/response log (and the OOB listener, for blind bugs) and returns
   `proven`, `not_proven`, `inconclusive`, or `error`.
7. **Triage** — reports land in queues on the dashboard (`/dashboard`). A
   human decides. After a fix, the report can be retested.

The split that matters: the LLM parser only ever sees untrusted report text
and produces JSON — it has no execution access. The executor never sees raw
report text — it only runs locked steps. The verifier only sees technical
evidence.


## Running it

Needs Docker + Docker Compose. Python 3.12 if you want the CLI locally.

```bash
docker compose up -d
```

That brings up Postgres (with pgvector), the web app on
http://localhost:8000, and the OOB listener on http://localhost:8080.

On first run, every page redirects to `/setup` — a wizard that creates the
admin account, writes your first program config, and stores LLM/OOB settings.
No manual file editing required.

The wizard has no login (there is no admin yet), so it shuts itself off once
it finishes: afterwards `/setup` returns 403. To run it again, remove the
saved state and restart:

```bash
docker compose exec web rm /app/data/setup.json /app/data/setup.env
docker compose restart web
```

If you'd rather generate `.env` yourself, install the CLI first:

```bash
pip install -e .
deslop init        # writes .env with secrets + a dashboard password
```

(Just `pip install -r requirements.txt` gives you the dependencies but not
the `deslop` command.)

The dashboard uses HTTP Basic auth, so run it behind HTTPS (below) anywhere
other than your own machine.

The Docker image ships with Chromium, which XSS and open-redirect
verification need. If you run the app on the host instead, install it once:

```bash
python -m playwright install chromium
```

### HTTPS

The Caddy reverse proxy lives in a separate compose file:

```bash
DESLOP_DOMAIN=vdp.example.com \
  docker compose -f docker-compose.yml -f deploy/docker-compose.https.yml \
  --profile https up -d
```

Caddy gets and renews the Let's Encrypt cert itself. For local testing use
`DESLOP_DOMAIN=localhost`.


## Configuring a program

Everything program-specific is a YAML file — scope, excluded bug classes,
the staging host map, test accounts, bounty table, reply templates,
`allowed_egress_hosts`, `allow_production`, `canary`,
`evidence_requirements`. Copy `config/programs/example-acme-cloud.yaml` and
edit it; the `id` field inside the file is the program's identity.

Where the files go depends on how you run:

- **docker compose**: `config/container/` (the container mounts `./config`
  and reads `DESLOP_CONFIG_DIR=/app/config/container`)
- **local CLI / `deslop serve`**: `./config/programs` (or `--config-dir`)

The setup wizard writes to whichever directory the running app uses. New
program files in both directories are gitignored — only the shipped example
and lab configs stay in the repo.

Environment variables (`DESLOP_*`) cover the rest — database URL, LLM
provider, execution limits, SMTP, notifications. See `.env.example`. The LLM
provider is your choice: `anthropic`, `openai` (any OpenAI-compatible
endpoint), `ollama`, or `none`. With `none` the pipeline makes no LLM calls
and stays fully local; reports then need a raw HTTP request or HAR to be
reproduced, because only the offline parser is available.


## Using it day to day

- Researchers submit at `/submit` and can check `/status/<token>` later if
  the status page is enabled.
- Triagers work out of `/dashboard`: queues by status, report detail with
  the evidence pack, decisions, replies, retest buttons. Roles are `admin`,
  `triager`, `readonly` (extra users via `DESLOP_DASHBOARD_USERS_JSON`;
  read-only accounts see no mutating actions).
- `/dashboard/cvss?vector=...` is an exact CVSS v3.1 calculator. The score
  suggested on each report is only a heuristic starting point (keywords in
  the report, then a typical-impact baseline per bug class) and is labelled
  that way; the triager sets the real rating.
- Slack webhook and/or Telegram bot notifications on new reports and status
  changes (`DESLOP_NOTIFY_ENABLED`, `DESLOP_SLACK_WEBHOOK_URL`, ...).
- Per-IP submission rate limiting and an email/IP blacklist with temporary
  blocks (`data/blacklist.json`).

CLI:

```bash
deslop init                                     # generate .env (secrets + dashboard password)
deslop config list                              # list loaded programs
deslop config show acme-cloud                   # dump one program's config as JSON
deslop doctor lab                               # preflight checklist (informational; the pipeline does not wait for it)
deslop eval lab                                 # run the eval harness against a synthetic dataset
deslop dataset generate --out data/ds.jsonl     # write that dataset to disk
deslop demo --program dvwa                      # feed a mixed batch through the pipeline (lab or dvwa)
deslop serve --init-db                          # run the web app without Docker
deslop retest <program> <report_id>             # re-run reproduction after a fix
deslop reprocess                                # run the pipeline for reports stuck in 'received'
```


## What it can actually prove (v1)

| Bug class | Proof criterion |
|---|---|
| IDOR | A secret owned by account A (its `owned_markers` in the program config) appears in a successful response returned to account B's session — or to an unauthenticated request. The report's own claimed marker is never used as proof. |
| XSS (reflected/stored) | The payload's unique marker appears in `document.title` after the page loads in a headless browser. A marker that is merely reflected — including safely escaped output — is not proof. |
| SSRF | A callback carrying a unique per-run token reaches the OOB listener. `*.oob.test`, interactsh `oast.*`, `interact.sh`, `burpcollaborator.net`, and `oastify.com` hosts are rewritten to the program's own listener. |
| Open redirect | The report's external redirect target is rewritten to DeSlop's own marker domain (`marker.deslop.test`) before replay; the 3xx `Location` or the browser must land there. A redirect to a host the report merely named is not proof. |
| OS command injection | The response contains real command output (e.g. `uid=... gid=...` from `id`) that was not present in the request — reflected payload text is not proof. |

Bug classes without a recipe get routed to `manual_reproduction_required`.
See `CONTRIBUTING.md` for how to write one.

Two deployment requirements for automatic proof:

- **IDOR** needs trusted ownership data: fill `owned_markers` on
  `test_accounts` (and `canary.owner` if you plant a canary) so the verifier
  can tell whose data a response contains. Without them, IDOR verdicts stay
  `inconclusive` — deliberately.
- **SSRF** needs the OOB listener (`DESLOP_OOB_BASE_URL`) to be reachable
  *from the staging environment*, since staging is what makes the callback.
  The verifier queries the same URL, so it must also work for DeSlop itself.

Optionally, plant a `canary` token in staging and mark the bug classes that
should surface it; a report that never shows the canary gets flagged to the
reviewer.


## Lab

`lab/docker-compose.yml` brings up intentionally vulnerable targets — keep
them on an isolated network:

- **custom-app** on :18000 — IDOR, reflected/stored XSS, SSRF, open redirect
- **DVWA** on :14000 — MariaDB-backed, security level `low`
- **OWASP Juice Shop** on :13000
- **OOB listener** on :18080

```bash
docker compose -f lab/docker-compose.yml up -d
deslop demo --program dvwa     # proves DVWA reflected XSS + command injection
```

See `lab/README.md` for accounts and the planted bugs.


## Eval numbers (synthetic)

`deslop eval lab` pushes a generated dataset (`seed=1337`, 37 reports) through
the pipeline against the lab app with no LLM. It needs Chromium for the
XSS/open-redirect checks (`python -m playwright install chromium`) and an OOB
URL that both the verifier and the lab containers can reach — the lab-network
gateway address works because the OOB port is published on the host:

```bash
docker compose -f lab/docker-compose.yml up -d lab-app oob
export DESLOP_OOB_BASE_URL="http://$(docker network inspect deslop-lab_lab --format '{{(index .IPAM.Config 0).Gateway}}'):18080"
deslop eval lab
```

| Provider | Routing acc. | Repro rate | False reproduced | Dup precision | Dup recall | Injection blocked |
|----------|--------------|------------|------------------|---------------|------------|-------------------|
| none     | 100.00%      | 100.00%    | 0                | 100.00%       | 100.00%    | 3/3               |

| Report label | Routed as expected |
|---|---|
| duplicate | 15/15 |
| excluded_class | 3/3 |
| incomplete | 3/3 |
| injection | 3/3 |
| out_of_scope | 3/3 |
| slop | 5/5 |
| valid | 5/5 |

How to read this:

- The dataset is generated from templates written by the same person who
  wrote the pipeline. Treat it as a regression check, not as evidence of
  accuracy on real reports. Nobody has measured that yet.
- The 15 duplicate rows are scored by the harness's own retrieval step, not by
  `pipeline.run()` (the pipeline is given no corpus during eval), so that row
  is optimistic.
- Samples are tiny (5 valid, 5 slop). `False reproduced: 0` only says none of
  the 32 non-valid reports was marked proven.
- These numbers were measured with an LLM provider of `none` (the offline
  raw-HTTP parser). How they change with an LLM configured has not been
  measured.


## Repo layout

```
src/deslop/
  cli.py        argparse CLI: init, config, doctor, eval, demo, serve, retest
  config/       settings + per-program YAML schema and loader
  db/           SQLAlchemy models (pgvector on Postgres, JSON on SQLite)
  llm/          provider abstraction, embeddings, prompts
  parser/       LLM step parser + offline raw-HTTP parser
  repro/        step model, scope, validator, substitution, web executor
  sandbox/      egress policy (host allowlist; no container isolation)
  security/     prompt-injection scanning
  intake/       evidence checklist, rate limiting, blacklist
  recipes/      recipe/verifier plugins (IDOR, XSS, SSRF, open redirect, cmdinj)
  pipeline/     orchestrator, filters, routing, retest
  dedup/        normalization, retrieval, judgement
  eval/         metrics + eval runner
  dataset/      synthetic dataset generator
  web/          FastAPI app: submit form, status page, setup wizard, dashboard
  oob/          self-hosted out-of-band listener
lab/            intentionally vulnerable targets (custom app, DVWA, Juice Shop, OOB)
config/         program configs (programs/ for local, container/ for compose)
deploy/         Caddy HTTPS compose file
docs/           architecture, setup, threat model
```


## Security notes

Report content is untrusted input: it is delimited in prompts, scanned for
prompt injection, and the executor only ever runs the locked steps. The
executor refuses any host outside the program's egress allowlist before each
request, credentials are redacted from logs and evidence packs, and
production reproduction requires explicit approval before anything is sent.
The threat model is in `docs/threat-model.md`.

## Known gaps

Things that are easy to assume from the description but are not true yet:

- **No container or network isolation.** Requests derived from a report are
  sent by the web app process itself. The egress allowlist compares
  hostnames, not resolved addresses, so it does not protect against a
  hostile DNS record for an allowed name. Run it somewhere where that
  process can only reach what you are happy for it to reach.
- **Duplicate detection is lexical.** It compares hashed tokens of title,
  class and endpoint. The `DESLOP_EMBEDDING_PROVIDER` / `DESLOP_EMBEDDING_MODEL`
  settings (default `bge-m3`) exist, but the live pipeline does not use them
  and `sentence-transformers` is not a dependency.
- **`deslop doctor` is advisory.** Nothing in the pipeline waits for it. Its
  egress check also reports NOT READY on any host that has internet access.
- **Triage runs as an in-process background task, not a queue.** `POST /submit`
  stores the report and answers immediately; the pipeline runs afterwards in
  the web process. If the process stops mid-run, that report stays in
  `received`. `deslop reprocess` runs the pipeline for everything still in
  `received`; run it when the app is idle, because a report that is being
  processed right now also still shows as `received`.
- **Suggested CVSS is a heuristic**, not a rating.
- The offline parser (no LLM) is conservative and under-reproduces.
- Only the web executor exists; mobile/desktop executors are interface stubs.
- A bug class with no recipe is never auto-proven.
- Not a full VDP platform: no researcher accounts, no long discussion
  threads, no disclosure workflow.


## Liability

This tool sends HTTP requests and drives a headless browser against targets
you configure. Only point it at infrastructure you own or are explicitly
authorized to test.


## License

Apache License 2.0 — see `LICENSE` and `NOTICE`.
