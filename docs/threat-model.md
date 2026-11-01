# Threat Model

## Assets

- The security team's staging environment and validator test accounts.
- The internal triage dashboard and its audit log.
- Researcher PII (email) and report contents.
- Status-page tokens that grant a researcher access to their own report.
- The evidence packs produced for each report.

## Adversaries

- **Malicious researcher** - submits reports containing prompt injection, or
  steps crafted to make DeSlop attack hosts outside scope, exfiltrate secrets, or
  pivot inside the staging network.
- **Sloppy / low-effort submitter** - floods the queue with non-reproducible
  AI-written reports.
- **Opportunistic attacker** - targets the DeSlop deployment itself (dashboard
  auth, status page, setup wizard).

## Mitigations

### Prompt injection in report text
Report text is delimited in prompts and treated strictly as data. A deterministic
detector flags override, exfiltration, plan-manipulation, and out-of-scope fetch
attempts, including instructions hidden in HTML comments. Instructions to fetch
an *in-scope* host are normal reproduction steps and are not flagged; everything
else still is. Flagged reports are routed to `blocked_by_policy` and never
auto-executed.

### Steps that attack out-of-scope hosts
The deterministic validator rejects any step whose target is not in scope, before
execution. Destructive methods (`DELETE`) and destructive path patterns are
blocked outright. In addition, the executor enforces the egress allowlist on
every single request, so even a substituted plan cannot reach an unlisted host.

### Blind exfiltration and SSRF pivots
The executor enforces an egress allowlist in-process: staging hosts and the
self-hosted OOB listener are reachable, in-scope production hosts need approval,
everything else is refused before the request is made. Redirects are not
followed. **There is no container or network-level isolation behind this**, and
the check compares hostnames rather than resolved addresses, so a hostile DNS
record for an allowed name is not defended against; restrict what the host can
reach at the network level if that matters to you. SSRF proof requires a per-run
callback token generated at `recipe.setup()` time and embedded into the plan by
the substitution layer — a hit the listener never saw cannot be claimed.

### Credential leakage
Test-account credentials are substituted at execution time and redacted from logs
and evidence packs. The executor never reads raw report text.

### Runaway execution
Per-run request-count, wall-clock, and per-target rate limits are enforced.

### Production damage
Staging is the default target. Execution against an in-scope production host
(anything in scope that is not mapped onto staging) requires explicit approval:
`DESLOP_ALLOW_PRODUCTION`, the program's `allow_production`, or a per-report
`approve_production` decision recorded in the audit log. Unapproved plans stop
at the production gate (`needs_human_review`) before any request is sent.
Every reproduction request carries an `X-Bounty-User: deslop-repro-<run_id>`
header (configurable) so target-side logs can correlate test traffic.

### Unauthorized dashboard access
HTTP Basic auth backed by a PBKDF2 password hash, so it must be served over
HTTPS (see the Caddy profile). Every decision is written to the audit log. The
first-run setup wizard is unauthenticated by necessity; it refuses all requests
once setup is complete or a dashboard password hash is configured.

### Status-page data leakage
The page shows only public fields. Internal statuses, evidence, repro logs, and
CVSS reasoning are never rendered. Tokens are random (>=128 bits), stored hashed,
expiring, revocable, and rate limited.

### Injection into the UI
All report content is rendered through Jinja2 autoescaping. Public pages never
include internal status names or evidence.

### Duplicate misclassification
Duplicates are surfaced for a human. Same root cause on a different endpoint is
flagged for a human decision, not auto-closed. The earliest valid report is the
original.

## Out of scope

DeSlop does not defend against an attacker who already controls the host running
it, nor against a compromised staging environment. It is a filtering and
reproduction aid, not a trust boundary around your infrastructure.
