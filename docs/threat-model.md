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
  auth, status page, sandbox escape).

## Mitigations

### Prompt injection in report text
Report text is delimited in prompts and treated strictly as data. A deterministic
detector flags override, exfiltration, and forced-fetch patterns, including
instructions hidden in HTML comments. Flagged reports are routed to
`blocked_by_policy` and never auto-executed.

### Steps that attack out-of-scope hosts
The deterministic validator rejects any step whose target is not in scope, before
execution. Destructive methods (`DELETE`) and destructive path patterns are
blocked outright.

### Blind exfiltration and SSRF pivots
The sandbox is a single-use container with egress restricted at the network level
to in-scope staging hosts and the self-hosted OOB listener. All other connections
are blocked.

### Credential leakage
Test-account credentials are substituted at execution time and redacted from logs
and evidence packs. The executor never reads raw report text.

### Runaway execution
Per-run request-count, wall-clock, and per-target rate limits are enforced.

### Production damage
Staging is the default target. Execution against production requires manual
triager approval per report.

### Unauthorized dashboard access
HTTP Basic auth backed by a PBKDF2 password hash. Every decision is written to the
audit log.

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
