"""Substitution mechanism for locked reproduction plans.

The only permitted mutations to a locked plan are the substitutions defined
here. Every substitution is recorded so it appears in the evidence pack.

Allowed:
  credentials/cookies/session tokens -> program test accounts
  host/domain -> staging host (via the program's host_map)
  dynamic tokens (CSRF/nonce/timestamp) -> re-fetched from prior responses
  object IDs owned by the researcher -> equivalent IDs owned by test accounts

Not allowed: changing payloads, endpoints, methods, or parameters; adding,
removing, or reordering steps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ..config.schema import ProgramConfig, TestAccount
from .steps import ReproPlanModel, ReproStep

CREDENTIAL_COOKIES = {
    "session",
    "sessionid",
    "sid",
    "jsessionid",
    "phpsessid",
    "connect.sid",
    "auth",
    "auth_token",
    "access_token",
    "token",
    "remember_token",
}
CREDENTIAL_HEADERS = {"authorization", "cookie", "x-auth-token", "x-api-key"}

DYNAMIC_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*(csrf|nonce|timestamp|token|dynamic)\s*\}\}", re.I
)


@dataclass
class Substitution:
    step_index: int
    field: str
    kind: str
    original: str
    replacement: str
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "step_index": self.step_index,
            "field": self.field,
            "kind": self.kind,
            "original": self.original,
            "replacement": self.replacement,
            "note": self.note,
        }


@dataclass
class SubstitutionResult:
    steps: list[ReproStep]
    substitutions: list[Substitution] = field(default_factory=list)


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-2:]


def _rewrite_host(url: str, program: ProgramConfig) -> tuple[str, str | None]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    mapping = {k.lower(): v for k, v in program.staging.host_map.items()}
    new_host = mapping.get(host)
    if not new_host:
        return url, None
    netloc = new_host if not parts.port else f"{new_host}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), new_host


def _rewrite_oob(url: str, oob_base_url: str) -> tuple[str, str | None]:
    """Rewrite a placeholder OOB callback host to the configured OOB listener.

    Reports use a symbolic host such as ``<token>.oob.test``; the real listener
    lives at ``oob_base_url``. This is a host substitution to a configured host,
    which is permitted (and logged).
    """
    if not oob_base_url:
        return url, None
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not (host.endswith(".oob.test") or host == "oob.test"):
        return url, None
    base = urlsplit(oob_base_url)
    netloc = base.hostname or ""
    if base.port:
        netloc = f"{netloc}:{base.port}"
    # Preserve the callback path (e.g. /cb/<token>).
    path = parts.path or "/cb"
    rebuilt = urlunsplit((base.scheme or "http", netloc, path, parts.query, parts.fragment))
    return rebuilt, netloc


def _account_for_step(step: ReproStep, program: ProgramConfig) -> TestAccount | None:
    if not step.as_account:
        return None
    for acct in program.test_accounts:
        if acct.id == step.as_account:
            return acct
    return None


def _substitute_credentials(
    step: ReproStep, account: TestAccount, subs: list[Substitution]
) -> ReproStep:
    req = step.request
    if req.cookies:
        new_cookies = {}
        for name, value in req.cookies.items():
            if name.lower() in CREDENTIAL_COOKIES and value:
                subs.append(
                    Substitution(
                        step.index,
                        f"cookies.{name}",
                        "credential",
                        _mask(value),
                        f"<session of {account.id}>",
                        "replaced with test-account session",
                    )
                )
            new_cookies[name] = value
        req = req.model_copy(update={"cookies": new_cookies})

    headers = dict(req.headers)
    for name in list(headers):
        if name.lower() in CREDENTIAL_HEADERS and headers[name]:
            subs.append(
                Substitution(
                    step.index,
                    f"headers.{name}",
                    "credential",
                    _mask(headers[name]),
                    f"<auth of {account.id}>",
                    "replaced with test-account auth",
                )
            )
    return step.model_copy(update={"request": req})


def _record_dynamic_placeholders(step: ReproStep, subs: list[Substitution]) -> None:
    blob = " ".join(
        [
            step.request.url,
            " ".join(step.request.headers.values()),
            step.request.body or "",
        ]
    )
    for m in DYNAMIC_PLACEHOLDER_RE.finditer(blob):
        subs.append(
            Substitution(
                step.index,
                "request",
                "dynamic",
                m.group(0),
                f"<live {m.group(1)}>",
                "resolved from a prior response at execution time",
            )
        )


def apply_substitutions(
    plan: ReproPlanModel, program: ProgramConfig, *, oob_base_url: str = ""
) -> SubstitutionResult:
    """Apply whitelisted substitutions to a locked plan.

    Host rewrites happen here; credential and dynamic substitutions are recorded
    and resolved by the executor (which has the actual test-account sessions).
    Step order, methods, paths, and payloads are never changed.
    """
    subs: list[Substitution] = []
    out: list[ReproStep] = []

    for step in plan.steps:
        new_url, new_host = _rewrite_host(step.request.url, program)
        if new_host:
            subs.append(
                Substitution(
                    step.index,
                    "request.url",
                    "host",
                    step.request.url,
                    new_url,
                    f"mapped to staging host {new_host}",
                )
            )
            step = step.model_copy(
                update={"request": step.request.model_copy(update={"url": new_url})}
            )

        # Rewrite any embedded OOB callback URLs (query params / bodies).
        rewritten_url, oob_note = _rewrite_oob(step.request.url, oob_base_url)
        if oob_note:
            subs.append(
                Substitution(
                    step.index, "request.url", "oob_host", step.request.url, rewritten_url,
                    "rewrote placeholder OOB callback host to the configured listener",
                )
            )
            step = step.model_copy(
                update={"request": step.request.model_copy(update={"url": rewritten_url})}
            )
        if step.request.body and oob_base_url:
            new_body, note = _rewrite_oob_in_text(step.request.body, oob_base_url)
            if note:
                subs.append(
                    Substitution(
                        step.index, "request.body", "oob_host", "<body>", new_body,
                        "rewrote placeholder OOB callback host in body",
                    )
                )
                step = step.model_copy(
                    update={"request": step.request.model_copy(update={"body": new_body})}
                )

        account = _account_for_step(step, program)
        if account is not None:
            step = _substitute_credentials(step, account, subs)

        _record_dynamic_placeholders(step, subs)
        out.append(step)

    return SubstitutionResult(steps=out, substitutions=subs)


def _rewrite_oob_in_text(text: str, oob_base_url: str) -> tuple[str, bool]:
    import re as _re

    def repl(match: _re.Match[str]) -> str:
        rewritten, note = _rewrite_oob(match.group(0), oob_base_url)
        return rewritten if note else match.group(0)

    pattern = _re.compile(r"https?://[^\s\"'<>]+\.oob\.test[^\s\"'<>]*")
    new_text = pattern.sub(repl, text)
    return new_text, new_text != text
