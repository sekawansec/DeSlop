"""Substitution mechanism for locked reproduction plans.

The only permitted mutations to a locked plan are the substitutions defined
here. Every substitution is recorded so it appears in the evidence pack.

Allowed:
  credentials/cookies/session tokens -> program test accounts
  host/domain -> staging host (via the program's host_map, staging scheme)
  OOB callback hosts (oob.test, interactsh, Collaborator, oastify) -> the
    program's own OOB listener with a per-run token
  open-redirect external targets -> DeSlop's marker domain
  dynamic placeholders ({{csrf}}, {{nonce}}, ...) -> recorded for the executor

Not allowed: changing payloads, endpoints, methods, or other parameters;
adding, removing, or reordering steps. Researcher-owned object IDs are not
remapped — reports must reference objects that exist on staging.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit, urlunsplit

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

#: Host suffixes recognised as OOB callback addresses. Reports may use the
#: built-in ``*.oob.test`` placeholder or a public callback service
#: (interactsh's oast.* domains, interact.sh, Burp Collaborator, oastify.com);
#: all are rewritten to the program's own OOB listener so the callback is
#: actually observed — external services are never contacted.
KNOWN_OOB_HOST_SUFFIXES = (
    "oob.test",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
    "interact.sh",
    "interactsh.com",
    "burpcollaborator.net",
    "oastify.com",
)


#: DeSlop's own redirect marker domain. For open-redirect plans, an external
#: destination in a redirect parameter is rewritten to this host, so a proof
#: means the app really followed the parameter — not that it redirects to some
#: host the report happened to name.
REDIRECT_MARKER_HOST = "marker.deslop.test"

REDIRECT_PARAMS = {
    "next", "redirect", "redirect_uri", "redirect_url", "redirecturl", "return",
    "return_to", "returnto", "returnurl", "return_url", "continue", "dest",
    "destination", "url", "to", "goto", "target", "forward", "r", "u",
}

_PARAM_RE = re.compile(r"(?P<lead>^|[?&])(?P<name>[^=&#?]+)=(?P<value>[^&#]*)")


def is_known_oob_host(host: str) -> bool:
    host = (host or "").lower()
    return any(
        host == suffix or host.endswith("." + suffix) for suffix in KNOWN_OOB_HOST_SUFFIXES
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
    # host_map values may already carry a port ("127.0.0.1:18000"); use them
    # verbatim as the authority. Only append the original port when the mapped
    # value is a bare host.
    if ":" in new_host:
        netloc = new_host
    elif parts.port:
        netloc = f"{new_host}:{parts.port}"
    else:
        netloc = new_host
    # The mapped host is staging; its scheme is defined by staging.base_url,
    # not by whatever scheme the report wrote (the offline raw-HTTP parser
    # always produces http://).
    scheme = urlsplit(program.staging.base_url).scheme or parts.scheme
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment)), new_host


def _rewrite_oob(url: str, oob_base_url: str, run_token: str | None = None) -> tuple[str, str | None]:
    """Rewrite a placeholder OOB callback host to the configured OOB listener.

    Reports use a symbolic host such as ``<token>.oob.test`` or a public
    callback service (interactsh/Burp Collaborator); the real listener lives
    at ``oob_base_url`` and only records hits under ``/cb/<token>``. The
    callback token is taken from ``run_token`` (generated by the recipe setup)
    when available, else from the callback's subdomain — so a hit can never
    be faked by a token the listener never saw.
    """
    if not oob_base_url:
        return url, None
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not is_known_oob_host(host):
        return url, None
    base = urlsplit(oob_base_url)
    netloc = base.hostname or ""
    if base.port:
        netloc = f"{netloc}:{base.port}"
    host_token = host.split(".")[0] if "." in host else ""
    token = run_token or host_token or "hit"
    # The listener keys callbacks by the /cb/<token> path segment and the
    # verifier polls for our token, so the rewritten URL must carry it — even
    # when the report embedded its own /cb/<other> path.
    path = f"/cb/{token}"
    rebuilt = urlunsplit((base.scheme or "http", netloc, path, parts.query, parts.fragment))
    return rebuilt, netloc


def _rewrite_redirect_targets(text: str, program: ProgramConfig) -> tuple[str, bool]:
    """Point external redirect-parameter values at the DeSlop marker domain.

    Only values of redirect-style parameters that are absolute (or
    protocol-relative) URLs to an out-of-scope host are touched; the path is
    kept, the encoding style of the original value is preserved.
    """
    from .scope import check_scope

    def repl(m: re.Match[str]) -> str:
        name, raw = m.group("name"), m.group("value")
        if name.lower() not in REDIRECT_PARAMS:
            return m.group(0)
        value = unquote(raw)
        target = "https:" + value if value.startswith("//") else value
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host or host == REDIRECT_MARKER_HOST:
            return m.group(0)
        if check_scope(host, program).allowed:
            return m.group(0)
        new_value = urlunsplit(("https", REDIRECT_MARKER_HOST, parts.path, parts.query, ""))
        encoded = quote(new_value, safe="") if raw != value else new_value
        return f"{m.group('lead')}{name}={encoded}"

    new_text = _PARAM_RE.sub(repl, text)
    return new_text, new_text != text


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
    plan: ReproPlanModel,
    program: ProgramConfig,
    *,
    oob_base_url: str = "",
    run_token: str | None = None,
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
        rewritten_url, oob_note = _rewrite_oob(step.request.url, oob_base_url, run_token)
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
        # OOB callbacks embedded inside the target URL's query string (the
        # common SSRF shape: ?url=http://<token>.oob.test/).
        if oob_base_url:
            new_url_text, note = _rewrite_oob_in_text(step.request.url, oob_base_url, run_token)
            if note:
                subs.append(
                    Substitution(
                        step.index, "request.url", "oob_host", "<url>", new_url_text,
                        "rewrote placeholder OOB callback host in URL",
                    )
                )
                step = step.model_copy(
                    update={"request": step.request.model_copy(update={"url": new_url_text})}
                )
        if step.request.body and oob_base_url:
            new_body, note = _rewrite_oob_in_text(step.request.body, oob_base_url, run_token)
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

        if plan.bug_class == "open_redirect":
            for fld in ("url", "body"):
                original = getattr(step.request, fld) or ""
                if not original:
                    continue
                rewritten, changed = _rewrite_redirect_targets(original, program)
                if changed:
                    subs.append(
                        Substitution(
                            step.index, f"request.{fld}", "redirect_target", original, rewritten,
                            f"external redirect target pointed at {REDIRECT_MARKER_HOST}",
                        )
                    )
                    step = step.model_copy(
                        update={"request": step.request.model_copy(update={fld: rewritten})}
                    )

        account = _account_for_step(step, program)
        if account is not None:
            step = _substitute_credentials(step, account, subs)

        _record_dynamic_placeholders(step, subs)
        out.append(step)

    return SubstitutionResult(steps=out, substitutions=subs)


_OOB_URL_RE = re.compile(
    r"https?://[\w.-]*(?:"
    + "|".join(s.replace(".", r"\.") for s in KNOWN_OOB_HOST_SUFFIXES)
    + r")(?::\d+)?[^\s\"'<>]*"
)


def _rewrite_oob_in_text(text: str, oob_base_url: str, run_token: str | None = None) -> tuple[str, bool]:
    def repl(match: re.Match[str]) -> str:
        rewritten, note = _rewrite_oob(match.group(0), oob_base_url, run_token)
        return rewritten if note else match.group(0)

    # Anchor on the host token directly after the scheme so a URL that merely
    # *embeds* an OOB URL (SSRF shape: /api/fetch?url=http://x.oob.test/) is
    # rewritten at the inner match, not swallowed by a greedy outer one.
    new_text = _OOB_URL_RE.sub(repl, text)
    return new_text, new_text != text
