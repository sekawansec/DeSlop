"""LLM step parser.

Turns an untrusted report into a locked, structured :class:`ReproPlanModel`.
The parser has no execution access: it only produces data. Its output is always
validated; on failure the report is routed to human review.

A deterministic, no-LLM fallback parser is provided so the pipeline is testable
and so a report with an explicit raw HTTP request can be parsed offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config.settings import Settings, get_settings
from ..llm.client import LLMClient
from ..llm.prompts import (
    STEP_PARSER_SYSTEM,
    STEP_PARSER_TEMPLATE,
    render,
    wrap_untrusted,
)
from ..llm.schemas import ParsedPlan
from ..repro.steps import (
    ReproPlanModel,
    ReproStep,
    SourceRef,
    StepExpectation,
    StructuredRequest,
)

_CANONICAL = {
    "idor": "idor",
    "bola": "idor",
    "broken object level": "idor",
    "access control": "idor",
    "xss_reflected": "xss_reflected",
    "reflected xss": "xss_reflected",
    "xss_stored": "xss_stored",
    "stored xss": "xss_stored",
    "persistent xss": "xss_stored",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "open_redirect": "open_redirect",
    "open redirect": "open_redirect",
    "command_injection": "command_injection",
    "command injection": "command_injection",
    "rce": "command_injection",
    "os command": "command_injection",
    "code execution": "command_injection",
}


def canonical_bug_class(raw: str | None) -> str:
    if not raw:
        return "unknown"
    key = raw.strip().lower()
    if key in _CANONICAL:
        return _CANONICAL[key]
    for needle, canon in _CANONICAL.items():
        if needle in key:
            return canon
    return key


@dataclass
class ParseOutcome:
    ok: bool
    plan: ReproPlanModel | None = None
    missing_info: list[str] = field(default_factory=list)
    error: str | None = None
    used_llm: bool = False
    used_fallback: bool = False


def _to_plan(parsed: ParsedPlan, report_body: str) -> ReproPlanModel:
    steps: list[ReproStep] = []
    for i, ps in enumerate(parsed.steps):
        source = None
        if ps.source_quote:
            idx = report_body.find(ps.source_quote)
            source = SourceRef(
                quote=ps.source_quote,
                start=idx if idx >= 0 else None,
                end=(idx + len(ps.source_quote)) if idx >= 0 else None,
            )
        expectation = StepExpectation(marker=ps.marker) if ps.marker else None
        steps.append(
            ReproStep(
                index=i,
                description=ps.description,
                request=StructuredRequest(
                    method=ps.method.upper(),
                    url=ps.url,
                    headers=ps.headers,
                    cookies=ps.cookies,
                    body=ps.body,
                ),
                expectation=expectation,
                source=source,
                as_account=ps.as_account,
            )
        )
    return ReproPlanModel(bug_class=canonical_bug_class(parsed.bug_class), steps=steps)


class StepParser:
    def __init__(self, client: LLMClient | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or LLMClient(settings=self.settings)

    def parse(
        self, report_body: str, *, allow_fallback: bool = True, account_hints: dict[str, str] | None = None
    ) -> ParseOutcome:
        """Parse a report into a locked plan.

        Uses the LLM when configured; on failure or when unavailable, optionally
        falls back to the deterministic raw-HTTP parser.
        """
        if self.client.available:
            result = self.client.complete_validated(
                system=STEP_PARSER_SYSTEM,
                user=render(STEP_PARSER_TEMPLATE, report=wrap_untrusted(report_body)),
                schema=ParsedPlan,
                max_tokens=3000,
            )
            if result.ok and isinstance(result.value, ParsedPlan):
                parsed = result.value
                if not parsed.steps:
                    return ParseOutcome(
                        ok=False,
                        missing_info=parsed.missing_info,
                        error="parser found no reproduction steps",
                        used_llm=True,
                    )
                return ParseOutcome(
                    ok=True,
                    plan=_to_plan(parsed, report_body),
                    missing_info=parsed.missing_info,
                    used_llm=True,
                )
            # LLM failed validation: do not guess.
            if not allow_fallback:
                return ParseOutcome(ok=False, error=result.error, used_llm=True)

        if allow_fallback:
            fb = parse_from_raw_http(report_body, account_hints=account_hints)
            if fb is not None:
                fb.used_fallback = True
                return fb
        return ParseOutcome(ok=False, error="no LLM configured and no parseable raw HTTP request found")


def parse_from_raw_http(
    report_body: str, *, account_hints: dict[str, str] | None = None
) -> ParseOutcome | None:
    """Deterministic parser for a report that embeds a raw HTTP request.

    Extracts method, path, and Host header from fenced or plain ``GET /path``
    request blocks. This is intentionally conservative: it only handles explicit
    request text, never prose.

    ``account_hints`` maps a username/substring found in the report to a logical
    test-account id, so authenticated steps are bound to the right identity when
    the LLM parser is unavailable.
    """
    blocks = re.findall(
        r"(?:^|\n)\s*([A-Z]{3,7})\s+(\S+)\s+HTTP/1\.[01](.*?)(?=\n\s*[A-Z]{3,7}\s+\S+\s+HTTP/|\Z)",
        report_body,
        re.S,
    )
    if not blocks:
        return None

    hinted_account = _pick_account_hint(report_body, account_hints or {})

    steps: list[ReproStep] = []
    for i, (method, path, rest) in enumerate(blocks):
        host = None
        headers: dict[str, str] = {}
        body: str | None = None
        # Split headers from the body at the first blank line.
        if "\n\n" in rest:
            header_part, _, body_part = rest.partition("\n\n")
            # Drop a trailing markdown code fence if present.
            body_part = re.split(r"\n?```", body_part)[0]
            body = body_part.strip() or None
        else:
            header_part = rest
        for line in header_part.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, _, value = line.partition(":")
            name, value = name.strip(), value.strip()
            if name.lower() == "host":
                host = value
            elif name.lower() in {
                "cookie",
                "content-type",
                "authorization",
                "accept",
                "x-requested-with",
            }:
                headers[name] = value
        url = f"http://{host}{path}" if host and path.startswith("/") else path
        steps.append(
            ReproStep(
                index=i,
                description=f"{method} {path}",
                request=StructuredRequest(
                    method=method, url=url, headers=headers, body=body
                ),
                source=SourceRef(quote=f"{method} {path}", start=None, end=None),
                as_account=hinted_account,
            )
        )

    bug_class = _guess_bug_class(report_body)
    marker = _extract_marker(report_body, bug_class)
    steps_out: list[ReproStep] = []
    for st in steps:
        expectation = (
            st.expectation
            if st.expectation is not None
            else (StepExpectation(marker=marker) if marker else None)
        )
        steps_out.append(st.model_copy(update={"expectation": expectation}))
    return ParseOutcome(ok=True, plan=ReproPlanModel(bug_class=bug_class, steps=steps_out))


_MARKER_PATTERNS = (
    re.compile(r"document\.title\s*=\s*['\"]([A-Za-z0-9_\-]{6,})['\"]"),
    re.compile(r"([A-Z0-9_]*XSS[A-Z0-9_]{0,}MARKER[A-Z0-9_]*)"),
)


def _extract_marker(report_body: str, bug_class: str) -> str | None:
    """Recover a payload execution marker from a raw report (offline mode)."""
    if "xss" not in bug_class:
        return None
    for pattern in _MARKER_PATTERNS:
        m = pattern.search(report_body)
        if m:
            return m.group(1)
    return None


def _pick_account_hint(report_body: str, hints: dict[str, str]) -> str | None:
    lowered = report_body.lower()
    for needle, account_id in hints.items():
        if needle and needle.lower() in lowered:
            return account_id
    return None


def _guess_bug_class(text: str) -> str:
    lowered = text.lower()
    for needle, canon in _CANONICAL.items():
        if needle in lowered:
            return canon
    return "unknown"
