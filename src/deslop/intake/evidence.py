"""Per-bug-class evidence checklist.

Deterministic checks on what a report *contains* — not whether its prose sounds
plausible. Each requirement maps to a concrete artifact a researcher who really
reproduced the bug can supply cheaply. Gaps are turned into follow-up questions
(``reply_draft`` / notes); they never auto-reject a report.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

_HTTP_BLOCK_RE = re.compile(r"[A-Z]{3,7}\s+\S+\s+HTTP/1\.[01]")
_OOB_RE = re.compile(
    r"(oob\.test|interactsh|burpcollaborator|webhook\.site|requestbin|"
    r"canarytokens|/cb/[A-Za-z0-9_\-]{4,}|callback|out-of-band|oob)",
    re.I,
)
_MARKER_RE = re.compile(
    r"(<script|alert\s*\(|document\.(domain|title|cookie)|onerror=|onload=|"
    r"[A-Z0-9_]{4,}MARKER[A-Z0-9_]*|{{.*}})",
    re.I,
)
_ACCOUNT_RE = re.compile(
    r"(account\s+[ab12]|user\s*[ab12]|attacker|victim|second account|"
    r"as\s+(alice|bob|carol|admin)|as_account|two accounts|other user)",
    re.I,
)
_CMD_OUT_RE = re.compile(
    r"(uid=\d+|gid=\d+|\$\(|;ls|&&\s*(id|whoami)|\bid\b.{0,20}output|whoami|"
    r"command output|/etc/passwd|root:)",
    re.I,
)
_REDIRECT_DEST_RE = re.compile(
    r"(next|redirect|return|returnurl|continue|dest|url|to)\s*=\s*https?://",
    re.I,
)
_REQUESTS_TWO_RE = _HTTP_BLOCK_RE


@dataclass
class EvidenceGap:
    code: str
    question: str


@dataclass
class CheckItem:
    """One checklist row for the triager UI: what was required and whether the
    report demonstrated it."""

    code: str
    question: str
    passed: bool


def _has_two_requests(text: str) -> bool:
    return len(_REQUESTS_TWO_RE.findall(text)) >= 2


def _has_oob(text: str) -> bool:
    return bool(_OOB_RE.search(text))


def _has_marker(text: str) -> bool:
    return bool(_MARKER_RE.search(text))


def _has_two_accounts(text: str) -> bool:
    # Two raw requests carrying distinct credentials, explicit attacker/victim
    # framing, or two account references plus two raw requests.
    distinct_creds = set(
        m.lower()
        for m in re.findall(r"(?:cookie|authorization)\s*:\s*([^\r\n]{4,})", text, re.I)
    )
    if len(distinct_creds) >= 2:
        return True
    if "attacker" in text.lower() and "victim" in text.lower():
        return True
    return bool(_ACCOUNT_RE.search(text)) and _has_two_requests(text)


def _has_redirect_dest(text: str) -> bool:
    return bool(_REDIRECT_DEST_RE.search(text))


def _has_cmd_output(text: str) -> bool:
    return bool(_CMD_OUT_RE.search(text))


_CHECKS = {
    "idor": [
        (
            "two_accounts",
            _has_two_accounts,
            "Two accounts and two requests: show the victim's object fetched "
            "while authenticated as the attacker (both raw requests + responses).",
        ),
    ],
    "xss_reflected": [
        (
            "marker",
            _has_marker,
            "Include the exact payload with a unique marker and a screenshot or "
            "log line proving it executed (e.g. document.domain).",
        ),
    ],
    "xss_stored": [
        (
            "marker",
            _has_marker,
            "Include the stored payload with a unique marker and where it "
            "renders; a screenshot/log showing execution is required.",
        ),
    ],
    "ssrf": [
        (
            "oob_callback",
            _has_oob,
            "Provide an out-of-band callback address (e.g. <token>.oob.test) "
            "that the server actually fetched.",
        ),
    ],
    "open_redirect": [
        (
            "redirect_destination",
            _has_redirect_dest,
            "Show the redirect parameter and the external destination URL the "
            "response points to.",
        ),
    ],
    "command_injection": [
        (
            "command_output",
            _has_cmd_output,
            "Show the executed command and its observed output (e.g. `id` "
            "output present in the response).",
        ),
    ],
}


def _collect_checks(
    vuln_class: str, program_requirements: list | None
) -> list[tuple[str, Callable[[str], bool], str]]:
    checks = list(_CHECKS.get(vuln_class, []))
    for req in program_requirements or []:
        if getattr(req, "bug_class", None) != vuln_class:
            continue
        for name in req.expect:
            for cls_checks in _CHECKS.values():
                for code, fn, question in cls_checks:
                    if code == name:
                        checks.append((code, fn, question))
    return checks


def evidence_checklist(
    vuln_class: str | None,
    report_text: str,
    attachments: list[dict] | None = None,
    program_requirements: list | None = None,
) -> list[CheckItem]:
    """Return every checklist item with its pass/fail for the triager UI."""
    if not vuln_class:
        return []
    blob = report_text
    for att in attachments or []:
        content = att.get("content")
        if content:
            blob += "\n" + content
    return [
        CheckItem(code=code, question=question, passed=bool(fn(blob)))
        for code, fn, question in _collect_checks(vuln_class, program_requirements)
    ]


def evidence_gaps(
    vuln_class: str | None,
    report_text: str,
    attachments: list[dict] | None = None,
    program_requirements: list | None = None,
) -> list[EvidenceGap]:
    """Return checklist items the report fails to demonstrate.

    ``program_requirements`` are optional per-program overrides
    (``ProgramConfig.evidence_requirements``); unknown expectation names are
    ignored.
    """
    return [
        EvidenceGap(code=item.code, question=item.question)
        for item in evidence_checklist(
            vuln_class, report_text, attachments, program_requirements
        )
        if not item.passed
    ]
