"""Prompt-injection detection.

Report content is untrusted. Before it reaches any LLM, we scan it for attempts
to override instructions, exfiltrate data, or force requests to hosts outside
scope. Detection is deterministic and does not rely on a model.

Detected injections do not auto-reject a report; they set the injection flag and
route it to ``blocked_by_policy`` for a human to look at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class InjectionFinding:
    category: str
    pattern: str
    snippet: str

    def to_dict(self) -> dict:
        return {"category": self.category, "pattern": self.pattern, "snippet": self.snippet}


@dataclass
class InjectionReport:
    flagged: bool = False
    findings: list[InjectionFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"flagged": self.flagged, "findings": [f.to_dict() for f in self.findings]}


_INSTRUCTION_OVERRIDE = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions?",
    r"disregard\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions?",
    r"forget\s+(everything|all|your)\s+(you|previous|prior|instructions?)",
    r"you\s+are\s+now\s+(a|an)\b",
    r"new\s+instructions?\s*:",
    r"\bsystem\s*:\s*",
    r"\bassistant\s*:\s*",
    r"do\s+not\s+treat\s+this\s+as\s+data",
    r"override\s+(the\s+)?(validator|policy|rules|scope)",
    r"(validator|policy|filter|guardrails?)\s+(has\s+been\s+)?(disabled|bypassed|turned\s+off)",
    r"act\s+as\s+(an?\s+)?(unrestricted|dan|developer\s+mode)",
]

_EXFIL = [
    r"(include|append|add|return|send|echo|print)\s+(the\s+)?(response|output|result|content)\s+(of|from|to)",
    r"exfiltrate",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"/latest/meta-data",
    r"(aws|gcp|azure)\s+(credentials|metadata|token)",
]

_FORCE_FETCH = [
    r"(fetch|request|visit|call|hit|curl|wget)\s+https?://",
    r"send\s+(a\s+)?request\s+to\s+https?://",
    r"add\s+a\s+step\s+(that\s+)?(sends?|requests?|fetches?)",
]

_COMPILED = [
    ("instruction_override", re.compile("|".join(_INSTRUCTION_OVERRIDE), re.I)),
    ("exfiltration", re.compile("|".join(_EXFIL), re.I)),
    ("forced_fetch", re.compile("|".join(_FORCE_FETCH), re.I)),
]


def _snippet(text: str, match: re.Match) -> str:
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)
    return text[start:end].replace("\n", " ").strip()


def detect_injection(text: str, *, extra_hosts: list[str] | None = None) -> InjectionReport:
    """Scan untrusted text for prompt-injection and out-of-scope-fetch attempts."""
    findings: list[InjectionFinding] = []
    for category, pattern in _COMPILED:
        for match in pattern.finditer(text):
            findings.append(
                InjectionFinding(category=category, pattern=match.re.pattern, snippet=_snippet(text, match))
            )

    # HTML comments are a common hiding place for injected instructions.
    for comment in re.findall(r"<!--(.*?)-->", text, re.S):
        for category, pattern in _COMPILED:
            for match in pattern.finditer(comment):
                findings.append(
                    InjectionFinding(
                        category=f"hidden_comment:{category}",
                        pattern=match.re.pattern,
                        snippet=_snippet(comment, match),
                    )
                )

    # Any attempt to reach a host that is not obviously part of the target.
    if extra_hosts:
        for host in extra_hosts:
            if host and host.lower() in text.lower():
                findings.append(
                    InjectionFinding(
                        category="out_of_scope_host_mention",
                        pattern=re.escape(host),
                        snippet=host,
                    )
                )

    return InjectionReport(flagged=bool(findings), findings=findings)
