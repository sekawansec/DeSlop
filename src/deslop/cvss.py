"""Deterministic CVSS v3.1 calculator.

A second opinion alongside the LLM's suggestion. Given a metric vector (or a
partial set of metrics) it computes the base score and severity rating exactly,
following the FIRST CVSS v3.1 specification.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _round_up(value: float) -> float:
    """CVSS 3.1 Roundup: round up to one decimal place."""
    return math.ceil(value * 10) / 10


@dataclass
class CvssResult:
    vector: str
    base_score: float
    severity: str

    def to_dict(self) -> dict:
        return {
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
        }


@dataclass
class CvssMetrics:
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "N"
    I: str = "N"  # noqa: E741 - CVSS metric name (Integrity)
    A: str = "N"

    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
            f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def compute_base(metrics: CvssMetrics) -> CvssResult:
    """Compute the CVSS v3.1 base score exactly per the spec."""
    scope_changed = metrics.S == "C"
    iss = 1 - (
        (1 - CIA[metrics.C]) * (1 - CIA[metrics.I]) * (1 - CIA[metrics.A])
    )
    if scope_changed:  # noqa: SIM108 - keep the spec formula readable
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = (
        8.22
        * AV[metrics.AV]
        * AC[metrics.AC]
        * (PR_CHANGED if scope_changed else PR_UNCHANGED)[metrics.PR]
        * UI[metrics.UI]
    )
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _round_up(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = _round_up(min(impact + exploitability, 10.0))
    return CvssResult(
        vector=metrics.vector(), base_score=score, severity=severity_from_score(score)
    )


_VECTOR_RE = re.compile(
    r"AV:(?P<AV>[NALP])/?.*?"
    r"AC:(?P<AC>[LH])/?.*?"
    r"PR:(?P<PR>[NLH])/?.*?"
    r"UI:(?P<UI>[NR])/?.*?"
    r"S:(?P<S>[UC])/?.*?"
    r"C:(?P<C>[NLH])/?.*?"
    r"I:(?P<I>[NLH])/?.*?"
    r"A:(?P<A>[NLH])",
    re.S,
)


def parse_vector(vector: str) -> CvssMetrics | None:
    m = _VECTOR_RE.search(vector)
    if not m:
        return None
    return CvssMetrics(**m.groupdict())


def compute_from_vector(vector: str) -> CvssResult | None:
    metrics = parse_vector(vector)
    if metrics is None:
        return None
    return compute_base(metrics)


#: Loose keyword -> metric mapping for deriving a provisional vector from text.
#: Order matters: more specific "no interaction"/"without interaction" patterns
#: must be checked before the generic "user interaction".
_KEYWORDS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bnetwork\b", re.I), "AV", "N"),
    (re.compile(r"\badjacent\b", re.I), "AV", "A"),
    (re.compile(r"\blocal\b", re.I), "AV", "L"),
    (re.compile(r"\bphysical\b", re.I), "AV", "P"),
    (re.compile(r"without auth|no auth|unauthenticated", re.I), "PR", "N"),
    (re.compile(r"low privileg|authenticated user", re.I), "PR", "L"),
    (re.compile(r"\badmin\b", re.I), "PR", "H"),
    (re.compile(r"no user interaction|without (user )?interaction|no interaction", re.I), "UI", "N"),
    (re.compile(r"(?<!no )(?<!without )user interaction|victim must|user must click", re.I), "UI", "R"),
    (re.compile(r"account takeover|full compromise|arbitrary code", re.I), "C", "H"),
]


def hints_from_text(text: str) -> dict[str, str]:
    """Metric values the text explicitly suggests (best effort)."""
    hints: dict[str, str] = {}
    for pattern, attr, value in _KEYWORDS:
        if pattern.search(text):
            hints[attr] = value
    return hints


def vector_from_text(text: str) -> CvssMetrics:
    """Derive a provisional metric set from descriptive text (best effort)."""
    return CvssMetrics(**hints_from_text(text))
