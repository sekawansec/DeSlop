"""Scope and excluded-bug-class checks used during filtering.

Deterministic checks that run before parsing or execution.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config.schema import ProgramConfig
from ..repro.scope import check_scope


@dataclass
class FilterDecision:
    passed: bool
    category: str | None = None
    reason: str = ""


def check_scope_for_report(
    asset: str | None, endpoint: str | None, program: ProgramConfig
) -> FilterDecision:
    if not asset:
        return FilterDecision(False, "out_of_scope", "report does not specify a target asset")
    target = asset
    if endpoint and endpoint.startswith("http"):
        target = endpoint
    decision = check_scope(target, program)
    if decision.allowed:
        return FilterDecision(True)
    return FilterDecision(False, "out_of_scope", decision.reason)


def check_excluded_class(vuln_class: str | None, program: ProgramConfig) -> FilterDecision:
    """Match a report's bug class / CWE against the program's excluded classes."""
    if not vuln_class:
        return FilterDecision(True)
    haystack = vuln_class.strip().lower()
    for excluded in program.excluded_classes:
        for needle in [excluded.id, *excluded.match]:
            if needle and needle.strip().lower() in haystack:
                return FilterDecision(
                    False,
                    "excluded_class",
                    excluded.reason or f"bug class {excluded.id!r} is excluded",
                )
    return FilterDecision(True)
