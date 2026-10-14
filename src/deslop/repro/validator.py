"""Deterministic policy validator.

This module contains **no LLM calls**. It inspects a locked
:class:`ReproPlanModel` and either approves it or blocks it. Every step is
checked against program policy before any network activity happens.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config.schema import ProgramConfig
from ..config.settings import Settings, get_settings
from .scope import check_scope
from .steps import ReproPlanModel, ReproStep

#: Methods that are never executed automatically.
DESTRUCTIVE_METHODS = frozenset({"DELETE"})

#: Path fragments that commonly denote destructive or administrative actions.
DESTRUCTIVE_PATTERNS = (
    "/delete",
    "/remove",
    "/destroy",
    "/drop",
    "/purge",
    "/shutdown",
    "/reboot",
    "/reset-db",
    "/wipe",
)


@dataclass
class ValidationIssue:
    step_index: int | None
    code: str
    message: str


@dataclass
class ValidationResult:
    approved: bool
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def blocking_issues(self) -> list[ValidationIssue]:
        return self.issues

    def summary(self) -> str:
        if self.approved:
            return "approved"
        return "; ".join(f"[step {i.step_index}] {i.code}: {i.message}" for i in self.issues)


def _looks_destructive(step: ReproStep) -> str | None:
    method = step.request.method.upper()
    if method in DESTRUCTIVE_METHODS:
        return f"method {method} is destructive and is never run automatically"
    path = step.request.url.lower()
    for pat in DESTRUCTIVE_PATTERNS:
        if pat in path:
            return f"URL contains destructive pattern {pat!r}"
    return None


def validate_plan(
    plan: ReproPlanModel,
    program: ProgramConfig,
    settings: Settings | None = None,
) -> ValidationResult:
    """Validate every step; return an approved/blocked decision with reasons.

    All issues are collected so triagers can see everything at once.
    """
    settings = settings or get_settings()
    issues: list[ValidationIssue] = []

    max_steps = program.max_requests_per_run or settings.max_requests_per_run
    if len(plan.steps) == 0:
        issues.append(ValidationIssue(None, "empty_plan", "plan has no steps"))
    if len(plan.steps) > max_steps:
        issues.append(
            ValidationIssue(
                None,
                "too_many_steps",
                f"plan has {len(plan.steps)} steps, limit is {max_steps}",
            )
        )

    seen_indexes: set[int] = set()
    for step in plan.steps:
        if step.index in seen_indexes:
            issues.append(ValidationIssue(step.index, "duplicate_step", "duplicate step index"))
        seen_indexes.add(step.index)

        # Scope: the request target must be in scope for the program.
        decision = check_scope(step.request.url, program)
        if not decision.allowed:
            issues.append(
                ValidationIssue(
                    step.index,
                    "out_of_scope",
                    f"target not in scope: {decision.reason}",
                )
            )

        # Account references must exist in the program config.
        if step.as_account and step.as_account not in {a.id for a in program.test_accounts}:
            issues.append(
                ValidationIssue(
                    step.index,
                    "unknown_account",
                    f"account {step.as_account!r} is not defined in the program config",
                )
            )

        # Destructive actions are blocked.
        destructive = _looks_destructive(step)
        if destructive:
            issues.append(ValidationIssue(step.index, "destructive", destructive))

        # Empty/missing URL.
        if not step.request.url.strip():
            issues.append(ValidationIssue(step.index, "empty_url", "step has no target URL"))

    return ValidationResult(approved=not issues, issues=issues)
