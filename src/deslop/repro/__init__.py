"""Deterministic reproduction pipeline (validator, substitution, executor).

This package is deliberately free of LLM calls. The LLM only produces the
structured plan elsewhere; everything here is deterministic code that either
approves, blocks, or executes locked steps.
"""

from .executor import WebExecutor, redact
from .interfaces import (
    ExecutionResult,
    Executor,
    StepResult,
    VerificationResult,
    Verifier,
)
from .login import Session, login_account
from .scope import ScopeDecision, check_scope, is_allowed_egress_host
from .steps import (
    ReproPlanModel,
    ReproStep,
    SourceRef,
    StepExpectation,
    StructuredRequest,
)
from .substitution import Substitution, SubstitutionResult, apply_substitutions
from .validator import ValidationIssue, ValidationResult, validate_plan

__all__ = [
    "ExecutionResult",
    "Executor",
    "ReproPlanModel",
    "ReproStep",
    "ScopeDecision",
    "Session",
    "SourceRef",
    "StepExpectation",
    "StepResult",
    "StructuredRequest",
    "Substitution",
    "SubstitutionResult",
    "ValidationIssue",
    "ValidationResult",
    "VerificationResult",
    "Verifier",
    "WebExecutor",
    "apply_substitutions",
    "check_scope",
    "is_allowed_egress_host",
    "login_account",
    "redact",
    "validate_plan",
]
