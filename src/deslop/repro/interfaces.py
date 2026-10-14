"""Executor plugin interface.

The core pipeline (validator, routing, evidence) is executor-agnostic. v1 ships
only the web executor; other executors (Android on-device, desktop) can be added
later without touching the core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from .steps import ReproPlanModel


@dataclass
class StepResult:
    index: int
    ok: bool
    request: dict[str, Any]
    response: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "ok": self.ok,
            "request": self.request,
            "response": self.response,
            "error": self.error,
        }


@dataclass
class ExecutionResult:
    run_id: str
    bug_class: str
    step_results: list[StepResult] = field(default_factory=list)
    failed_step_index: int | None = None
    duration_ms: int = 0
    error: str | None = None

    @property
    def completed(self) -> bool:
        return self.failed_step_index is None and self.error is None


@dataclass
class VerificationResult:
    verdict: Verdict
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@runtime_checkable
class Executor(Protocol):
    """Runs a validated, substituted plan and returns raw execution results."""

    name: str

    def execute(
        self, plan: ReproPlanModel, program: ProgramConfig, *, run_id: str
    ) -> ExecutionResult: ...


@runtime_checkable
class Verifier(Protocol):
    """Decides, from technical evidence, whether a bug is proven."""

    bug_class: str

    def verify(
        self, plan: ReproPlanModel, execution: ExecutionResult, program: ProgramConfig
    ) -> VerificationResult: ...
