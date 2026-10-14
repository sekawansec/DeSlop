"""Concrete recipes for v1 bug classes.

Each recipe wires a deterministic verifier and, where needed, state setup. The
recipe's ``verify`` runs after the executor has produced the request/response log.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config.schema import ProgramConfig
from ..repro.interfaces import ExecutionResult, VerificationResult
from .registry import BaseRecipe, SetupResult, register_recipe


@dataclass
class IdorRecipe(BaseRecipe):
    bug_class: str = "idor"
    owner_markers: list[str] = field(default_factory=list)

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:
        # State setup is program-specific; the lab recipe overrides this to seed
        # objects and capture ownership markers.
        return SetupResult(ok=True, detail="default setup", data={"markers": self.owner_markers})

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        from .idor import IdorVerifier

        return IdorVerifier(self.owner_markers).verify(plan, execution, program)


@dataclass
class ReflectedXssRecipe(BaseRecipe):
    bug_class: str = "xss_reflected"

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        from .xss import ReflectedXssVerifier

        return ReflectedXssVerifier().verify(plan, execution, program)


@dataclass
class StoredXssRecipe(BaseRecipe):
    bug_class: str = "xss_stored"

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        from .xss import StoredXssVerifier

        return StoredXssVerifier().verify(plan, execution, program)


@dataclass
class SsrfRecipe(BaseRecipe):
    bug_class: str = "ssrf"
    run_token: str | None = None

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        from .ssrf import SsrfVerifier

        return SsrfVerifier(run_token=self.run_token).verify(plan, execution, program)


@dataclass
class OpenRedirectRecipe(BaseRecipe):
    bug_class: str = "open_redirect"
    marker_host: str = "marker.deslop.test"

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        from .open_redirect import OpenRedirectVerifier

        return OpenRedirectVerifier(marker_host=self.marker_host).verify(plan, execution, program)


@dataclass
class CommandInjectionRecipe(BaseRecipe):
    bug_class: str = "command_injection"
    proof_pattern: str = r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)"

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        from .command_injection import CommandInjectionVerifier

        return CommandInjectionVerifier(self.proof_pattern).verify(plan, execution, program)


def register_default_recipes() -> None:
    register_recipe(IdorRecipe())
    register_recipe(ReflectedXssRecipe())
    register_recipe(StoredXssRecipe())
    register_recipe(SsrfRecipe())
    register_recipe(OpenRedirectRecipe())
    register_recipe(CommandInjectionRecipe())
