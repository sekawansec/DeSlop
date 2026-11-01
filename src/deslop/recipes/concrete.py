"""Concrete recipes for v1 bug classes.

Each recipe wires a deterministic verifier and, where needed, state setup. The
recipe's ``verify`` runs after the executor has produced the request/response
log; values produced by ``setup`` (run tokens, ownership markers, canaries)
arrive via ``setup_data``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from ..config.schema import ProgramConfig
from ..repro.interfaces import ExecutionResult, VerificationResult
from ..repro.substitution import REDIRECT_MARKER_HOST
from .registry import BaseRecipe, SetupResult, register_recipe


@dataclass
class IdorRecipe(BaseRecipe):
    bug_class: str = "idor"
    # Extra ownership markers keyed by owning test-account id. The verifier
    # also reads test_accounts[].owned_markers and an owned canary from the
    # program config itself.
    owner_markers: dict[str, list[str]] = field(default_factory=dict)

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:
        return SetupResult(
            ok=True, detail="default setup", data={"owner_markers": dict(self.owner_markers)}
        )

    def verify(
        self,
        plan,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:  # noqa: ANN001
        from .idor import IdorVerifier

        owner_markers = {k: list(v) for k, v in self.owner_markers.items()}
        for owner, markers in ((setup_data or {}).get("owner_markers") or {}).items():
            owner_markers.setdefault(owner, []).extend(markers)
        return IdorVerifier(owner_markers).verify(plan, execution, program)


@dataclass
class ReflectedXssRecipe(BaseRecipe):
    bug_class: str = "xss_reflected"

    def verify(
        self,
        plan,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:  # noqa: ANN001
        from .xss import ReflectedXssVerifier

        return ReflectedXssVerifier().verify(plan, execution, program)


@dataclass
class StoredXssRecipe(BaseRecipe):
    bug_class: str = "xss_stored"

    def verify(
        self,
        plan,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:  # noqa: ANN001
        from .xss import StoredXssVerifier

        return StoredXssVerifier().verify(plan, execution, program)


@dataclass
class SsrfRecipe(BaseRecipe):
    bug_class: str = "ssrf"
    run_token: str | None = None

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:
        # Generate a unique per-run callback token; it is embedded into the
        # plan's OOB placeholder hosts by the substitution layer and looked up
        # on the listener during verification.
        token = secrets.token_hex(16)
        return SetupResult(ok=True, detail="generated per-run OOB token", data={"run_token": token})

    def verify(
        self,
        plan,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:  # noqa: ANN001
        from .ssrf import SsrfVerifier

        token = (setup_data or {}).get("run_token") or self.run_token
        return SsrfVerifier(run_token=token).verify(plan, execution, program)


@dataclass
class OpenRedirectRecipe(BaseRecipe):
    bug_class: str = "open_redirect"
    marker_host: str = REDIRECT_MARKER_HOST

    def verify(
        self,
        plan,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:  # noqa: ANN001
        from .open_redirect import OpenRedirectVerifier

        return OpenRedirectVerifier(marker_host=self.marker_host).verify(plan, execution, program)


@dataclass
class CommandInjectionRecipe(BaseRecipe):
    bug_class: str = "command_injection"
    proof_pattern: str = r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)"

    def verify(
        self,
        plan,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:  # noqa: ANN001
        from .command_injection import CommandInjectionVerifier

        return CommandInjectionVerifier(self.proof_pattern).verify(plan, execution, program)


def register_default_recipes() -> None:
    register_recipe(IdorRecipe())
    register_recipe(ReflectedXssRecipe())
    register_recipe(StoredXssRecipe())
    register_recipe(SsrfRecipe())
    register_recipe(OpenRedirectRecipe())
    register_recipe(CommandInjectionRecipe())
