"""Recipe plugin system.

A *recipe* bundles the three things needed to prove one bug class:

1. state setup  — bring the staging target into a known state (call the reset
   endpoint, seed an object owned by an account, ...),
2. execution      — provided by an executor (v1: the web executor),
3. verification   — a deterministic :class:`Verifier` that reads technical
   evidence and returns a verdict.

The core pipeline never hardcodes bug classes; it looks them up here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..config.schema import ProgramConfig
from ..repro.interfaces import ExecutionResult, VerificationResult, Verifier
from ..repro.steps import ReproPlanModel


@dataclass
class SetupResult:
    ok: bool
    detail: str = ""
    data: dict = field(default_factory=dict)


@runtime_checkable
class Recipe(Protocol):
    bug_class: str
    verifier: Verifier

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult: ...

    def verify(
        self,
        plan: ReproPlanModel,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult: ...


_REGISTRY: dict[str, Recipe] = {}


def register_recipe(recipe: Recipe) -> Recipe:
    _REGISTRY[recipe.bug_class] = recipe
    return recipe


def get_recipe(bug_class: str) -> Recipe | None:
    return _REGISTRY.get(bug_class)


def all_recipes() -> dict[str, Recipe]:
    return dict(_REGISTRY)


def has_recipe(bug_class: str) -> bool:
    return bug_class in _REGISTRY


@dataclass
class BaseRecipe:
    """Shared plumbing for concrete recipes."""

    bug_class: str = ""
    verifier: Verifier | None = None

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:  # noqa: D401
        return SetupResult(ok=True, detail="no setup required")

    def verify(
        self,
        plan: ReproPlanModel,
        execution: ExecutionResult,
        program: ProgramConfig,
        *,
        setup_data: dict | None = None,
    ) -> VerificationResult:
        if self.verifier is None:  # pragma: no cover - misconfiguration
            raise RuntimeError(f"recipe {self.bug_class!r} has no verifier")
        return self.verifier.verify(plan, execution, program)
