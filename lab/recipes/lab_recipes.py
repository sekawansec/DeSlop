"""Lab recipes: concrete recipes wired to the intentionally vulnerable lab app.

These provide real state setup (reset the lab, capture ownership markers) and
real verifier parameters (the lab's marker domain, the OOB run token).
"""

from __future__ import annotations

from dataclasses import dataclass

from deslop.config.schema import ProgramConfig
from deslop.recipes.concrete import (
    IdorRecipe,
    OpenRedirectRecipe,
    ReflectedXssRecipe,
    SsrfRecipe,
    StoredXssRecipe,
)
from deslop.recipes.registry import SetupResult, register_recipe


@dataclass
class LabSsrfRecipe(SsrfRecipe):
    bug_class: str = "ssrf"

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:
        result = super().setup(program, run_id=run_id)
        result.detail = "lab ssrf setup"
        return result


def register_lab_recipes() -> None:
    register_recipe(IdorRecipe())
    register_recipe(LabSsrfRecipe())
    register_recipe(ReflectedXssRecipe())
    register_recipe(StoredXssRecipe())
    register_recipe(OpenRedirectRecipe())
