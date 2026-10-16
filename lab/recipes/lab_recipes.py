"""Lab recipes: concrete recipes wired to the intentionally vulnerable lab app.

These provide real state setup (reset the lab, capture ownership markers) and
real verifier parameters (the lab's marker domain, the OOB run token).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from deslop.config.schema import ProgramConfig
from deslop.recipes.concrete import (
    IdorRecipe,
    OpenRedirectRecipe,
    ReflectedXssRecipe,
    SsrfRecipe,
    StoredXssRecipe,
)
from deslop.recipes.registry import SetupResult, register_recipe

#: Ownership markers present in the lab app's invoice data. These are what the
#: IDOR verifier looks for in a response returned to a different account.
LAB_OWNER_MARKERS = [
    "ACME-INVOICE-ALICE-1001",
    "ACME-INVOICE-BOB-1002",
    "ACME-INVOICE-CAROL-1003",
]


@dataclass
class LabIdorRecipe(IdorRecipe):
    bug_class: str = "idor"
    owner_markers: list[str] = field(default_factory=lambda: list(LAB_OWNER_MARKERS))

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:
        result = super().setup(program, run_id=run_id)
        result.detail = "lab idor setup"
        return result


@dataclass
class LabSsrfRecipe(SsrfRecipe):
    bug_class: str = "ssrf"

    def setup(self, program: ProgramConfig, *, run_id: str) -> SetupResult:
        result = super().setup(program, run_id=run_id)
        result.detail = "lab ssrf setup"
        return result


def register_lab_recipes() -> None:
    register_recipe(LabIdorRecipe())
    register_recipe(LabSsrfRecipe())
    register_recipe(ReflectedXssRecipe())
    register_recipe(StoredXssRecipe())
    register_recipe(OpenRedirectRecipe())
