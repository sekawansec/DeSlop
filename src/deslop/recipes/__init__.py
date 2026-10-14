"""Recipe / verifier plugin system for proven reproduction.

Adding a new recipe: subclass the verifier logic, return a :class:`Recipe`, and
register it. The core pipeline looks recipes up by bug class; bug classes
without a recipe are routed to ``manual_reproduction_required``.
"""

from .browser import Browser, BrowserObservation, PlaywrightBrowser, get_browser, set_browser
from .concrete import (
    CommandInjectionRecipe,
    IdorRecipe,
    OpenRedirectRecipe,
    ReflectedXssRecipe,
    SsrfRecipe,
    StoredXssRecipe,
    register_default_recipes,
)
from .registry import (
    BaseRecipe,
    Recipe,
    SetupResult,
    all_recipes,
    get_recipe,
    has_recipe,
    register_recipe,
)

__all__ = [
    "BaseRecipe",
    "Browser",
    "BrowserObservation",
    "CommandInjectionRecipe",
    "IdorRecipe",
    "OpenRedirectRecipe",
    "PlaywrightBrowser",
    "Recipe",
    "ReflectedXssRecipe",
    "SetupResult",
    "SsrfRecipe",
    "StoredXssRecipe",
    "all_recipes",
    "get_browser",
    "get_recipe",
    "has_recipe",
    "register_default_recipes",
    "register_recipe",
    "set_browser",
]
