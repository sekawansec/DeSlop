"""Recipe registration for the CLI and the demo.

The lab and DVWA recipes live in the repository's ``lab/`` directory, outside
the installed package, so they can only be imported from a checkout.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from .concrete import register_default_recipes

_LAB_RECIPES = {
    "lab": ("lab.recipes.lab_recipes", "register_lab_recipes"),
    "dvwa": ("lab.recipes.dvwa_recipes", "register_dvwa_recipes"),
}


def register_recipes_for(program_id: str) -> None:
    """Register the built-in recipes plus any lab recipes for ``program_id``.

    Raises ``ImportError`` with an actionable message if the lab recipes are
    needed but cannot be imported, instead of silently running without them.
    """
    register_default_recipes()
    target = _LAB_RECIPES.get(program_id)
    if target is None:
        return
    module, func = target
    cwd = Path.cwd()
    if (cwd / "lab").is_dir() and str(cwd) not in sys.path:
        sys.path.insert(0, str(cwd))
    try:
        getattr(importlib.import_module(module), func)()
    except ImportError as exc:
        raise ImportError(
            f"program {program_id!r} needs the recipes in the repository's lab/ "
            f"directory ({exc}); run this command from the repository root"
        ) from exc
