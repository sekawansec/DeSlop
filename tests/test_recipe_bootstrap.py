import importlib

import pytest

from deslop.cli import main
from deslop.recipes import bootstrap
from deslop.recipes.registry import get_recipe


def test_unknown_program_gets_only_default_recipes():
    bootstrap.register_recipes_for("some-customer-program")
    for bug_class in ("idor", "xss_reflected", "ssrf", "open_redirect", "command_injection"):
        assert get_recipe(bug_class) is not None


def test_lab_program_registers_lab_recipes():
    bootstrap.register_recipes_for("lab")
    assert type(get_recipe("ssrf")).__name__ == "LabSsrfRecipe"


def test_missing_lab_package_is_an_error_not_a_silent_skip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def boom(name, *args, **kwargs):
        raise ImportError(f"No module named {name!r}")

    monkeypatch.setattr(importlib, "import_module", boom)
    with pytest.raises(ImportError, match="repository root"):
        bootstrap.register_recipes_for("lab")


def test_cli_eval_reports_missing_lab_recipes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def boom(name, *args, **kwargs):
        raise ImportError(f"No module named {name!r}")

    monkeypatch.setattr(importlib, "import_module", boom)
    program = tmp_path / "lab.yaml"
    program.write_text(
        "id: lab\nname: Lab\nin_scope: [{kind: domain, value: lab.test}]\n"
        "staging: {base_url: 'http://lab.test'}\n",
        encoding="utf-8",
    )
    rc = main(["--config-dir", str(tmp_path), "eval", "lab", "--per", "1"])
    assert rc == 2
    assert "repository root" in capsys.readouterr().err
