from pathlib import Path

import pytest
import yaml

from deslop.config import (
    ConfigError,
    ProgramRegistry,
    load_program_file,
    load_programs,
)

MINIMAL = {
    "id": "demo",
    "name": "Demo",
    "staging": {"base_url": "https://staging.demo.test"},
}


def _write(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


def test_load_minimal_program(tmp_path: Path):
    p = _write(tmp_path, "demo.yaml", MINIMAL)
    program = load_program_file(p)
    assert program.id == "demo"
    assert program.staging.base_url == "https://staging.demo.test"
    assert program.status_page.enabled is True


def test_load_example_config_from_repo():
    path = Path(__file__).resolve().parents[1] / "config" / "programs" / "example-acme-cloud.yaml"
    program = load_program_file(path)
    assert program.id == "acme-cloud"
    assert program.staging.host_map["app.acme-cloud.test"] == "staging.acme-cloud.test"
    assert program.bounty_for("high").amount == 2500
    assert program.account_by_role("user", tenant="tenant-one")[0].id == "user_a"
    # two distinct same-role accounts exist
    same_role = program.account_by_role("user", tenant="tenant-one")
    assert len(same_role) == 2
    assert same_role[0].username != same_role[1].username


def test_invalid_program_missing_staging(tmp_path: Path):
    bad = {"id": "x", "name": "X"}
    p = _write(tmp_path, "bad.yaml", bad)
    with pytest.raises(ConfigError):
        load_program_file(p)


def test_invalid_program_id_with_space(tmp_path: Path):
    bad = {**MINIMAL, "id": "has space"}
    p = _write(tmp_path, "bad.yaml", bad)
    with pytest.raises(ConfigError):
        load_program_file(p)


def test_unknown_top_level_key_rejected(tmp_path: Path):
    bad = {**MINIMAL, "surprise": True}
    p = _write(tmp_path, "bad.yaml", bad)
    with pytest.raises(ConfigError):
        load_program_file(p)


def test_load_programs_directory_and_registry(tmp_path: Path):
    _write(tmp_path, "a.yaml", {**MINIMAL, "id": "a"})
    _write(tmp_path, "b.yml", {**MINIMAL, "id": "b"})
    programs = load_programs(tmp_path)
    assert set(programs) == {"a", "b"}

    reg = ProgramRegistry.from_dir(tmp_path)
    assert "a" in reg
    assert reg.ids() == ["a", "b"]
    assert reg.get("a").name == "Demo"
    with pytest.raises(ConfigError):
        reg.get("missing")


def test_duplicate_program_id_rejected(tmp_path: Path):
    _write(tmp_path, "one.yaml", {**MINIMAL, "id": "dup"})
    _write(tmp_path, "two.yaml", {**MINIMAL, "id": "dup"})
    with pytest.raises(ConfigError):
        load_programs(tmp_path)


def test_token_ttl_parsed_from_iso8601(tmp_path: Path):
    data = {
        **MINIMAL,
        "status_page": {"enabled": True, "token_ttl": "P30D"},
    }
    p = _write(tmp_path, "demo.yaml", data)
    program = load_program_file(p)
    assert program.status_page.token_ttl.days == 30


def test_config_error_on_missing_file():
    with pytest.raises(ConfigError):
        load_program_file("does-not-exist.yaml")


def test_scope_value_cannot_be_blank(tmp_path: Path):
    data = {**MINIMAL, "in_scope": [{"kind": "domain", "value": "  "}]}
    p = _write(tmp_path, "demo.yaml", data)
    with pytest.raises(ConfigError):
        load_program_file(p)
