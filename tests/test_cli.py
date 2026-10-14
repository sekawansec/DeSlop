import json

from deslop.cli import main


def test_config_list(capsys, tmp_path):
    import yaml

    (tmp_path / "demo.yaml").write_text(
        yaml.safe_dump({"id": "demo", "name": "Demo", "staging": {"base_url": "https://s.test"}}),
        encoding="utf-8",
    )
    rc = main(["--config-dir", str(tmp_path), "config", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "demo: Demo" in out


def test_config_show(capsys, tmp_path):
    import yaml

    (tmp_path / "demo.yaml").write_text(
        yaml.safe_dump({"id": "demo", "name": "Demo", "staging": {"base_url": "https://s.test"}}),
        encoding="utf-8",
    )
    rc = main(["--config-dir", str(tmp_path), "config", "show", "demo"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["id"] == "demo"


def test_config_show_unknown_program(capsys, tmp_path):
    rc = main(["--config-dir", str(tmp_path), "config", "show", "nope"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error:" in err


def test_version(capsys):
    rc = main(["--version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "deslop" in out
