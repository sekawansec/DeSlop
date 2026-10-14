"""Tests for the first-run setup wizard and setup gating."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from deslop.config.loader import ProgramRegistry
from deslop.config.settings import Settings, reset_settings_cache
from deslop.db import Base
from deslop.db.session import get_engine, reset_engine
from deslop.web.app import create_app
from deslop.web.setup_state import is_setup_complete, load_state


def _settings(tmp_path, monkeypatch, *, with_hash=False, setup_file=None):
    monkeypatch.setenv("DESLOP_DATABASE_URL", f"sqlite+pysqlite:///{tmp_path/'w.db'}")
    monkeypatch.setenv("DESLOP_CONFIG_DIR", str(tmp_path / "programs"))
    monkeypatch.setenv("DESLOP_SETUP_STATE_FILE", str(setup_file or (tmp_path / "setup.json")))
    monkeypatch.setenv("DESLOP_BLACKLIST_FILE", str(tmp_path / "bl.json"))
    monkeypatch.setenv("DESLOP_EMBEDDING_DIM", "16")
    if with_hash:
        from deslop.web.auth import hash_password

        monkeypatch.setenv("DESLOP_DASHBOARD_PASSWORD_HASH", hash_password("pw"))
    else:
        monkeypatch.setenv("DESLOP_DASHBOARD_PASSWORD_HASH", "")
    reset_settings_cache()
    reset_engine()
    Base.metadata.create_all(get_engine())
    return Settings(_env_file=None)


@pytest.fixture()
def fresh_client(tmp_path, monkeypatch):
    settings = _settings(tmp_path, monkeypatch)
    (tmp_path / "programs").mkdir(exist_ok=True)
    app = create_app(settings, ProgramRegistry.from_dir(settings.config_dir))
    with TestClient(app) as c:
        yield c
    reset_engine()
    reset_settings_cache()


def test_setup_required_redirects_home(fresh_client):
    r = fresh_client.get("/", follow_redirects=False)
    assert r.status_code == 307
    assert r.headers["location"] == "/setup"


def test_setup_page_renders(fresh_client):
    r = fresh_client.get("/setup")
    assert r.status_code == 200
    assert "Welcome to DeSlop" in r.text


def test_setup_static_exempt(fresh_client):
    # Static assets must load before setup is complete.
    r = fresh_client.get("/static/app.css")
    assert r.status_code == 200
    assert "--accent" in r.text


def test_db_check_endpoint(fresh_client):
    r = fresh_client.get("/setup/db-check")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_complete_setup_creates_config_and_enables_app(tmp_path, monkeypatch):
    settings = _settings(tmp_path, monkeypatch)
    (tmp_path / "programs").mkdir(exist_ok=True)
    app = create_app(settings, ProgramRegistry.from_dir(settings.config_dir))
    with TestClient(app) as c:
        r = c.post(
            "/setup",
            data={
                "admin_user": "admin",
                "admin_password": "supersecret",
                "program_name": "Acme Cloud",
                "program_id": "acme",
                "in_scope": "example.com",
                "staging_base_url": "https://staging.example.com",
                "llm_provider": "none",
                "llm_model": "",
                "oob_base_url": "http://localhost:8080",
                "enable_status_page": "1",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/setup/done"

        # Program config was written and validates.
        cfg = tmp_path / "programs" / "acme.yaml"
        assert cfg.is_file()
        from deslop.config.loader import load_program_file

        program = load_program_file(cfg)
        assert program.id == "acme"
        assert program.name == "Acme Cloud"
        assert program.in_scope[0].value == "example.com"

        # Setup is now complete: home no longer redirects.
        r2 = c.get("/", follow_redirects=False)
        assert r2.status_code == 200

        # The new admin account works against the dashboard.
        b64 = __import__("base64").b64encode(b"admin:supersecret").decode()
        dash = c.get("/dashboard", headers={"Authorization": f"Basic {b64}"})
        assert dash.status_code == 200
    reset_engine()
    reset_settings_cache()


def test_setup_state_persisted(tmp_path, monkeypatch):
    settings = _settings(tmp_path, monkeypatch)
    (tmp_path / "programs").mkdir(exist_ok=True)
    app = create_app(settings, ProgramRegistry.from_dir(settings.config_dir))
    with TestClient(app) as c:
        c.post(
            "/setup",
            data={
                "admin_user": "boss",
                "admin_password": "supersecret",
                "program_name": "P",
                "program_id": "p",
                "in_scope": "p.test",
                "staging_base_url": "https://s.p.test",
                "llm_provider": "none",
                "oob_base_url": "http://oob:8080",
            },
        )
    state = load_state(settings)
    assert state.complete
    assert state.admin_user == "boss"
    assert "p" in state.programs
    reset_engine()
    reset_settings_cache()


def test_is_setup_complete_true_when_hash_set(tmp_path, monkeypatch):
    settings = _settings(tmp_path, monkeypatch, with_hash=True)
    assert is_setup_complete(settings) is True
    reset_engine()
    reset_settings_cache()
