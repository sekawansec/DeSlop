import pytest
from fastapi.testclient import TestClient

from deslop.config.loader import ProgramRegistry
from deslop.config.settings import Settings, reset_settings_cache
from deslop.db import Base
from deslop.db.session import reset_engine
from deslop.web.app import create_app
from deslop.web.auth import hash_password


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "web.db"
    monkeypatch.setenv("DESLOP_DATABASE_URL", f"sqlite+pysqlite:///{db}")
    monkeypatch.setenv("DESLOP_CONFIG_DIR", "config/programs")
    monkeypatch.setenv("DESLOP_DASHBOARD_USER", "admin")
    monkeypatch.setenv("DESLOP_DASHBOARD_PASSWORD_HASH", hash_password("secret"))
    monkeypatch.setenv("DESLOP_EMBEDDING_DIM", "16")
    monkeypatch.setenv("DESLOP_LLM_PROVIDER", "none")
    reset_settings_cache()
    reset_engine()

    settings = Settings(_env_file=None)
    from deslop.db.session import get_engine

    Base.metadata.create_all(get_engine())

    app = create_app(settings, ProgramRegistry.from_dir("config/programs"))
    with TestClient(app) as c:
        yield c
    reset_engine()
    reset_settings_cache()


AUTH = ("admin", "secret")


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_index_lists_programs(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "acme-cloud" in r.text or "lab" in r.text


def test_submit_requires_evidence(client):
    r = client.post(
        "/submit",
        data={
            "program_id": "lab",
            "title": "t",
            "asset": "api.lab.test",
            "vuln_class": "idor",
            "body": "steps",
        },
    )
    assert r.status_code == 422


def test_submit_success_returns_report_id_and_status_url(client):
    r = client.post(
        "/submit",
        data={
            "program_id": "lab",
            "title": "IDOR",
            "asset": "api.lab.test",
            "vuln_class": "idor",
            "body": "1. do a thing",
            "raw_http": "GET /api/invoices/1001 HTTP/1.1\nHost: api.lab.test",
        },
    )
    assert r.status_code == 201, r.text
    payload = r.json()
    assert payload["report_id"].startswith("RPT-")
    assert "status_url" in payload


def test_dashboard_requires_auth(client):
    assert client.get("/dashboard").status_code == 401


def test_dashboard_ok_with_auth(client):
    r = client.get("/dashboard", auth=AUTH)
    assert r.status_code == 200
    assert "Triage dashboard" in r.text


def test_unknown_program_rejected(client):
    r = client.post(
        "/submit",
        data={
            "program_id": "nope",
            "title": "t",
            "asset": "x",
            "vuln_class": "idor",
            "body": "y",
            "raw_http": "GET / HTTP/1.1",
        },
    )
    assert r.status_code == 404
