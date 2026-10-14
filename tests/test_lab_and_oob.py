import pytest
from fastapi.testclient import TestClient
from lab.custom_app.app import create_app

from deslop.oob.listener import app as oob_app


@pytest.fixture()
def lab():
    app = create_app()
    with TestClient(app) as client:
        client.post("/__test__/reset")
        yield client
        client.post("/__test__/reset")


def _login(client: TestClient, username: str, password: str) -> None:
    r = client.post("/api/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text


def test_healthz(lab):
    assert lab.get("/healthz").json()["status"] == "ok"


def test_login_and_me(lab):
    _login(lab, "alice", "alice-pass")
    me = lab.get("/api/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_login_bad_credentials(lab):
    r = lab.post("/api/login", data={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_idor_bob_can_read_alices_invoice(lab):
    _login(lab, "bob", "bob-pass")
    r = lab.get("/api/invoices/1001")
    assert r.status_code == 200
    assert r.json()["owner"] == "alice"
    assert r.json()["secret"] == "ACME-INVOICE-ALICE-1001"


def test_invoice_list_is_scoped_to_owner(lab):
    _login(lab, "bob", "bob-pass")
    r = lab.get("/api/invoices")
    owners = {inv["owner"] for inv in r.json()["invoices"]}
    assert owners == {"bob"}


def test_invoices_require_auth(lab):
    assert lab.get("/api/invoices/1001").status_code == 401


def test_reflected_xss_is_unescaped(lab):
    payload = "<script>document.title='XSS_REFLECTED_MARKER'</script>"
    r = lab.get("/search", params={"q": payload})
    assert r.status_code == 200
    assert payload in r.text


def test_stored_xss_persists_and_renders(lab):
    payload = "<script>document.title='XSS_STORED_MARKER'</script>"
    lab.post("/api/comments", data={"author": "attacker", "text": payload})
    r = lab.get("/comments")
    assert payload in r.text


def test_ssrf_fetch_hits_oob(monkeypatch):
    # Point the lab app's httpx.get at the local OOB listener.
    hits: list[str] = []

    class FakeResp:
        status_code = 200
        text = "ok"

    def fake_get(url, **kwargs):
        hits.append(url)
        return FakeResp()

    monkeypatch.setattr("lab.custom_app.app.httpx.get", fake_get)
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/fetch", params={"url": "http://evil.test/cb/token123"})
    assert r.status_code == 200
    assert any("token123" in h for h in hits)


def test_open_redirect_returns_302_to_marker(lab):
    r = lab.get("/redirect", params={"next": "https://marker.deslop.test/landing"}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "https://marker.deslop.test/landing"


def test_oob_listener_records_callback():
    with TestClient(oob_app) as client:
        client.post("/__test__/reset")
        assert client.get("/healthz").json()["status"] == "ok"
        client.get("/cb/run-token-1")
        client.get("/cb/run-token-1")
        client.get("/cb/other-token")
        hits = client.get("/hits/run-token-1").json()
        assert hits["count"] == 2
        all_hits = client.get("/hits").json()["hits"]
        assert len(all_hits) == 3
        client.post("/__test__/reset")
        assert client.get("/hits").json()["hits"] == []
