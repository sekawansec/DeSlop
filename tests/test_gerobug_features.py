"""Tests for the Gerobug-inspired features: init, CVSS, blacklist, roles, notify."""

from __future__ import annotations

import json

import pytest

from deslop.config.settings import Settings
from deslop.cvss import (
    CvssMetrics,
    compute_base,
    compute_from_vector,
    parse_vector,
    severity_from_score,
    vector_from_text,
)
from deslop.install import generate_env, write_env


# ----------------------------------------------------------------- CVSS
def test_cvss_known_vector_critical():
    # Classic critical RCE vector, score 9.8.
    result = compute_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result is not None
    assert result.base_score == 9.8
    assert result.severity == "critical"


def test_cvss_known_vector_medium():
    # AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N => 4.3
    result = compute_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N")
    assert result is not None
    assert result.base_score == 4.3
    assert result.severity == "medium"


def test_cvss_scope_changed():
    # S:C example: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N => 6.1 (medium).
    result = compute_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert result is not None
    assert result.base_score == 6.1
    assert result.severity == "medium"


def test_cvss_zero_impact_is_zero():
    result = compute_base(CvssMetrics())  # all N
    assert result.base_score == 0.0
    assert result.severity == "none"


def test_cvss_parse_invalid_returns_none():
    assert parse_vector("not a vector") is None
    assert compute_from_vector("garbage") is None


def test_cvss_severity_bands():
    assert severity_from_score(0.0) == "none"
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(6.9) == "medium"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(9.0) == "critical"


def test_cvss_from_text_hints():
    metrics = vector_from_text("Unauthenticated network account takeover, no user interaction")
    assert metrics.AV == "N"
    assert metrics.PR == "N"
    assert metrics.UI == "N"


def test_pipeline_cvss_bias_for_command_injection():
    """A proven command injection must not score 0 even with terse prose."""
    from deslop.cvss import compute_base, vector_from_text
    from deslop.pipeline.orchestrator import _suggest_cvss

    payload = _suggest_cvss("the response contains id output", "command_injection", None)
    assert payload is not None
    assert payload["base_score"] >= 9.0
    assert payload["severity"] == "critical"
    # Sanity: the heuristic alone would have been low.
    assert compute_base(vector_from_text("the response contains id output")).base_score < 9.0


def test_pipeline_cvss_bias_for_idor():
    from deslop.pipeline.orchestrator import _suggest_cvss

    payload = _suggest_cvss("read another user's invoice", "idor", None)
    assert payload is not None
    assert payload["severity"] in {"medium", "high", "critical"}


# ----------------------------------------------------------------- init
def test_generate_env_contains_secrets_and_password():
    contents, password = generate_env(dashboard_password="s3cret", llm_provider="none")
    assert password == "s3cret"
    assert "DESLOP_SECRET_KEY=" in contents
    assert "DESLOP_DASHBOARD_PASSWORD_HASH=" in contents
    # The plaintext password must not appear in the file.
    assert "s3cret" not in contents
    assert "pbkdf2_sha256" in contents


def test_write_env_refuses_overwrite(tmp_path):
    p = tmp_path / ".env"
    result = write_env(p, dashboard_password="x")
    assert result.created
    again = write_env(p, dashboard_password="y")
    assert not again.created
    assert "already exists" in again.notes[0]


def test_write_env_force_overwrites(tmp_path):
    p = tmp_path / ".env"
    write_env(p, dashboard_password="x")
    again = write_env(p, force=True, dashboard_password="z")
    assert again.created


def test_generated_env_is_parseable_by_settings(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    write_env(p, dashboard_password="pw", llm_provider="none")
    # Load it through Settings to prove it is well-formed.
    s = Settings(_env_file=str(p))
    assert s.dashboard_user == "admin"
    assert s.llm_provider == "none"
    assert s.dashboard_password_hash


# ----------------------------------------------------------------- blacklist
def test_blacklist_add_check_remove(tmp_path):
    from deslop.intake.abuse import Blacklist

    bl = Blacklist.load(tmp_path / "bl.json")
    assert bl.is_blocked("spammer@evil.test") is None
    bl.add("spammer@evil.test", "email", reason="spam")
    assert bl.is_blocked("spammer@evil.test") is not None
    # Case-insensitive.
    assert bl.is_blocked("SPAMMER@EVIL.TEST") is not None
    assert bl.remove("spammer@evil.test")
    assert bl.is_blocked("spammer@evil.test") is None


def test_blacklist_temporary_expires(tmp_path):
    from deslop.intake.abuse import Blacklist

    bl = Blacklist.load(tmp_path / "bl.json")
    bl.add("1.2.3.4", "ip", ttl_seconds=-1)  # already expired
    assert bl.is_blocked("1.2.3.4") is None


def test_blacklist_persists(tmp_path):
    from deslop.intake.abuse import Blacklist

    path = tmp_path / "bl.json"
    bl = Blacklist.load(path)
    bl.add("bad@actor.test", "email", reason="abuse")
    reloaded = Blacklist.load(path)
    assert reloaded.is_blocked("bad@actor.test") is not None
    assert json.loads(path.read_text())[0]["value"] == "bad@actor.test"


def test_intake_limiter_blocks_after_limit():
    from deslop.intake.abuse import IntakeLimiter

    lim = IntakeLimiter(limit=2, window=60.0)
    assert lim.allow("1.1.1.1")
    assert lim.allow("1.1.1.1")
    assert not lim.allow("1.1.1.1")
    assert lim.allow("2.2.2.2")  # different IP unaffected


# ----------------------------------------------------------------- auth roles
def test_role_from_users_json():
    from deslop.web.auth import ROLE_READONLY, ROLE_TRIAGER, hash_password

    settings = Settings(
        _env_file=None,
        dashboard_user="admin",
        dashboard_password_hash=hash_password("adminpw"),
        dashboard_users_json=json.dumps(
            [
                {"username": "t1", "password_hash": hash_password("t1pw"), "role": "triager"},
                {"username": "ro", "password_hash": hash_password("ropw"), "role": "readonly"},
            ]
        ),
    )
    from fastapi.security import HTTPBasicCredentials

    from deslop.web.auth import authenticate

    admin = authenticate(HTTPBasicCredentials(username="admin", password="adminpw"), settings)
    assert admin.role == "admin" and admin.can_act
    triager = authenticate(HTTPBasicCredentials(username="t1", password="t1pw"), settings)
    assert triager.role == ROLE_TRIAGER and triager.can_act
    readonly = authenticate(HTTPBasicCredentials(username="ro", password="ropw"), settings)
    assert readonly.role == ROLE_READONLY and not readonly.can_act


def test_wrong_password_rejected():
    from fastapi import HTTPException
    from fastapi.security import HTTPBasicCredentials

    from deslop.web.auth import authenticate, hash_password

    settings = Settings(
        _env_file=None, dashboard_user="admin", dashboard_password_hash=hash_password("right")
    )
    with pytest.raises(HTTPException):
        authenticate(HTTPBasicCredentials(username="admin", password="wrong"), settings)


# ----------------------------------------------------------------- notify
def test_notifier_disabled_by_default():
    from deslop.notify import get_notifier

    notifier = get_notifier(Settings(_env_file=None))
    assert not notifier.enabled
    assert notifier.notify("hello") == []


def test_notifier_sends_slack(monkeypatch):
    import httpx

    from deslop.notify import Notifier

    sent: dict = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        sent["url"] = url
        sent["json"] = json
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr("deslop.notify.httpx.post", fake_post)
    settings = Settings(
        _env_file=None,
        notify_enabled=True,
        slack_webhook_url="https://hooks.slack.test/abc",
    )
    used = Notifier(settings).notify("new report", report_id="RPT-1")
    assert used == ["slack"]
    assert "new report" in sent["json"]["text"]


def test_notifier_telegram(monkeypatch):
    import httpx

    from deslop.notify import Notifier

    sent: dict = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        sent["url"] = url
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr("deslop.notify.httpx.post", fake_post)
    settings = Settings(
        _env_file=None,
        notify_enabled=True,
        telegram_bot_token="tok",
        telegram_chat_id="123",
    )
    used = Notifier(settings).notify("hi")
    assert used == ["telegram"]
    assert "tok" in sent["url"]
