"""Tests for CSRF-aware automated login and offline marker extraction."""

from __future__ import annotations

import httpx

from deslop.config.schema import LoginConfig, TestAccount
from deslop.config.settings import Settings, reset_settings_cache
from deslop.llm.client import LLMClient
from deslop.parser.step_parser import StepParser, parse_from_raw_http
from deslop.repro.login import login_account


def test_csrf_login_fetches_and_submits_token():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                text='<form><input name="user_token" value="tok-123"><input name="username"></form>',
                headers={"set-cookie": "PHPSESSID=abc; Path=/"},
            )
        # POST
        body = request.content.decode()
        seen["body"] = body
        return httpx.Response(
            200, text="<a href='logout.php'>Logout</a>", headers={"set-cookie": "PHPSESSID=abc; Path=/"}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    login = LoginConfig(
        kind="form",
        url="http://target/login.php",
        username_field="username",
        password_field="password",
        csrf_field="user_token",
        success_indicator="logout.php",
        session_cookie="PHPSESSID",
    )
    account = TestAccount(id="admin", role="admin", username="admin", password="password")
    session = login_account(account, login, client=client)
    assert "user_token=tok-123" in seen["body"]
    assert "username=admin" in seen["body"]
    assert session.cookies.get("PHPSESSID") == "abc"


def test_login_without_csrf_field_skips_token():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            seen["body"] = request.content.decode()
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    login = LoginConfig(kind="form", url="http://target/login", username_field="u", password_field="p")
    account = TestAccount(id="a", role="user", username="alice", password="pw")
    login_account(account, login, client=client)
    assert "user_token" not in seen["body"]


def test_offline_parser_extracts_post_body():
    report = (
        "Command injection.\n\n```http\n"
        "POST /vulnerabilities/exec/ HTTP/1.1\n"
        "Host: 127.0.0.1:14000\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "ip=127.0.0.1;%20id&Submit=Submit\n```\n"
    )
    outcome = parse_from_raw_http(report)
    assert outcome is not None
    step = outcome.plan.steps[0]
    assert step.request.method == "POST"
    assert step.request.body == "ip=127.0.0.1;%20id&Submit=Submit"
    assert step.request.headers.get("Content-Type") == "application/x-www-form-urlencoded"


def test_offline_parser_extracts_xss_marker():
    report = (
        "Reflected XSS.\n\n```http\n"
        "GET /vulnerabilities/xss_r/?name=<script>document.title='DESLOP_DVWA_XSS_MARKER'</script>"
        " HTTP/1.1\nHost: 127.0.0.1:14000\n```\n"
    )
    outcome = parse_from_raw_http(report)
    assert outcome is not None
    assert outcome.plan.bug_class == "xss_reflected"
    assert outcome.plan.steps[0].expectation is not None
    assert outcome.plan.steps[0].expectation.marker == "DESLOP_DVWA_XSS_MARKER"


def test_command_injection_bug_class_recognised():
    reset_settings_cache()
    settings = Settings(_env_file=None, llm_provider="none")
    parser = StepParser(client=LLMClient(settings=settings), settings=settings)
    outcome = parser.parse(
        "OS command injection in the ping field.\n\n```http\n"
        "POST /exec HTTP/1.1\nHost: t\n\nip=1;id\n```\n"
    )
    assert outcome.ok
    assert outcome.plan.bug_class == "command_injection"
