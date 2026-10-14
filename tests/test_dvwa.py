"""DVWA integration test: prove DeSlop reproduces DVWA bugs end to end.

Requires the DVWA target from lab/docker-compose.yml to be reachable at
http://127.0.0.1:14000. Skips if it is not running.
"""

from __future__ import annotations

import httpx
import pytest

from deslop.config.schema import LoginConfig, ProgramConfig, ScopeEntry, StagingConfig, TestAccount
from deslop.config.settings import Settings, reset_settings_cache
from deslop.db.enums import Verdict
from deslop.repro.executor import WebExecutor
from deslop.repro.steps import ReproPlanModel, ReproStep, StepExpectation, StructuredRequest
from deslop.repro.validator import validate_plan

DVWA_BASE = "http://127.0.0.1:14000"


def _dvwa_available() -> bool:
    try:
        r = httpx.get(f"{DVWA_BASE}/login.php", timeout=3.0)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _dvwa_available(), reason="DVWA target not running")


def _program() -> ProgramConfig:
    return ProgramConfig(
        id="dvwa",
        name="DVWA Lab",
        in_scope=[ScopeEntry(kind="domain", value="127.0.0.1")],
        staging=StagingConfig(base_url=DVWA_BASE),
        test_accounts=[
            TestAccount(id="admin", role="admin", username="admin", password="password"),
        ],
        login=LoginConfig(
            kind="form",
            url=f"{DVWA_BASE}/login.php",
            username_field="username",
            password_field="password",
            extra_fields={"Login": "Login"},
            csrf_field="user_token",
            success_indicator="logout.php",
            session_cookie="PHPSESSID",
        ),
        allowed_egress_hosts=["127.0.0.1"],
    )


def _settings() -> Settings:
    reset_settings_cache()
    return Settings(
        _env_file=None,
        database_url="sqlite+pysqlite:///:memory:",
        rate_limit_rps=0,
        max_run_seconds=30,
        llm_provider="none",
    )


def test_dvwa_login_with_csrf():
    from deslop.repro.login import login_account

    program = _program()
    session = login_account(program.test_accounts[0], program.login)
    assert session.cookies, "expected a session cookie (PHPSESSID)"
    assert any("PHPSESSID" in k or k == "PHPSESSID" for k in session.cookies)


def test_dvwa_command_injection_proven():
    from deslop.recipes.command_injection import CommandInjectionVerifier

    program = _program()
    settings = _settings()
    plan = ReproPlanModel(
        bug_class="command_injection",
        steps=[
            ReproStep(
                index=0,
                description="command injection via ip",
                request=StructuredRequest(
                    method="POST",
                    url=f"{DVWA_BASE}/vulnerabilities/exec/",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="ip=127.0.0.1;%20id&Submit=Submit",
                ),
                as_account="admin",
                expectation=StepExpectation(marker="uid="),
            )
        ],
    )
    assert validate_plan(plan, program, settings).approved
    execution = WebExecutor(settings).execute(plan, program, run_id="dvwa-ci")
    result = CommandInjectionVerifier().verify(plan, execution, program)
    assert result.verdict == Verdict.PROVEN, result.evidence
    assert "uid=" in result.evidence["marker"]


def test_dvwa_reflected_xss_reflected():
    """The XSS payload must be reflected unescaped (browser execution is the
    verifier's job; here we confirm the preconditions hold)."""
    program = _program()
    settings = _settings()
    payload = "<script>document.title='DESLOP_DVWA_XSS_MARKER'</script>"
    plan = ReproPlanModel(
        bug_class="xss_reflected",
        steps=[
            ReproStep(
                index=0,
                description="reflected xss in name",
                request=StructuredRequest(
                    method="GET",
                    url=f"{DVWA_BASE}/vulnerabilities/xss_r/?name={payload}",
                ),
                as_account="admin",
                expectation=StepExpectation(marker="DESLOP_DVWA_XSS_MARKER"),
            )
        ],
    )
    execution = WebExecutor(settings).execute(plan, program, run_id="dvwa-xss")
    body = execution.step_results[0].response["body"]
    assert payload in body
