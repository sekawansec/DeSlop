"""Full-pipeline DVWA reproduction test.

Runs a DVWA command-injection report through the whole Pipeline (parse ->
validate -> substitute -> execute -> verify -> route) and asserts it is routed
as "reproduced". Skips if the DVWA target is not running.
"""

from __future__ import annotations

import httpx
import pytest

from deslop.config.schema import LoginConfig, ProgramConfig, ScopeEntry, StagingConfig, TestAccount
from deslop.config.settings import Settings, reset_settings_cache
from deslop.pipeline.orchestrator import Pipeline

DVWA_BASE = "http://127.0.0.1:14000"


def _up() -> bool:
    try:
        return httpx.get(f"{DVWA_BASE}/login.php", timeout=3.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="DVWA target not running")

REPORT = (
    "## Summary\n"
    "Command injection in the DVWA exec module via the ip parameter.\n\n"
    "## Steps to reproduce\n"
    "1. Log in with admin credentials.\n"
    "2. POST the following request.\n\n"
    "```http\n"
    "POST /vulnerabilities/exec/ HTTP/1.1\n"
    "Host: 127.0.0.1:14000\n"
    "Content-Type: application/x-www-form-urlencoded\n\n"
    "ip=127.0.0.1;%20id&Submit=Submit\n"
    "```\n\n"
    "## Actual result\n"
    "The response includes the output of the id command.\n"
)


def _program() -> ProgramConfig:
    host = DVWA_BASE.replace("http://", "")
    return ProgramConfig(
        id="dvwa",
        name="DVWA Lab",
        in_scope=[ScopeEntry(kind="domain", value="127.0.0.1")],
        staging=StagingConfig(
            base_url=DVWA_BASE,
            host_map={"dvwa.lab.test": host},
        ),
        test_accounts=[
            TestAccount(id="admin", role="admin", username="admin", password="password"),
        ],
        login=LoginConfig(
            kind="form", url=f"{DVWA_BASE}/login.php",
            username_field="username", password_field="password",
            extra_fields={"Login": "Login"}, csrf_field="user_token",
            success_indicator="logout.php", session_cookie="PHPSESSID",
        ),
        allowed_egress_hosts=["127.0.0.1"],
    )


def test_pipeline_reproduces_dvwa_command_injection():
    from deslop.recipes.concrete import CommandInjectionRecipe
    from deslop.recipes.registry import register_recipe

    register_recipe(CommandInjectionRecipe())
    reset_settings_cache()
    settings = Settings(
        _env_file=None,
        database_url="sqlite+pysqlite:///:memory:",
        rate_limit_rps=0,
        max_run_seconds=30,
        llm_provider="none",
    )
    program = _program()
    pipeline = Pipeline(program, settings=settings)
    result = pipeline.run(
        title="DVWA command injection",
        body=REPORT,
        asset="127.0.0.1",
        vuln_class="command_injection",
        run_id="dvwa-pipeline",
    )
    assert result.routing.category == "reproduced", result.to_dict()
    assert result.verification.verdict.value == "proven"
    assert "uid=" in result.verification.evidence["marker"]
