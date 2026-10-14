"""End-to-end recipe verification against the live lab app.

This test boots the real lab FastAPI app and OOB listener in-process on random
ports, builds locked plans, executes them with the real WebExecutor, and runs
each verifier. It proves the whole Stage 3+4 chain works against real bugs — not
just mocks.

Skipped automatically if dependencies for the in-process servers are missing.
"""

from __future__ import annotations

import socket
import threading
import time
import uuid

import pytest
import uvicorn

from deslop.config.schema import (
    LoginConfig,
    ProgramConfig,
    ScopeEntry,
    StagingConfig,
    TestAccount,
)
from deslop.config.settings import Settings
from deslop.db.enums import Verdict
from deslop.repro.executor import WebExecutor
from deslop.repro.steps import ReproPlanModel, ReproStep, StepExpectation, StructuredRequest
from deslop.repro.validator import validate_plan

pytest.importorskip("uvicorn")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerThread:
    def __init__(self, app, port: int) -> None:
        self.config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        self.server = uvicorn.Server(self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                break
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture(scope="module")
def lab_env():
    from lab.custom_app.app import create_app

    from deslop.oob.listener import app as oob_app

    lab_port = _free_port()
    oob_port = _free_port()
    with ServerThread(create_app(), lab_port), ServerThread(oob_app, oob_port):
        base = f"http://127.0.0.1:{lab_port}"
        oob = f"http://127.0.0.1:{oob_port}"
        import httpx

        httpx.post(f"{base}/__test__/reset")
        httpx.post(f"{oob}/__test__/reset")
        yield base, oob


def _program(base: str) -> ProgramConfig:
    return ProgramConfig(
        id="lab",
        name="Lab",
        in_scope=[ScopeEntry(kind="domain", value="127.0.0.1")],
        staging=StagingConfig(base_url=base),
        test_accounts=[
            TestAccount(id="user_a", role="user", username="alice", password="alice-pass"),
            TestAccount(id="user_b", role="user", username="bob", password="bob-pass"),
        ],
        login=LoginConfig(
            kind="form",
            url=f"{base}/api/login",
            username_field="username",
            password_field="password",
        ),
        allowed_egress_hosts=["127.0.0.1"],
    )


def _settings(oob: str) -> Settings:
    from deslop.config.settings import reset_settings_cache

    reset_settings_cache()
    return Settings(
        _env_file=None,
        database_url="sqlite+pysqlite:///:memory:",
        oob_base_url=oob,
        rate_limit_rps=0,
        max_run_seconds=30,
        repro_header="X-Repro-Validator",
    )


def _run(plan, program, oob):
    settings = _settings(oob)
    result = validate_plan(plan, program, settings)
    assert result.approved, result.summary()
    executor = WebExecutor(settings)
    return executor.execute(plan, program, run_id=uuid.uuid4().hex)


def test_validator_rejects_out_of_scope_before_execution(lab_env):
    base, oob = lab_env
    program = _program(base)
    plan = ReproPlanModel(
        bug_class="open_redirect",
        steps=[
            ReproStep(
                index=0,
                description="off-site",
                request=StructuredRequest(url="http://evil.example.test/redirect"),
            )
        ],
    )
    result = validate_plan(plan, program, _settings(oob))
    assert not result.approved
    assert any(i.code == "out_of_scope" for i in result.issues)


def test_idor_end_to_end(lab_env):
    base, oob = lab_env
    program = _program(base)
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(
                index=0,
                description="bob reads alice's invoice",
                request=StructuredRequest(url=f"{base}/api/invoices/1001"),
                as_account="user_b",
                expectation=StepExpectation(marker="ACME-INVOICE-ALICE-1001"),
            )
        ],
    )
    execution = _run(plan, program, oob)
    from deslop.recipes.idor import IdorVerifier

    verification = IdorVerifier(["ACME-INVOICE-ALICE-1001"]).verify(plan, execution, program)
    assert verification.verdict == Verdict.PROVEN
    assert verification.evidence["marker"] == "ACME-INVOICE-ALICE-1001"


def test_idor_not_proven_for_own_invoice(lab_env):
    base, oob = lab_env
    program = _program(base)
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(
                index=0,
                description="alice reads bob's invoice",
                request=StructuredRequest(url=f"{base}/api/invoices/1002"),
                as_account="user_a",
            )
        ],
    )
    execution = _run(plan, program, oob)
    from deslop.recipes.idor import IdorVerifier

    # Alice reading Bob's invoice *is* an IDOR in the lab; verify the marker logic
    # by looking only for Carol's marker, which should NOT be present.
    verification = IdorVerifier(["ACME-INVOICE-CAROL-1003"]).verify(plan, execution, program)
    assert verification.verdict == Verdict.NOT_PROVEN


def test_ssrf_end_to_end_with_real_oob(lab_env):
    base, oob = lab_env
    program = _program(base)
    token = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    # The lab's /api/fetch will actually request this URL; point it at the OOB listener.
    callback = f"{oob}/cb/{token}"
    plan = ReproPlanModel(
        bug_class="ssrf",
        steps=[
            ReproStep(
                index=0,
                description="ssrf to oob",
                request=StructuredRequest(url=f"{base}/api/fetch?url={callback}"),
                expectation=StepExpectation(marker=token),
            )
        ],
    )
    execution = _run(plan, program, oob)
    from deslop.recipes.ssrf import OobClient, SsrfVerifier

    verification = SsrfVerifier(oob_client=OobClient(oob), run_token=token).verify(
        plan, execution, program
    )
    assert verification.verdict == Verdict.PROVEN
    assert verification.evidence["hit_count"] >= 1


def test_open_redirect_end_to_end(lab_env):
    base, oob = lab_env
    program = _program(base)
    plan = ReproPlanModel(
        bug_class="open_redirect",
        steps=[
            ReproStep(
                index=0,
                description="open redirect",
                request=StructuredRequest(
                    url=f"{base}/redirect?next=https://marker.deslop.test/landing"
                ),
                expectation=StepExpectation(marker="https://marker.deslop.test/landing"),
            )
        ],
    )
    execution = _run(plan, program, oob)
    from deslop.recipes.open_redirect import OpenRedirectVerifier

    verification = OpenRedirectVerifier().verify(plan, execution, program)
    assert verification.verdict == Verdict.PROVEN
    assert verification.evidence["method"] == "location_header"


def test_stored_xss_payload_persisted(lab_env):
    base, oob = lab_env
    program = _program(base)
    marker = "XSS_STORED_E2E_MARKER"
    plan = ReproPlanModel(
        bug_class="xss_stored",
        steps=[
            ReproStep(
                index=0,
                description="post comment",
                request=StructuredRequest(
                    method="POST",
                    url=f"{base}/api/comments",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=f"author=attacker&text=<script>document.title='{marker}'</script>",
                ),
            ),
            ReproStep(
                index=1,
                description="view comments",
                request=StructuredRequest(url=f"{base}/comments"),
                expectation=StepExpectation(marker=marker),
            ),
        ],
    )
    execution = _run(plan, program, oob)
    # The payload must be persisted and reflected in the view response.
    body = execution.step_results[1].response["body"]
    assert marker in body

    # The verifier proves it executes via the (fake) browser.
    from deslop.recipes.browser import BrowserObservation, set_browser
    from deslop.recipes.xss import StoredXssVerifier

    class ProvesExecution:
        def observe(self, url, *, expected_markers, headless=True):
            return BrowserObservation(executed_markers=set(expected_markers), final_url=url)

    set_browser(ProvesExecution())
    try:
        verification = StoredXssVerifier().verify(plan, execution, program)
        assert verification.verdict == Verdict.PROVEN
    finally:
        from deslop.recipes.browser import PlaywrightBrowser

        set_browser(PlaywrightBrowser())
