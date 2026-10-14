"""Eval harness tests, including the zero-false-reproduced safety target."""

from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from deslop.config.schema import (
    ExcludedClass,
    LoginConfig,
    ProgramConfig,
    ScopeEntry,
    StagingConfig,
    TestAccount,
)
from deslop.config.settings import Settings, reset_settings_cache

pytest.importorskip("uvicorn")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerThread:
    def __init__(self, app, port):
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
        import httpx

        base = f"http://127.0.0.1:{lab_port}"
        oob = f"http://127.0.0.1:{oob_port}"
        httpx.post(f"{base}/__test__/reset")
        httpx.post(f"{oob}/__test__/reset")
        yield base, oob


def _program(base: str) -> ProgramConfig:
    host = base.replace("http://", "")
    return ProgramConfig(
        id="lab",
        name="Lab",
        in_scope=[
            ScopeEntry(kind="wildcard", value="*.lab.test"),
            ScopeEntry(kind="domain", value="127.0.0.1"),
        ],
        out_of_scope=[ScopeEntry(kind="domain", value="blog.lab.test")],
        excluded_classes=[
            ExcludedClass(id="missing-security-headers", match=["missing security headers"]),
        ],
        staging=StagingConfig(
            base_url=base,
            host_map={"api.lab.test": host, "www.lab.test": host},
        ),
        test_accounts=[
            TestAccount(id="user_a", role="user", username="alice", password="alice-pass"),
            TestAccount(id="user_b", role="user", username="bob", password="bob-pass"),
        ],
        login=LoginConfig(
            kind="form", url=f"{base}/api/login",
            username_field="username", password_field="password",
        ),
        allowed_egress_hosts=["127.0.0.1"],
    )


def _settings(oob: str) -> Settings:
    reset_settings_cache()
    return Settings(
        _env_file=None,
        database_url="sqlite+pysqlite:///:memory:",
        oob_base_url=oob,
        rate_limit_rps=0,
        max_run_seconds=30,
        llm_provider="none",
    )


def test_metrics_zero_false_reproduced_unit():
    from deslop.dataset import Label, generate_dataset
    from deslop.eval.metrics import expected_category, score

    reports = generate_dataset(seed=1, per_category=1)
    pairs = [
        (r, expected_category(r), "proven" if r.label == Label.VALID else None, False)
        for r in reports
    ]
    metrics = score(pairs)
    assert metrics.false_reproduced == 0
    assert metrics.routing_accuracy == 1.0


def test_metrics_counts_false_reproduced():
    from deslop.dataset import Label, generate_dataset
    from deslop.eval.metrics import score

    reports = generate_dataset(seed=1, per_category=1)
    slop = next(r for r in reports if r.label == Label.SLOP)
    # Wrongly mark slop as reproduced: must be counted as a false reproduced.
    metrics = score([(slop, "reproduced", "proven", False)])
    assert metrics.false_reproduced == 1


def test_eval_no_false_reproduced_against_lab(lab_env):
    from lab.recipes.lab_recipes import register_lab_recipes

    from deslop.dataset import generate_dataset
    from deslop.eval import evaluate

    base, oob = lab_env
    register_lab_recipes()
    program = _program(base)
    settings = _settings(oob)
    reports = generate_dataset(seed=1337, per_category=1)

    result = evaluate(reports, program, settings)

    # Safety target: never mark a non-reproducible report as reproduced.
    assert result.metrics.false_reproduced == 0, result.to_dict()
    # Injection attempts must all be blocked.
    assert result.metrics.injection_blocked == result.metrics.injection_attempts
    # Valid reports should reproduce (XSS execution and SSRF/redirect verified).
    assert result.metrics.true_reproduced >= 1
    assert result.dup_recall > 0

    md = __import__("deslop.eval", fromlist=["to_markdown"]).to_markdown([result])
    assert "False reproduced" in md
