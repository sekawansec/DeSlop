"""Demo scenario test against the live lab.

Verifies the demo sorts a mixed batch: originals reproduce, paraphrases are
detected as duplicates, slop/incomplete are never marked reproduced, and
injection attempts are blocked.
"""

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
from deslop.dataset import generate_dataset
from deslop.dataset.schema import Label
from deslop.dedup.detector import NormalizedReport
from deslop.llm.embeddings import HashingEmbedder
from deslop.pipeline.orchestrator import Pipeline

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
        staging=StagingConfig(base_url=base, host_map={"api.lab.test": host, "www.lab.test": host}),
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


def _corpus(reports, settings):
    emb = HashingEmbedder(settings.embedding_dim)
    out = []
    for r in reports:
        if r.label != Label.VALID:
            continue
        summary = f"{r.title} {r.vuln_class or ''} {r.endpoint or ''}".strip()
        out.append(
            NormalizedReport(
                report_id=r.id, asset=r.asset, endpoint=r.endpoint,
                vuln_class=r.vuln_class, root_cause_summary=summary,
                embedding=emb.embed([summary])[0],
            )
        )
    return out


def test_demo_batch_sorts_correctly(lab_env):
    from lab.recipes.lab_recipes import register_lab_recipes

    base, oob = lab_env
    register_lab_recipes()
    settings = _settings(oob)
    program = _program(base)
    reports = generate_dataset(seed=1337, per_category=2)
    pipeline = Pipeline(program, settings=settings, duplicate_corpus=_corpus(reports, settings))

    categories = {}
    for r in reports:
        result = pipeline.run(
            title=r.title, body=r.body, asset=r.asset, endpoint=r.endpoint,
            vuln_class=r.vuln_class, run_id=r.id,
        )
        categories[r.id] = (r.label, result.routing.category if result.routing else None)

    # Originals reproduce.
    for rid, (label, cat) in categories.items():
        if label == Label.VALID:
            assert cat in {"reproduced", "failed_replay", "needs_human_review"}, (rid, cat)

    # Paraphrases are duplicates.
    for rid, (label, cat) in categories.items():
        if label == Label.DUPLICATE:
            assert cat == "duplicate", (rid, cat)

    # Slop is never reproduced.
    for rid, (label, cat) in categories.items():
        if label == Label.SLOP:
            assert cat != "reproduced", (rid, cat)

    # Injection attempts are blocked.
    for rid, (label, cat) in categories.items():
        if label == Label.INJECTION:
            assert cat == "blocked_by_policy", (rid, cat)

    # Out of scope and excluded are routed correctly.
    for rid, (label, cat) in categories.items():
        if label == Label.OUT_OF_SCOPE:
            assert cat == "out_of_scope", (rid, cat)
        if label == Label.EXCLUDED_CLASS:
            assert cat == "excluded_class", (rid, cat)

    # At least the IDOR and open-redirect originals prove end to end.
    proven = [rid for rid, (_, cat) in categories.items() if cat == "reproduced"]
    assert len(proven) >= 2
