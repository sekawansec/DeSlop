import pytest

from deslop.config.schema import (
    LoginConfig,
    ProgramConfig,
    ScopeEntry,
    StagingConfig,
    TestAccount,
)
from deslop.config.settings import Settings, reset_settings_cache
from deslop.db import Base, Report, ReproPlan
from deslop.db.session import get_engine, reset_engine, session_scope
from deslop.pipeline.retest import retest_report


def _program(tmp_path):
    # A tiny local HTTP target the executor can actually reach is not started
    # here; retest is tested for its no-plan / not-proven paths deterministically.
    return ProgramConfig(
        id="lab",
        name="Lab",
        in_scope=[ScopeEntry(kind="wildcard", value="*.lab.test")],
        staging=StagingConfig(base_url="http://127.0.0.1:1"),
        test_accounts=[
            TestAccount(id="user_a", role="user", username="a", password="a"),
            TestAccount(id="user_b", role="user", username="b", password="b"),
        ],
        login=LoginConfig(kind="none"),
    )


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("DESLOP_DATABASE_URL", f"sqlite+pysqlite:///{tmp_path/'r.db'}")
    monkeypatch.setenv("DESLOP_EMBEDDING_DIM", "16")
    reset_settings_cache()
    reset_engine()
    Base.metadata.create_all(get_engine())
    yield
    reset_engine()
    reset_settings_cache()


def test_retest_requires_a_plan(db):
    with session_scope() as s:
        s.add(Report(id="R1", program_id="lab", title="t", body="b", vuln_class="idor"))
    with session_scope() as s, pytest.raises(ValueError):
        retest_report(s, "R1", _program(None), settings=Settings(_env_file=None))


def test_retest_not_proven_against_unreachable_target(db):
    with session_scope() as s:
        s.add(Report(id="R2", program_id="lab", title="t", body="b", vuln_class="idor"))
        s.add(
            ReproPlan(
                report_id="R2",
                steps=[
                    {
                        "index": 0,
                        "description": "read invoice",
                        "request": {"method": "GET", "url": "http://api.lab.test/api/invoices/1001"},
                        "as_account": "user_b",
                    }
                ],
            )
        )
    settings = Settings(_env_file=None, rate_limit_rps=0, max_run_seconds=5)
    with session_scope() as s:
        result = retest_report(s, "R2", _program(None), settings=settings)
    assert result.still_reproducible is False
    assert result.verdict in {"not_proven", "inconclusive"}


def test_retest_unknown_report(db):
    with session_scope() as s, pytest.raises(ValueError):
        retest_report(s, "missing", _program(None), settings=Settings(_env_file=None))
