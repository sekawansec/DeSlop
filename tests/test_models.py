import pytest

from deslop.config.settings import reset_settings_cache
from deslop.db import (
    AuditLog,
    Base,
    DuplicateCandidate,
    Message,
    PublicStatus,
    Report,
    ReportStatus,
    ReproPlan,
    ReproRun,
    RoutingCategory,
    TriageResult,
    get_engine,
    reset_engine,
    session_scope,
)


@pytest.fixture()
def sqlite_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    monkeypatch.setenv("DESLOP_DATABASE_URL", f"sqlite+pysqlite:///{db}")
    monkeypatch.setenv("DESLOP_EMBEDDING_DIM", "8")
    reset_settings_cache()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield engine
    reset_engine()
    reset_settings_cache()


def test_tables_created(sqlite_db):
    from sqlalchemy import inspect

    tables = set(inspect(sqlite_db).get_table_names())
    assert {
        "reports",
        "messages",
        "repro_plans",
        "repro_runs",
        "duplicate_candidates",
        "triage_results",
        "audit_logs",
    } <= tables


def test_report_roundtrip_with_embedding(sqlite_db):
    with session_scope() as s:
        r = Report(
            id="RPT-1",
            program_id="demo",
            title="IDOR on invoices",
            body="Steps...",
            asset="api.demo.test",
            vuln_class="CWE-639",
            status=ReportStatus.RECEIVED.value,
            public_status=PublicStatus.RECEIVED.value,
            embedding=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
        )
        s.add(r)

    with session_scope() as s:
        got = s.get(Report, "RPT-1")
        assert got is not None
        assert got.title == "IDOR on invoices"
        assert got.embedding is not None
        assert len(got.embedding) == 8
        assert got.embedding[0] == pytest.approx(0.1)


def test_relationships_and_cascade(sqlite_db):
    with session_scope() as s:
        r = Report(id="RPT-2", program_id="demo", title="X", body="y")
        s.add(r)
        s.add(Message(report_id="RPT-2", direction="to_researcher", body="hi"))
        plan = ReproPlan(report_id="RPT-2", steps=[{"n": 1}])
        s.add(plan)
        s.flush()
        s.add(ReproRun(plan_id=plan.id, run_id="run-1", status="passed", verdict="proven"))
        s.add(
            TriageResult(
                report_id="RPT-2",
                routing_category=RoutingCategory.REPRODUCED.value,
                confidence=0.9,
            )
        )
        s.add(DuplicateCandidate(report_id="RPT-2", candidate_report_id="RPT-2", similarity=0.5))
        s.add(AuditLog(report_id="RPT-2", actor="admin", action="accept", detail={}))

    with session_scope() as s:
        r = s.get(Report, "RPT-2")
        assert len(r.messages) == 1
        assert len(r.repro_plans) == 1
        assert r.repro_plans[0].runs[0].verdict == "proven"
        assert r.triage_result.routing_category == RoutingCategory.REPRODUCED.value


def test_duplicate_of_self_reference(sqlite_db):
    with session_scope() as s:
        s.add(Report(id="ORIG", program_id="demo", title="orig", body="b"))
    with session_scope() as s:
        s.add(
            Report(
                id="DUP",
                program_id="demo",
                title="dup",
                body="b",
                duplicate_of="ORIG",
                status=ReportStatus.DUPLICATE.value,
            )
        )
    with session_scope() as s:
        assert s.get(Report, "DUP").duplicate_of == "ORIG"


def test_status_token_hash_stored(sqlite_db):
    with session_scope() as s:
        s.add(
            Report(
                id="RPT-3",
                program_id="demo",
                title="t",
                body="b",
                status_token_hash="deadbeef",
            )
        )
    with session_scope() as s:
        r = s.get(Report, "RPT-3")
        assert r.status_token_hash == "deadbeef"
        assert r.status_token_revoked is False
