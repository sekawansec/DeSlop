"""ORM models for the DeSlop data model (see docs/architecture.md)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..config.settings import get_settings
from .base import Base, TimestampMixin, Vector, utcnow
from .enums import (
    Decision,
    DuplicateVerdict,
    MessageDirection,
    PublicStatus,
    ReportStatus,
    ReproRunStatus,
    RoutingCategory,
    Verdict,
)


def _embedding_col() -> Mapped[list[float] | None]:
    return mapped_column(Vector(get_settings().embedding_dim), nullable=True)


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    program_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)

    researcher: Mapped[str | None] = mapped_column(String(255), nullable=True)
    researcher_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    asset: Mapped[str | None] = mapped_column(String(512), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    vuln_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claimed_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Attachments stored as JSON: [{"name","kind","path","sha256","size"}]
    attachments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    status: Mapped[str] = mapped_column(
        String(48), default=ReportStatus.RECEIVED.value, index=True
    )
    public_status: Mapped[str] = mapped_column(
        String(32), default=PublicStatus.RECEIVED.value, index=True
    )
    final_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    duplicate_of: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("reports.id"), nullable=True
    )

    # Status-page token: stored hashed, never in plaintext.
    status_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    status_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status_token_revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    embedding: Mapped[list[float] | None] = _embedding_col()
    root_cause_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Intake attestation: the researcher asserted they reproduced the bug and
    # optionally disclosed AI assistance. Recorded, never trusted on its own.
    attestation: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_used: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Optional PoC video (YouTube link); validated at intake.
    poc_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # A triager's approve_production decision flips this; it permits automated
    # reproduction against in-scope production hosts for this report only.
    production_approved: Mapped[bool] = mapped_column(Boolean, default=False)

    last_public_update_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    messages: Mapped[list[Message]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )
    repro_plans: Mapped[list[ReproPlan]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )
    triage_result: Mapped[TriageResult | None] = relationship(
        back_populates="report", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_reports_program_status", "program_id", "status"),
    )


class Message(Base, TimestampMixin):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    direction: Mapped[str] = mapped_column(String(24))
    body: Mapped[str] = mapped_column(Text)
    attachments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    sent_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    visible_to_researcher: Mapped[bool] = mapped_column(Boolean, default=True)

    report: Mapped[Report] = relationship(back_populates="messages")


class ReproPlan(Base, TimestampMixin):
    __tablename__ = "repro_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    bug_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    substitutions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    parser_model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    report: Mapped[Report] = relationship(back_populates="repro_plans")
    runs: Mapped[list[ReproRun]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class ReproRun(Base, TimestampMixin):
    __tablename__ = "repro_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("repro_plans.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(24), default=ReproRunStatus.PENDING.value)
    verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
    failed_step_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    request_log: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    deviation_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    plan: Mapped[ReproPlan] = relationship(back_populates="runs")


class DuplicateCandidate(Base, TimestampMixin):
    __tablename__ = "duplicate_candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    candidate_report_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    similarity: Mapped[float] = mapped_column(Float, default=0.0)
    boosted_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)


class TriageResult(Base, TimestampMixin):
    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("reports.id", ondelete="CASCADE"), unique=True, index=True
    )
    routing_category: Mapped[str | None] = mapped_column(String(48), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    suggested_cvss: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    injection_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    injection_details: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    #: True when the plan was stopped at the production gate — an
    #: ``approve_production`` decision re-runs it.
    production_gate: Mapped[bool] = mapped_column(Boolean, default=False)
    reply_draft: Mapped[str | None] = mapped_column(Text, nullable=True)
    final_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    report: Mapped[Report] = relationship(back_populates="triage_result")


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


__all__ = [
    "AuditLog",
    "Decision",
    "DuplicateCandidate",
    "DuplicateVerdict",
    "Message",
    "MessageDirection",
    "PublicStatus",
    "Report",
    "ReportStatus",
    "ReproPlan",
    "ReproRun",
    "ReproRunStatus",
    "RoutingCategory",
    "TriageResult",
    "Verdict",
    "utcnow",
]
