"""Audit log helper: every decision is recorded."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..db.models import AuditLog


def record(
    session: Session,
    *,
    actor: str,
    action: str,
    report_id: str | None = None,
    detail: dict | None = None,
) -> AuditLog:
    entry = AuditLog(
        report_id=report_id,
        actor=actor,
        action=action,
        detail=detail or {},
    )
    session.add(entry)
    return entry
