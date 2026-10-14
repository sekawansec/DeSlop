"""Database layer: ORM models, enums, and session management."""

from .base import Base, TimestampMixin, Vector, utcnow
from .enums import (
    SUPPORTED_BUG_CLASSES,
    Decision,
    DuplicateVerdict,
    MessageDirection,
    PublicStatus,
    ReportStatus,
    ReproRunStatus,
    RoutingCategory,
    Verdict,
)
from .models import (
    AuditLog,
    DuplicateCandidate,
    Message,
    Report,
    ReproPlan,
    ReproRun,
    TriageResult,
)
from .session import (
    get_engine,
    get_sessionmaker,
    init_db,
    make_engine,
    reset_engine,
    session_scope,
)

__all__ = [
    "SUPPORTED_BUG_CLASSES",
    "AuditLog",
    "Base",
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
    "TimestampMixin",
    "TriageResult",
    "Vector",
    "Verdict",
    "get_engine",
    "get_sessionmaker",
    "init_db",
    "make_engine",
    "reset_engine",
    "session_scope",
    "utcnow",
]
