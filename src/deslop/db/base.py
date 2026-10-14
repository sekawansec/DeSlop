"""SQLAlchemy declarative base, mixins, and a portable embedding column.

DeSlop targets PostgreSQL + pgvector in production, but tests and local dev
run on SQLite. The :class:`Vector` type decorator maps to ``pgvector`` on
PostgreSQL and falls back to a JSON-encoded list on SQLite so the same models
work in both places.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Text, TypeDecorator, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

try:  # pragma: no cover - depends on optional dependency
    from pgvector.sqlalchemy import Vector as _PGVector
except Exception:  # pragma: no cover
    _PGVector = None


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
        nullable=False,
    )


class Vector(TypeDecorator):
    """Portable embedding column.

    On PostgreSQL with pgvector installed this is a real ``vector(dim)`` column
    (indexable with ivfflat/hnsw). Everywhere else it is stored as JSON text.
    """

    impl = Text
    cache_ok = True

    def __init__(self, dim: int = 1024) -> None:
        super().__init__()
        self.dim = dim

    def load_dialect_impl(self, dialect):  # noqa: ANN001
        if dialect.name == "postgresql" and _PGVector is not None:
            return dialect.type_descriptor(_PGVector(self.dim))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value: Any, dialect):  # noqa: ANN001
        if value is None:
            return None
        if dialect.name == "postgresql" and _PGVector is not None:
            return value
        return json.dumps([float(x) for x in value])

    def process_result_value(self, value: Any, dialect):  # noqa: ANN001
        if value is None:
            return None
        if dialect.name == "postgresql" and _PGVector is not None:
            return list(value)
        try:
            return [float(x) for x in json.loads(value)]
        except (TypeError, ValueError):
            return None
