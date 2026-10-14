"""Intake anti-abuse: per-IP rate limiting and an email/IP blacklist.

The blacklist is a small JSON file so it survives restarts and can be edited by
hand or by a triager. Entries can be permanent or time-limited ("temporary
block" like Gerobug's email blacklisting).
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..config.settings import Settings, get_settings


@dataclass
class BlacklistEntry:
    value: str  # email or IP
    kind: str  # "email" | "ip"
    reason: str = ""
    expires_at: str | None = None  # ISO8601, or None for permanent

    def expired(self, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return False
        now = now or datetime.now(UTC)
        try:
            exp = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        return now > exp


@dataclass
class Blacklist:
    path: Path
    entries: dict[str, BlacklistEntry] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def load(cls, path: str | Path) -> Blacklist:
        p = Path(path)
        bl = cls(path=p)
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                data = []
            for item in data:
                try:
                    entry = BlacklistEntry(**item)
                    bl.entries[entry.value.lower()] = entry
                except TypeError:
                    continue
        return bl

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = [
            {
                "value": e.value,
                "kind": e.kind,
                "reason": e.reason,
                "expires_at": e.expires_at,
            }
            for e in self.entries.values()
        ]
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def is_blocked(self, value: str) -> BlacklistEntry | None:
        if not value:
            return None
        now = datetime.now(UTC)
        with self._lock:
            entry = self.entries.get(value.lower())
            if entry and entry.expired(now):
                self.entries.pop(value.lower(), None)
                entry = None
        return entry

    def add(self, value: str, kind: str, *, reason: str = "", ttl_seconds: int | None = None) -> None:
        expires = None
        if ttl_seconds:
            expires = datetime.now(UTC).timestamp() + ttl_seconds
            expires = datetime.fromtimestamp(expires, tz=UTC).isoformat()
        with self._lock:
            self.entries[value.lower()] = BlacklistEntry(
                value=value, kind=kind, reason=reason, expires_at=expires
            )
        self.save()

    def remove(self, value: str) -> bool:
        with self._lock:
            removed = self.entries.pop(value.lower(), None) is not None
        if removed:
            self.save()
        return removed


@dataclass
class IntakeLimiter:
    """Per-IP submission rate limiter (in-process)."""

    limit: int
    window: float
    _hits: dict[str, list[float]] = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits.setdefault(key, [])
        while hits and now - hits[0] > self.window:
            hits.pop(0)
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


def get_blacklist(settings: Settings | None = None) -> Blacklist:
    settings = settings or get_settings()
    return Blacklist.load(settings.blacklist_file)


_default_limiter: IntakeLimiter | None = None


def get_intake_limiter(settings: Settings | None = None) -> IntakeLimiter:
    global _default_limiter
    settings = settings or get_settings()
    if _default_limiter is None:
        _default_limiter = IntakeLimiter(
            limit=settings.intake_rate_limit, window=float(settings.intake_rate_window_seconds)
        )
    return _default_limiter


def reset_intake_limiter() -> None:
    global _default_limiter
    _default_limiter = None
