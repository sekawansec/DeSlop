"""Status-page tokens.

Tokens grant a researcher account-less access to their own report. They are:

* random (>= 128 bits), generated with ``secrets``
* stored only as a SHA-256 hash in the database
* unique per report, optionally expiring, and revocable by a triager
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def generate_token(nbytes: int = 32) -> str:
    """Return a URL-safe token with at least 128 bits of entropy (default 256)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class IssuedToken:
    token: str
    token_hash: str
    expires_at: datetime | None

    def status_url(self, base_url: str) -> str:
        return f"{base_url.rstrip('/')}/status/{self.token}"


def issue_token(ttl: timedelta | None = None) -> IssuedToken:
    token = generate_token()
    expires = datetime.now(UTC) + ttl if ttl else None
    return IssuedToken(token=token, token_hash=hash_token(token), expires_at=expires)


def token_is_valid(
    *,
    token_hash: str | None,
    stored_hash: str | None,
    expires_at: datetime | None,
    revoked: bool,
) -> bool:
    """Constant-time comparison plus expiry/revocation checks."""
    if revoked or not stored_hash or not token_hash:
        return False
    if not secrets.compare_digest(token_hash, stored_hash):
        return False
    if expires_at is not None:
        now = datetime.now(UTC)
        exp = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=UTC)
        if now > exp:
            return False
    return True
