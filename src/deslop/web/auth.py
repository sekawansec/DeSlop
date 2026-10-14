"""Dashboard authentication and role-based authorization.

HTTP Basic auth over the triage dashboard, backed by a password hash in
settings, plus optional additional users from ``DESLOP_DASHBOARD_USERS_JSON``.

Roles:

* ``admin``    - everything, including settings-ish actions.
* ``triager``  - make decisions, send replies, update public status, retest.
* ``readonly`` - view the dashboard and reports only.

Deployments can also put this behind their own SSO / reverse proxy.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ..config.settings import Settings

security = HTTPBasic(auto_error=False)

ROLE_ADMIN = "admin"
ROLE_TRIAGER = "triager"
ROLE_READONLY = "readonly"
_VALID_ROLES = {ROLE_ADMIN, ROLE_TRIAGER, ROLE_READONLY}
#: Roles allowed to take mutating actions.
_CAN_ACT = {ROLE_ADMIN, ROLE_TRIAGER}


def hash_password(password: str, *, salt: str | None = None) -> str:
    """Hash a password as ``salt$pbkdf2_sha256$hex`` for storage in settings."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}$pbkdf2_sha256${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    try:
        salt, algo, hexdigest = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return hmac.compare_digest(digest.hex(), hexdigest)


@dataclass
class Principal:
    username: str
    role: str

    @property
    def can_act(self) -> bool:
        return self.role in _CAN_ACT


def _load_users(settings: Settings) -> list[Principal]:
    users = [Principal(settings.dashboard_user, ROLE_ADMIN)]
    raw = settings.dashboard_users_json.strip()
    if raw:
        try:
            items = json.loads(raw)
        except ValueError:
            items = []
        for item in items if isinstance(items, list) else []:
            name = str(item.get("username", "")).strip()
            role = str(item.get("role", ROLE_READONLY)).strip().lower()
            if not name:
                continue
            users.append(Principal(name, role if role in _VALID_ROLES else ROLE_READONLY))
    return users


def _hash_for(username: str, settings: Settings) -> str | None:
    if username == settings.dashboard_user:
        return settings.dashboard_password_hash or None
    raw = settings.dashboard_users_json.strip()
    if raw:
        try:
            items = json.loads(raw)
        except ValueError:
            items = []
        for item in items if isinstance(items, list) else []:
            if str(item.get("username", "")) == username:
                return item.get("password_hash")
    return None


def authenticate(
    credentials: HTTPBasicCredentials | None, settings: Settings
) -> Principal:
    # Always compare against something to reduce user-enumeration timing leaks.
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    username = credentials.username
    stored = _hash_for(username, settings)
    known = stored is not None
    if not known:
        # Dummy verification to equalize timing.
        verify_password(credentials.password, hash_password("x"))
    pass_ok = known and verify_password(credentials.password, stored or "")
    if not (known and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    role = next((u.role for u in _load_users(settings) if u.username == username), ROLE_READONLY)
    return Principal(username, role)


def require_user(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(security),
) -> Principal:
    settings: Settings = request.app.state.settings
    return authenticate(credentials, settings)


def require_triager(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(security),
) -> str:
    """Backwards-compatible dependency returning the username; requires triager+."""
    principal = authenticate(credentials, request.app.state.settings)
    if not principal.can_act:
        raise HTTPException(status_code=403, detail="read-only account")
    return principal.username
