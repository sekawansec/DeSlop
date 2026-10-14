"""Login helpers for validator test accounts.

Automated login is required for reproduction. Credentials are sourced from the
program config and are never written to logs or evidence packs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from ..config.schema import LoginConfig, TestAccount

log = logging.getLogger("deslop.repro.login")


@dataclass
class Session:
    account_id: str
    cookies: dict[str, str]
    headers: dict[str, str]
    raw: dict | None = None


def _extract_json_object(body: str) -> dict | None:
    import json

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _extract_token(body: str) -> str | None:
    import re

    m = re.search(r'"(?:token|access_token|id_token)"\s*:\s*"([^"]+)"', body)
    return m.group(1) if m else None


def _fetch_csrf(client: httpx.Client, login: LoginConfig) -> str | None:
    """GET the login page and extract an anti-CSRF token, if configured."""
    if not login.csrf_field or not login.url:
        return None
    import re

    resp = client.get(login.url)
    if login.csrf_regex:
        m = re.search(login.csrf_regex, resp.text)
        return m.group(1) if m and m.groups() else None
    pattern = (
        rf"name=['\"]{re.escape(login.csrf_field)}['\"]\s+value=['\"]([^'\"]+)['\"]"
    )
    m = re.search(pattern, resp.text)
    if m:
        return m.group(1)
    # Also handle value-before-name ordering.
    pattern2 = (
        rf"value=['\"]([^'\"]+)['\"]\s+name=['\"]{re.escape(login.csrf_field)}['\"]"
    )
    m = re.search(pattern2, resp.text)
    return m.group(1) if m else None


def login_account(
    account: TestAccount,
    login: LoginConfig,
    *,
    client: httpx.Client | None = None,
) -> Session:
    """Authenticate a test account and return its session credentials."""
    if login.kind == "none" or not login.url:
        # Token-style accounts: the config may carry a pre-provisioned session
        # in the password field, or the app allows cookie-free test auth.
        return Session(account_id=account.id, cookies={}, headers={})

    owns_client = client is None
    client = client or httpx.Client(timeout=15.0, follow_redirects=True)
    try:
        csrf_value = _fetch_csrf(client, login)

        if login.kind == "api":
            payload = {
                login.username_field: account.username,
                login.password_field: account.password,
            }
            payload.update(login.extra_fields)
            if login.csrf_field and csrf_value:
                payload[login.csrf_field] = csrf_value
            resp = client.post(login.url, json=payload)
        else:  # form
            data = {
                login.username_field: account.username,
                login.password_field: account.password,
            }
            data.update(login.extra_fields)
            if login.csrf_field and csrf_value:
                data[login.csrf_field] = csrf_value
            resp = client.post(login.url, data=data)

        if resp.status_code >= 400:
            raise RuntimeError(
                f"login for account {account.id!r} failed with HTTP {resp.status_code}"
            )
        if login.success_indicator and login.success_indicator not in resp.text:
            raise RuntimeError(
                f"login for account {account.id!r} did not return the success indicator"
            )

        cookies = dict(client.cookies)
        headers: dict[str, str] = {}
        token = _extract_token(resp.text)
        if token:
            headers["Authorization"] = f"Bearer {token}"

        return Session(
            account_id=account.id,
            cookies=cookies,
            headers=headers,
            raw=_extract_json_object(resp.text),
        )
    finally:
        if owns_client:
            client.close()
