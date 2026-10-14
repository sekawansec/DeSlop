"""Intentionally vulnerable lab application for DeSlop.

WARNING: This app is DELIBERATELY INSECURE. It exists only so DeSlop's
verifiers can be tested end-to-end against known, reproducible bugs. Never
expose it beyond a local lab network.

Bugs included (one per v1 recipe):

* IDOR            GET  /api/invoices/{invoice_id}   (no ownership check)
* Reflected XSS   GET  /search?q=                   (unescaped reflection)
* Stored XSS      POST /api/comments, GET /comments (unescaped rendering)
* SSRF            GET  /api/fetch?url=              (server-side fetch)
* Open redirect   GET  /redirect?next=              (unvalidated redirect)
"""

from __future__ import annotations

import os
import secrets
from typing import Any

import httpx
from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

SESSION_COOKIE = "lab_session"
SSRF_ENABLED = os.environ.get("LAB_ENABLE_SSRF", "1") != "0"

USERS: dict[str, dict[str, Any]] = {
    "alice": {"id": 1, "password": "alice-pass", "role": "user", "tenant": "tenant-one"},
    "bob": {"id": 2, "password": "bob-pass", "role": "user", "tenant": "tenant-one"},
    "carol": {"id": 3, "password": "carol-pass", "role": "user", "tenant": "tenant-two"},
    "admin": {"id": 100, "password": "admin-pass", "role": "admin", "tenant": "tenant-one"},
}

#: Owner-scoped invoices. The ``secret`` field is the ownership proof the IDOR
#: verifier looks for in a response returned to a *different* account.
INVOICES: dict[int, dict[str, Any]] = {
    1001: {"id": 1001, "owner": "alice", "amount": 4200.00, "secret": "ACME-INVOICE-ALICE-1001"},
    1002: {"id": 1002, "owner": "bob", "amount": 1500.00, "secret": "ACME-INVOICE-BOB-1002"},
    1003: {"id": 1003, "owner": "carol", "amount": 999.00, "secret": "ACME-INVOICE-CAROL-1003"},
}

_sessions: dict[str, str] = {}
_comments: list[dict[str, str]] = []


def _reset_state() -> None:
    _sessions.clear()
    _comments.clear()
    _comments.append({"author": "alice", "text": "Welcome to the Acme lab comment board."})


_reset_state()


def _current_user(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return _sessions.get(token)


def create_app() -> FastAPI:
    app = FastAPI(title="DeSlop Lab (vulnerable)", version="0.1.0")

    # ------------------------------------------------------------------ health
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "lab": "true"}

    # ------------------------------------------------------------------- auth
    @app.post("/api/login")
    def login(username: str = Form(...), password: str = Form(...)) -> Response:
        user = USERS.get(username)
        if not user or user["password"] != password:
            return JSONResponse({"error": "invalid credentials"}, status_code=401)
        token = secrets.token_urlsafe(24)
        _sessions[token] = username
        resp = JSONResponse({"username": username, "role": user["role"], "id": user["id"]})
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
        return resp

    @app.post("/api/logout")
    def logout(request: Request) -> Response:
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            _sessions.pop(token, None)
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    @app.get("/api/me")
    def me(request: Request) -> Response:
        username = _current_user(request)
        if not username:
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        user = USERS[username]
        return JSONResponse({"username": username, "id": user["id"], "role": user["role"]})

    # ------------------------------------------------------------------- IDOR
    @app.get("/api/invoices/{invoice_id}")
    def get_invoice(invoice_id: int, request: Request) -> Response:
        # VULNERABLE: authenticated, but no ownership / tenant check.
        if not _current_user(request):
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        invoice = INVOICES.get(invoice_id)
        if not invoice:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(invoice)

    @app.get("/api/invoices")
    def list_invoices(request: Request) -> Response:
        username = _current_user(request)
        if not username:
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        mine = [inv for inv in INVOICES.values() if inv["owner"] == username]
        return JSONResponse({"invoices": mine})

    # --------------------------------------------------------- Reflected XSS
    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = "") -> HTMLResponse:
        # VULNERABLE: q is reflected without escaping.
        return HTMLResponse(
            f"<!doctype html><html><body>"
            f"<h1>Search</h1><p>Results for: {q}</p>"
            f"</body></html>"
        )

    # ------------------------------------------------------------ Stored XSS
    @app.post("/api/comments")
    def add_comment(author: str = Form("anonymous"), text: str = Form(...)) -> Response:
        # VULNERABLE: comment text is stored and later rendered unescaped.
        _comments.append({"author": author, "text": text})
        return JSONResponse({"ok": True, "count": len(_comments)})

    @app.get("/comments", response_class=HTMLResponse)
    def list_comments() -> HTMLResponse:
        rows = "".join(
            f"<li><b>{c['author']}</b>: {c['text']}</li>" for c in _comments
        )
        return HTMLResponse(f"<!doctype html><html><body><ul>{rows}</ul></body></html>")

    # ------------------------------------------------------------------ SSRF
    @app.get("/api/fetch")
    def fetch(url: str) -> Response:
        # VULNERABLE: fetches any URL the caller supplies.
        if not SSRF_ENABLED:
            return JSONResponse({"error": "ssrf disabled"}, status_code=403)
        try:
            r = httpx.get(url, timeout=5.0, follow_redirects=False)
        except httpx.HTTPError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse({"status": r.status_code, "body": r.text[:4096]})

    # --------------------------------------------------------- Open redirect
    @app.get("/redirect")
    def open_redirect(next: str) -> Response:
        # VULNERABLE: redirects to any next= value.
        return RedirectResponse(url=next, status_code=302)

    # ----------------------------------------------------------------- reset
    @app.post("/__test__/reset")
    def reset() -> PlainTextResponse:
        _reset_state()
        return PlainTextResponse("reset ok")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><html><body><h1>DeSlop Lab</h1>"
            "<p>Intentionally vulnerable. For local testing only.</p>"
            "<ul><li>IDOR: /api/invoices/1001</li><li>XSS: /search?q=</li>"
            "<li>SSRF: /api/fetch?url=</li><li>Redirect: /redirect?next=</li></ul>"
            "</body></html>"
        )

    return app


app = create_app()
