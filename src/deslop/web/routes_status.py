"""Researcher status page (account-less, token-based).

Shows only: report id, title, submission date, simplified public status, last
update time, and the message thread (triage questions plus the researcher's own
replies). Never exposes evidence, repro logs, internal statuses, CVSS reasoning,
or other reports.
"""

from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..db.enums import MessageDirection, PublicStatus, ReportStatus
from ..db.session import session_scope
from .app import templates
from .http import redirect_back, wants_html
from .rate_limit import limiter
from .service import add_message, public_view, report_by_token
from .status_token import hash_token

router = APIRouter()

_PUBLIC_LABELS = {
    PublicStatus.RECEIVED.value: "received",
    PublicStatus.UNDER_REVIEW.value: "under review",
    PublicStatus.NEEDS_INFO.value: "needs more information",
    PublicStatus.ACCEPTED.value: "accepted",
    PublicStatus.NOT_ACCEPTED.value: "not accepted",
    PublicStatus.DUPLICATE.value: "duplicate",
    PublicStatus.FIXED.value: "fixed",
}

#: Plain-language meaning shown under the status badge.
_PUBLIC_MEANINGS = {
    PublicStatus.RECEIVED.value: "queued for reproduction",
    PublicStatus.UNDER_REVIEW.value: "a triager is reviewing it",
    PublicStatus.NEEDS_INFO.value: "reply below to continue",
    PublicStatus.ACCEPTED.value: "verified, thank you",
    PublicStatus.NOT_ACCEPTED.value: "the claim could not be verified",
    PublicStatus.DUPLICATE.value: "already reported",
    PublicStatus.FIXED.value: "resolved, thank you",
}


def _status_steps(public_status: str) -> list[dict]:
    """Three-step progress: received -> under review -> decision."""
    steps = [
        {"label": "received", "state": "done"},
        {"label": "under review", "state": "todo"},
        {"label": "decision", "state": "todo"},
    ]
    if public_status in {PublicStatus.UNDER_REVIEW.value, PublicStatus.NEEDS_INFO.value}:
        steps[1]["state"] = "active"
        if public_status == PublicStatus.NEEDS_INFO.value:
            steps[1]["label"] = "needs info"
    elif public_status in {
        PublicStatus.ACCEPTED.value,
        PublicStatus.NOT_ACCEPTED.value,
        PublicStatus.DUPLICATE.value,
        PublicStatus.FIXED.value,
    }:
        steps[1]["state"] = "done"
        steps[2]["state"] = "done"
        steps[2]["label"] = _PUBLIC_LABELS.get(public_status, "decision")
    return steps


@router.get("/status/{token}", response_class=HTMLResponse)
def status_page(request: Request, token: str, notice: str | None = None) -> HTMLResponse:
    limiter.check(_client_key(request), limit=60, window=60.0)
    with session_scope() as session:
        report = report_by_token(session, hash_token(token))
        if report is None:
            raise HTTPException(status_code=404, detail="not found")
        messages = [
            {
                "body": m.body,
                "created_at": m.created_at.isoformat(),
                "mine": m.direction == MessageDirection.FROM_RESEARCHER.value,
            }
            for m in report.messages
            if m.visible_to_researcher
        ]
        view = public_view(report)
        view["status_label"] = _PUBLIC_LABELS.get(report.public_status, report.public_status)
        view["status_meaning"] = _PUBLIC_MEANINGS.get(report.public_status, "")
        can_reply = report.public_status == PublicStatus.NEEDS_INFO.value
        return templates.TemplateResponse(
            request,
            "status.html",
            {
                "report": view,
                "messages": messages,
                "token": token,
                "can_reply": can_reply,
                "steps": _status_steps(report.public_status),
                "notice": notice,
            },
        )


@router.post("/status/{token}/reply")
def reply(
    request: Request,
    token: str,
    message: str = Form(...),
) -> Response:
    limiter.check(_client_key(request), limit=10, window=60.0)
    if not message.strip():
        raise HTTPException(status_code=422, detail="message must not be empty")
    with session_scope() as session:
        report = report_by_token(session, hash_token(token))
        if report is None:
            raise HTTPException(status_code=404, detail="not found")
        add_message(
            session,
            report,
            body=message,
            direction=MessageDirection.FROM_RESEARCHER.value,
            sent_by="researcher",
            visible_to_researcher=True,
        )
        # Surface the reply in the triage queue; public status unchanged.
        report.status = ReportStatus.NEEDS_HUMAN_REVIEW.value
        report_id = report.id
    if wants_html(request):
        return redirect_back(f"/status/{token}", notice="Reply sent.")
    return JSONResponse({"ok": True, "report_id": report_id})


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"
