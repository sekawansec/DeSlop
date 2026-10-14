"""Researcher status page (account-less, token-based).

Shows only: report id, title, submission date, simplified public status, last
update time, and messages the triager explicitly chose to send. Never exposes
evidence, repro logs, internal statuses, CVSS reasoning, or other reports.
"""

from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..db.enums import MessageDirection, PublicStatus
from ..db.session import session_scope
from .app import templates
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


@router.get("/status/{token}", response_class=HTMLResponse)
def status_page(request: Request, token: str) -> HTMLResponse:
    limiter.check(_client_key(request), limit=60, window=60.0)
    with session_scope() as session:
        report = report_by_token(session, hash_token(token))
        if report is None:
            raise HTTPException(status_code=404, detail="not found")
        messages = [
            {"body": m.body, "created_at": m.created_at.isoformat()}
            for m in report.messages
            if m.direction == MessageDirection.TO_RESEARCHER.value and m.visible_to_researcher
        ]
        view = public_view(report)
        view["status_label"] = _PUBLIC_LABELS.get(report.public_status, report.public_status)
        can_reply = report.public_status == PublicStatus.NEEDS_INFO.value
        return templates.TemplateResponse(
            request, "status.html", {"report": view, "messages": messages, "token": token,
                                     "can_reply": can_reply}
        )


@router.post("/status/{token}/reply")
def reply(
    request: Request,
    token: str,
    message: str = Form(...),
) -> JSONResponse:
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
        # Re-enters the pipeline; internal status set, public status unchanged.
        report.status = "received"
        report_id = report.id
    return JSONResponse({"ok": True, "report_id": report_id})


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"
