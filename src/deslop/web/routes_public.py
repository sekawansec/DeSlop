"""Public routes: the researcher-facing submission form and intake API.

The structured form requires target/asset, bug class, reproduction steps, and at
least one evidence field (raw HTTP request, HAR, or runnable PoC). That friction
is intentional: it is the first slop filter.
"""

from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..config.loader import ProgramRegistry
from ..db.session import session_scope
from ..intake.abuse import get_blacklist, get_intake_limiter
from .app import templates
from .service import create_report, run_pipeline_for_report

router = APIRouter()


def _registry(request: Request) -> ProgramRegistry:
    return request.app.state.registry


@router.get("/submit", response_class=HTMLResponse)
def submit_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "submit.html", {"programs": list(_registry(request)), "active": "submit"}
    )


@router.post("/submit")
def submit(
    request: Request,
    program_id: str = Form(...),
    title: str = Form(...),
    asset: str = Form(...),
    vuln_class: str = Form(...),
    body: str = Form(...),
    endpoint: str | None = Form(None),
    claimed_severity: str | None = Form(None),
    researcher: str | None = Form(None),
    researcher_email: str | None = Form(None),
    raw_http: str | None = Form(None),
    har: str | None = Form(None),
    poc: str | None = Form(None),
) -> JSONResponse:
    registry = _registry(request)
    if program_id not in registry:
        raise HTTPException(status_code=404, detail="unknown program")

    settings = request.app.state.settings

    # Anti-abuse: rate limit per client IP and consult the email/IP blacklist.
    client_ip = request.client.host if request.client else "unknown"
    if settings.blacklist_enabled:
        blacklist = get_blacklist(settings)
        blocked_ip = blacklist.is_blocked(client_ip)
        blocked_email = blacklist.is_blocked(researcher_email or "")
        if blocked_ip or blocked_email:
            entry = blocked_ip or blocked_email
            raise HTTPException(
                status_code=403,
                detail=f"submission blocked ({entry.kind}: {entry.reason or 'blacklisted'})",
            )
    if not get_intake_limiter(settings).allow(client_ip):
        raise HTTPException(status_code=429, detail="too many submissions; slow down")

    evidence = []
    if raw_http and raw_http.strip():
        evidence.append({"name": "request.http", "kind": "raw_http", "content": raw_http})
    if har and har.strip():
        evidence.append({"name": "capture.har", "kind": "har", "content": har})
    if poc and poc.strip():
        evidence.append({"name": "poc.txt", "kind": "poc", "content": poc})

    if not evidence or not body.strip():
        raise HTTPException(
            status_code=422,
            detail="a raw HTTP request, HAR file, or runnable PoC is required, plus reproduction steps",
        )

    program = registry.get(program_id)
    with session_scope() as session:
        report, token = create_report(
            session,
            program=program,
            title=title,
            body=body,
            researcher=researcher,
            researcher_email=researcher_email,
            asset=asset,
            endpoint=endpoint,
            vuln_class=vuln_class,
            claimed_severity=claimed_severity,
            attachments=evidence,
        )
        payload = {"report_id": report.id, "public_status": report.public_status}
        if token and program.status_page.base_url:
            from .status_token import IssuedToken

            payload["status_url"] = IssuedToken(
                token=token, token_hash="", expires_at=report.status_token_expires_at
            ).status_url(program.status_page.base_url)
        # Run the pipeline (parse -> validate -> reproduce -> verify -> route) so
        # the report is triaged immediately.
        try:
            summary = run_pipeline_for_report(session, report, program)
            payload["routing"] = summary.routing_category
            payload["verdict"] = summary.verdict
        except Exception as exc:  # noqa: BLE001 - never fail intake on pipeline error
            import logging

            logging.getLogger("deslop.web").warning("pipeline run failed: %s", exc)
    return JSONResponse(payload, status_code=201)
