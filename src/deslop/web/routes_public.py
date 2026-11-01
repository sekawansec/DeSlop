"""Public routes: the researcher-facing submission form and intake API.

The structured form requires target/asset, bug class, reproduction steps, and at
least one evidence field (raw HTTP request, HAR, or runnable PoC). That friction
is intentional: it is the first slop filter.
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..config.loader import ProgramRegistry
from ..db.session import session_scope
from ..intake.abuse import get_blacklist, get_intake_limiter
from .app import templates
from .http import wants_html
from .service import create_report, process_report

router = APIRouter()


def _registry(request: Request) -> ProgramRegistry:
    return request.app.state.registry


_YOUTUBE_HOSTS = {"youtube.com", "youtu.be"}


def _is_youtube_url(value: str) -> bool:
    """Accept only real YouTube hosts (watch, shorts, live, youtu.be shares)."""
    url = value.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in _YOUTUBE_HOSTS or host.endswith(".youtube.com")


@router.get("/guide", response_class=HTMLResponse)
def guide(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "guide.html", {"active": "guide"})


@router.get("/submit", response_class=HTMLResponse)
def submit_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "submit.html",
        {"programs": list(_registry(request)), "active": "submit", "form": {}},
    )


def _submit_error(
    request: Request, detail: str, form: dict, status_code: int = 422
) -> Response:
    """Re-render the form with an error for browsers; JSON for API clients."""
    if wants_html(request):
        return templates.TemplateResponse(
            request,
            "submit.html",
            {
                "programs": list(_registry(request)),
                "active": "submit",
                "error": detail,
                "form": form,
            },
            status_code=status_code,
        )
    raise HTTPException(status_code=status_code, detail=detail)


@router.post("/submit")
def submit(
    request: Request,
    background_tasks: BackgroundTasks,
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
    poc_video: str | None = Form(None),
    attestation: str | None = Form(None),
    ai_used: str | None = Form(None),
) -> Response:
    registry = _registry(request)
    # Repopulate the form on validation errors so researchers do not lose work.
    form = {
        "program_id": program_id, "title": title, "asset": asset,
        "vuln_class": vuln_class, "body": body, "endpoint": endpoint,
        "claimed_severity": claimed_severity, "researcher": researcher,
        "researcher_email": researcher_email, "raw_http": raw_http,
        "har": har, "poc": poc, "poc_video": poc_video,
        "attestation": attestation, "ai_used": ai_used,
    }
    if poc_video and poc_video.strip() and not _is_youtube_url(poc_video):
        return _submit_error(
            request, "PoC video must be a YouTube link", form
        )
    if program_id not in registry:
        return _submit_error(request, "unknown program", form, status_code=404)

    settings = request.app.state.settings

    # Anti-abuse: rate limit per client IP and consult the email/IP blacklist.
    client_ip = request.client.host if request.client else "unknown"
    if settings.blacklist_enabled:
        blacklist = get_blacklist(settings)
        blocked_ip = blacklist.is_blocked(client_ip)
        blocked_email = blacklist.is_blocked(researcher_email or "")
        if blocked_ip or blocked_email:
            entry = blocked_ip or blocked_email
            return _submit_error(
                request,
                f"submission blocked ({entry.kind}: {entry.reason or 'blacklisted'})",
                form,
                status_code=403,
            )
    if not get_intake_limiter(settings).allow(client_ip):
        return _submit_error(
            request, "too many submissions; slow down", form, status_code=429
        )

    evidence = []
    if raw_http and raw_http.strip():
        evidence.append({"name": "request.http", "kind": "raw_http", "content": raw_http})
    if har and har.strip():
        evidence.append({"name": "capture.har", "kind": "har", "content": har})
    if poc and poc.strip():
        evidence.append({"name": "poc.txt", "kind": "poc", "content": poc})

    if not evidence or not body.strip():
        return _submit_error(
            request,
            "a raw HTTP request, HAR file, or runnable PoC is required, plus reproduction steps",
            form,
        )
    # Attestation is recorded, not trusted: a false attestation is grounds for
    # a ban, which is what gives it weight.
    if not attestation:
        return _submit_error(
            request,
            "attestation required: confirm you reproduced this yourself",
            form,
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
            attestation=True,
            ai_used=ai_used if ai_used in {"yes", "no"} else None,
            poc_url=poc_video.strip() if poc_video and poc_video.strip() else None,
        )
        payload = {"report_id": report.id, "public_status": report.public_status}
        status_url = None
        if token:
            from .status_token import IssuedToken

            # Fall back to the request's own origin when the program does not
            # configure a public base URL, so every program is trackable.
            base = program.status_page.base_url or str(request.base_url).rstrip("/")
            status_url = IssuedToken(
                token=token, token_hash="", expires_at=report.status_token_expires_at
            ).status_url(base)
            payload["status_url"] = status_url

    # The report is committed; triage (parse -> validate -> reproduce -> verify
    # -> route) runs after the response so a slow reproduction never holds the
    # request open. Internal routing/verdict are never returned to the
    # researcher — they only get the public status page.
    background_tasks.add_task(process_report, report.id, program, settings=settings)

    if wants_html(request):
        return templates.TemplateResponse(
            request,
            "submitted.html",
            {
                "report_id": report.id,
                "status_url": status_url,
                "program_name": program.name,
                "active": "submit",
            },
            status_code=201,
        )
    return JSONResponse(payload, status_code=201)
