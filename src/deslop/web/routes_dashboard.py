"""Internal triage dashboard.

Authenticated UI where the security team reviews the routed queue, opens report
detail, makes decisions, and sends replies. Every action is written to the audit
log. Internal statuses are never exposed publicly.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import select

from ..db.enums import Decision, MessageDirection, PublicStatus
from ..db.models import Report
from ..db.session import session_scope
from .app import templates
from .auth import Principal, require_triager, require_user
from .service import (
    add_message,
    record_decision,
    revoke_token,
    set_public_status,
)

router = APIRouter(prefix="/dashboard")

_QUEUE_ORDER = [
    "reproduced",
    "reproduced_with_deviation",
    "needs_human_review",
    "needs_info",
    "manual_reproduction_required",
    "duplicate",
    "out_of_scope",
    "excluded_class",
    "blocked_by_policy",
    "failed_replay",
]


@router.get("", response_class=HTMLResponse)
def dashboard(
    request: Request, status: str | None = None, principal: Principal = Depends(require_user)
) -> HTMLResponse:
    with session_scope() as session:
        stmt = select(Report).order_by(Report.submitted_at.desc())
        reports = list(session.scalars(stmt))
        queues: dict[str, list[Report]] = {}
        for r in reports:
            queues.setdefault(r.status, []).append(r)
        ordered = {k: queues[k] for k in _QUEUE_ORDER if k in queues}
        for k, v in queues.items():
            ordered.setdefault(k, v)
        selected = queues.get(status, []) if status else []
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {"queues": ordered, "selected_status": status, "selected": selected,
             "triager": principal.username, "can_act": principal.can_act,
             "active": "dashboard",
             "total": len(reports)},
        )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def report_detail(
    request: Request, report_id: str, principal: Principal = Depends(require_user)
) -> HTMLResponse:
    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        messages = [
            {"direction": m.direction, "body": m.body, "sent_by": m.sent_by,
             "created_at": m.created_at.isoformat()}
            for m in report.messages
        ]
        plans = [
            {"version": p.version, "steps": p.steps, "substitutions": p.substitutions}
            for p in report.repro_plans
        ]
        runs = [
            {"run_id": r.run_id, "status": r.status, "verdict": r.verdict,
             "failed_step_index": r.failed_step_index, "evidence": r.evidence,
             "duration_ms": r.duration_ms}
            for plan in report.repro_plans
            for r in plan.runs
        ]
        triage = None
        if report.triage_result is not None:
            t = report.triage_result
            triage = {
                "routing_category": t.routing_category,
                "confidence": t.confidence,
                "suggested_cvss": t.suggested_cvss,
                "reasoning": t.reasoning,
                "injection_flag": t.injection_flag,
                "reply_draft": t.reply_draft,
                "final_decision": t.final_decision,
            }
        public_statuses = [s.value for s in PublicStatus]
        return templates.TemplateResponse(
            request,
            "report_detail.html",
            {
                "report": report,
                "messages": messages,
                "plans": plans,
                "runs": runs,
                "triage": triage,
                "public_statuses": public_statuses,
                "triager": principal.username,
                "can_act": principal.can_act,
                "active": "dashboard",
            },
        )


@router.post("/reports/{report_id}/decision")
def decide(
    report_id: str,
    decision: str = Form(...),
    reason: str | None = Form(None),
    triager: str = Depends(require_triager),
) -> JSONResponse:
    if decision not in {d.value for d in Decision}:
        raise HTTPException(status_code=422, detail="unknown decision")
    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        record_decision(session, report, decision=decision, actor=triager,
                        detail={"reason": reason})
        # A human decision may update the public status.
        if decision == Decision.ACCEPT.value:
            set_public_status(session, report, PublicStatus.ACCEPTED.value, actor=triager)
        elif decision == Decision.REJECT.value:
            set_public_status(session, report, PublicStatus.NOT_ACCEPTED.value, actor=triager)
        elif decision == Decision.DUPLICATE.value:
            set_public_status(session, report, PublicStatus.DUPLICATE.value, actor=triager)
        elif decision == Decision.REQUEST_INFO.value:
            set_public_status(session, report, PublicStatus.NEEDS_INFO.value, actor=triager)
    return JSONResponse({"ok": True})


@router.post("/reports/{report_id}/reply")
def reply(
    report_id: str,
    body: str = Form(...),
    triager: str = Depends(require_triager),
) -> JSONResponse:
    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        add_message(
            session, report, body=body,
            direction=MessageDirection.TO_RESEARCHER.value, sent_by=triager,
        )
    return JSONResponse({"ok": True})


@router.post("/reports/{report_id}/public_status")
def update_public_status(
    report_id: str,
    public_status: str = Form(...),
    triager: str = Depends(require_triager),
) -> JSONResponse:
    if public_status not in {s.value for s in PublicStatus}:
        raise HTTPException(status_code=422, detail="unknown public status")
    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        set_public_status(session, report, public_status, actor=triager)
    return JSONResponse({"ok": True})


@router.post("/reports/{report_id}/revoke")
def revoke(report_id: str, triager: str = Depends(require_triager)) -> JSONResponse:
    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        revoke_token(session, report, actor=triager)
    return JSONResponse({"ok": True})


@router.post("/reports/{report_id}/retest")
def retest(
    request: Request, report_id: str, triager: str = Depends(require_triager)
) -> JSONResponse:
    from ..pipeline.retest import retest_report

    registry = request.app.state.registry
    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        try:
            program = registry.get(report.program_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"program unavailable: {exc}") from exc
        try:
            result = retest_report(
                session, report_id, program, settings=request.app.state.settings
            )
        except ValueError as exc:
            # e.g. no stored reproduction plan yet (report not run through the
            # pipeline); surface as a client error, not a 500.
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(result.to_dict())


@router.get("/cvss")
def cvss_calculator(
    vector: str | None = None, triager: str = Depends(require_triager)
) -> JSONResponse:
    """Deterministic CVSS v3.1 calculator endpoint (a second opinion to any LLM)."""
    from ..cvss import compute_from_vector, vector_from_text

    if vector:
        result = compute_from_vector(vector)
        if result is None:
            raise HTTPException(status_code=422, detail="could not parse CVSS vector")
        return JSONResponse(result.to_dict())
    return JSONResponse({"metrics": vector_from_text("").vector()})


@router.get("/reports/{report_id}/evidence")
def evidence_pack(
    report_id: str, triager: str = Depends(require_triager)
) -> Response:
    from .evidence import build_evidence_pack

    with session_scope() as session:
        report = session.get(Report, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        triage = None
        if report.triage_result is not None:
            triage = {
                "routing_category": report.triage_result.routing_category,
                "suggested_cvss": report.triage_result.suggested_cvss,
                "reply_draft": report.triage_result.reply_draft,
            }
        payload = build_evidence_pack(report, triage)
        filename = f"evidence-{report.id}.zip"
    return Response(
        content=payload,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
