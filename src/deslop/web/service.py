"""Report persistence and triage actions.

All triager actions go through here so every state change is audited and the
public status only ever changes on an explicit human decision.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config.schema import ProgramConfig
from ..config.settings import Settings
from ..db.enums import Decision, MessageDirection, PublicStatus, ReportStatus
from ..db.models import Message, Report, TriageResult
from ..db.session import session_scope
from . import audit
from .status_token import issue_token, token_is_valid


def create_report(
    session: Session,
    *,
    program: ProgramConfig,
    title: str,
    body: str,
    researcher: str | None,
    researcher_email: str | None,
    asset: str | None,
    endpoint: str | None,
    vuln_class: str | None,
    claimed_severity: str | None,
    attachments: list[dict] | None = None,
    attestation: bool = False,
    ai_used: str | None = None,
    poc_url: str | None = None,
    status: str = ReportStatus.RECEIVED.value,
) -> tuple[Report, str | None]:
    """Create a report and (if the status page is on) issue a status token.

    Returns the report and the *plaintext* token (only available here, once).
    """
    report = Report(
        id=f"RPT-{uuid.uuid4().hex[:12]}",
        program_id=program.id,
        title=title,
        body=body,
        researcher=researcher,
        researcher_email=researcher_email,
        asset=asset,
        endpoint=endpoint,
        vuln_class=vuln_class,
        claimed_severity=claimed_severity,
        attachments=attachments or [],
        attestation=attestation,
        ai_used=ai_used,
        poc_url=poc_url,
        status=status,
        public_status=PublicStatus.RECEIVED.value,
    )

    plaintext_token: str | None = None
    if program.status_page.enabled:
        issued = issue_token(program.status_page.token_ttl)
        report.status_token_hash = issued.token_hash
        report.status_token_expires_at = issued.expires_at
        plaintext_token = issued.token

    session.add(report)
    session.flush()
    audit.record(session, actor="system", action="intake", report_id=report.id)
    return report, plaintext_token


def get_report(session: Session, report_id: str) -> Report | None:
    return session.get(Report, report_id)


def report_by_token(session: Session, token_hash: str) -> Report | None:
    stmt = select(Report).where(Report.status_token_hash == token_hash)
    report = session.scalars(stmt).first()
    if report is None:
        return None
    if not token_is_valid(
        token_hash=token_hash,
        stored_hash=report.status_token_hash,
        expires_at=report.status_token_expires_at,
        revoked=report.status_token_revoked,
    ):
        return None
    return report


def set_internal_status(session: Session, report: Report, status: str, *, actor: str) -> None:
    report.status = status
    audit.record(session, actor=actor, action="set_internal_status", report_id=report.id,
                 detail={"status": status})


def set_public_status(
    session: Session, report: Report, public_status: str, *, actor: str
) -> None:
    """Only call from a triager action; never from the automatic pipeline."""
    report.public_status = public_status
    report.last_public_update_at = datetime.now(UTC)
    audit.record(session, actor=actor, action="set_public_status", report_id=report.id,
                 detail={"public_status": public_status})
    try:
        from ..notify import get_notifier, status_change_message

        get_notifier().notify(
            status_change_message(report.id, public_status, actor), report_id=report.id
        )
    except Exception:  # noqa: BLE001 - notifications must never break a decision
        pass


def add_message(
    session: Session,
    report: Report,
    *,
    body: str,
    direction: str,
    sent_by: str,
    attachments: list[dict] | None = None,
    visible_to_researcher: bool = True,
) -> Message:
    message = Message(
        report_id=report.id,
        direction=direction,
        body=body,
        attachments=attachments or [],
        sent_by=sent_by,
        visible_to_researcher=visible_to_researcher,
    )
    session.add(message)
    if direction == MessageDirection.TO_RESEARCHER.value:
        report.last_public_update_at = datetime.now(UTC)
    audit.record(
        session,
        actor=sent_by,
        action="message",
        report_id=report.id,
        detail={"direction": direction},
    )
    return message


def record_decision(
    session: Session,
    report: Report,
    *,
    decision: str,
    actor: str,
    detail: dict | None = None,
) -> None:
    triage = session.scalar(select(TriageResult).where(TriageResult.report_id == report.id))
    if triage is None:
        triage = TriageResult(report_id=report.id)
        session.add(triage)
    triage.final_decision = decision
    triage.decided_by = actor
    triage.decided_at = datetime.now(UTC)
    audit.record(session, actor=actor, action=f"decision:{decision}", report_id=report.id,
                 detail=detail or {})


def revoke_token(session: Session, report: Report, *, actor: str) -> None:
    report.status_token_revoked = True
    audit.record(session, actor=actor, action=Decision.REVOKE_TOKEN.value, report_id=report.id)


def run_pipeline_for_report(
    session: Session,
    report: Report,
    program: ProgramConfig,
    *,
    settings: Settings | None = None,
) -> PipelineRunSummary:
    """Run the DeSlop pipeline for a report and persist the outcome.

    Persists the locked ReproPlan, the ReproRun (with evidence), and the
    TriageResult (routing category, injection flag, duplicate candidates). The
    report's internal status is updated; the public status is NOT touched (only a
    triager changes that).
    """
    from ..config.settings import get_settings as _get_settings
    from ..db.models import DuplicateCandidate, ReproPlan, ReproRun, TriageResult
    from ..dedup.detector import NormalizedReport
    from ..llm.embeddings import HashingEmbedder
    from ..pipeline.orchestrator import Pipeline

    settings = settings or _get_settings()

    # --- Duplicate corpus: embed the new report and load prior embeddings ---
    embedder = HashingEmbedder(settings.embedding_dim)
    summary = f"{report.title} {report.vuln_class or ''} {report.endpoint or ''}".strip()
    if report.embedding is None:
        report.embedding = embedder.embed([summary])[0]
    corpus: list[NormalizedReport] = []
    stmt = select(Report).where(
        Report.program_id == report.program_id,
        Report.id != report.id,
    )
    for other in session.scalars(stmt):
        if other.embedding is None:
            other_summary = (
                f"{other.title} {other.vuln_class or ''} {other.endpoint or ''}".strip()
            )
            other.embedding = embedder.embed([other_summary])[0]
            other.root_cause_summary = other_summary
        corpus.append(
            NormalizedReport(
                report_id=other.id,
                asset=other.asset,
                endpoint=other.endpoint,
                vuln_class=other.vuln_class,
                root_cause_summary=other.root_cause_summary or "",
                embedding=list(other.embedding),
            )
        )

    pipeline = Pipeline(program, settings=settings, duplicate_corpus=corpus)
    # Include any raw HTTP request / HAR evidence in the text the parser sees, so
    # a report whose steps are expressed as a raw request reproduces offline.
    parse_text = report.body
    evidence_blobs: list[str] = []
    for att in report.attachments or []:
        content = att.get("content")
        if content:
            evidence_blobs.append(content)
            parse_text += "\n\n```http\n" + content.strip() + "\n```\n"
    result = pipeline.run(
        title=report.title,
        body=parse_text,
        asset=report.asset,
        endpoint=report.endpoint,
        vuln_class=report.vuln_class,
        run_id=report.id,
        production_approved=bool(report.production_approved),
        evidence_blobs=evidence_blobs,
    )

    report.status = result.status
    report.root_cause_summary = summary

    # Persist the parsed plan (if any). A re-run (e.g. after an
    # approve_production decision) stores a new plan version.
    plan_row = None
    if result.parse and result.parse.plan is not None:
        plan = result.parse.plan
        existing_versions = [
            p.version for p in session.scalars(
                select(ReproPlan).where(ReproPlan.report_id == report.id)
            )
        ]
        plan_row = ReproPlan(
            report_id=report.id,
            version=(max(existing_versions) + 1) if existing_versions else 1,
            bug_class=plan.bug_class,
            steps=[s.model_dump(mode="json") for s in plan.steps],
            substitutions=(
                [s.to_dict() for s in result.substitutions.substitutions]
                if result.substitutions
                else []
            ),
            parser_model="offline" if result.parse.used_fallback else settings.llm_model,
        )
        session.add(plan_row)
        session.flush()

    # Persist the execution + verifier evidence.
    if plan_row is not None and result.execution is not None:
        run = ReproRun(
            plan_id=plan_row.id,
            run_id=result.execution.run_id,
            status="passed"
            if (result.verification and result.verification.verdict.value == "proven")
            else "failed",
            verdict=result.verification.verdict.value if result.verification else None,
            failed_step_index=result.execution.failed_step_index,
            evidence=result.verification.evidence if result.verification else {},
            request_log=[r.to_dict() for r in result.execution.step_results],
            duration_ms=result.execution.duration_ms,
        )
        session.add(run)

    # Persist triage result.
    reasoning_parts = [
        result.routing.reason if result.routing else "",
        *result.notes,
        *result.evidence_gaps,
    ]
    triage = session.scalar(select(TriageResult).where(TriageResult.report_id == report.id))
    if triage is None:
        triage = TriageResult(report_id=report.id)
        session.add(triage)
    triage.routing_category = result.routing.category if result.routing else None
    triage.reasoning = "; ".join(p for p in reasoning_parts if p) or None
    triage.injection_flag = result.injection.flagged
    triage.injection_details = result.injection.to_dict().get("findings", [])
    triage.production_gate = result.production_gate
    triage.suggested_cvss = result.cvss
    triage.reply_draft = _draft_reply(program, result)

    for cand in result.duplicate_candidates:
        session.add(
            DuplicateCandidate(
                report_id=report.id,
                candidate_report_id=cand.report_id,
                similarity=cand.similarity,
                boosted_score=cand.boosted,
                verdict=cand.verdict,
                reasoning=cand.reasoning,
            )
        )

    audit.record(
        session,
        actor="pipeline",
        action=f"pipeline:{result.routing.category if result.routing else 'unknown'}",
        report_id=report.id,
        detail={"status": result.status},
    )

    # Best-effort notification for a newly triaged report.
    try:
        from ..notify import get_notifier, new_report_message

        get_notifier(settings).notify(
            new_report_message(
                report.title,
                report.id,
                result.routing.category if result.routing else None,
            ),
            report_id=report.id,
        )
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger("deslop.web").warning("notify failed: %s", exc)

    return PipelineRunSummary(
        report_id=report.id,
        status=result.status,
        routing_category=result.routing.category if result.routing else None,
        verdict=result.verification.verdict.value if result.verification else None,
    )


def process_report(
    report_id: str, program: ProgramConfig, *, settings: Settings | None = None
) -> bool:
    """Run the pipeline for a stored report in its own transaction.

    Used as a background task after intake and by ``deslop reprocess``. Never
    raises: on failure the transaction is rolled back and the report stays as
    it was (``received``). Returns whether the run completed.
    """
    try:
        with session_scope() as session:
            report = session.get(Report, report_id)
            if report is None:
                return False
            run_pipeline_for_report(session, report, program, settings=settings)
        return True
    except Exception:  # noqa: BLE001 - intake must not depend on the pipeline
        logging.getLogger("deslop.web").exception("pipeline run failed for %s", report_id)
        return False


def _draft_reply(program: ProgramConfig, result) -> str | None:  # noqa: ANN001
    """Draft the researcher reply for outcomes that need human follow-up.

    For ``needs_info`` the draft lists the missing fields and the evidence
    checklist items the report failed to demonstrate. Uses the program's reply
    template when configured.
    """
    if result.routing is None:
        return None
    if result.routing.category != "needs_info":
        return None
    questions: list[str] = []
    if result.parse and result.parse.missing_info:
        questions.extend(f"- Please provide: {m}" for m in result.parse.missing_info)
    questions.extend(f"- {gap}" for gap in result.evidence_gaps)
    if not questions:
        questions.append("- Please provide complete reproduction steps and raw evidence.")
    body = (program.replies.needs_info or "Thanks for the report. We need more information to reproduce it:")
    return body + "\n" + "\n".join(questions)


@dataclass
class PipelineRunSummary:
    report_id: str
    status: str
    routing_category: str | None
    verdict: str | None

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "status": self.status,
            "routing_category": self.routing_category,
            "verdict": self.verdict,
        }


def public_view(report: Report) -> dict:
    """The subset of report data allowed on the public status page.

    Deliberately excludes evidence packs, repro logs, internal routing status,
    CVSS reasoning, and other reports.
    """
    return {
        "id": report.id,
        "title": report.title,
        "submitted_at": report.submitted_at.isoformat() if report.submitted_at else None,
        "public_status": report.public_status,
        "last_update": report.last_public_update_at.isoformat()
        if report.last_public_update_at
        else None,
    }
