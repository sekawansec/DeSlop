"""Retest: re-run a stored reproduction plan after a fix.

The report is re-executed with the same locked plan and verifier. The result is
either still-reproducible or no-longer-proven. If a triager confirms the fix,
the public status can be set to 'fixed'.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config.schema import ProgramConfig
from ..config.settings import Settings, get_settings
from ..db.enums import ReproRunStatus, Verdict
from ..db.models import Report, ReproPlan, ReproRun
from ..recipes.registry import get_recipe
from ..repro.executor import WebExecutor
from ..repro.steps import ReproPlanModel, ReproStep, SourceRef, StepExpectation, StructuredRequest


@dataclass
class RetestResult:
    report_id: str
    still_reproducible: bool
    verdict: str
    run_id: str
    evidence: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "still_reproducible": self.still_reproducible,
            "verdict": self.verdict,
            "run_id": self.run_id,
            "evidence": self.evidence,
            "notes": self.notes,
        }


def _plan_from_row(row: ReproPlan, bug_class: str) -> ReproPlanModel:
    steps: list[ReproStep] = []
    for i, s in enumerate(row.steps or []):
        req = s.get("request", {})
        source = None
        if s.get("source"):
            source = SourceRef.model_validate(s["source"])
        expectation = None
        if s.get("expectation"):
            expectation = StepExpectation.model_validate(s["expectation"])
        steps.append(
            ReproStep(
                index=s.get("index", i),
                description=s.get("description", ""),
                request=StructuredRequest.model_validate(req),
                source=source,
                expectation=expectation,
                as_account=s.get("as_account"),
            )
        )
    return ReproPlanModel(bug_class=bug_class, steps=steps)


def retest_report(
    session: Session,
    report_id: str,
    program: ProgramConfig,
    *,
    settings: Settings | None = None,
    executor: WebExecutor | None = None,
    bug_class: str | None = None,
    run_id: str | None = None,
) -> RetestResult:
    settings = settings or get_settings()
    report = session.get(Report, report_id)
    if report is None:
        raise ValueError(f"report {report_id!r} not found")

    plan_row = session.scalars(
        select(ReproPlan).where(ReproPlan.report_id == report_id).order_by(ReproPlan.version.desc())
    ).first()
    if plan_row is None:
        raise ValueError(f"report {report_id!r} has no stored reproduction plan")

    effective_bug_class = bug_class or report.vuln_class or "unknown"
    plan = _plan_from_row(plan_row, effective_bug_class)

    recipe = get_recipe(plan.bug_class)
    executor = executor or WebExecutor(settings)
    execution = executor.execute(plan, program, run_id=run_id)

    verdict = Verdict.INCONCLUSIVE
    evidence: dict = {}
    if recipe is not None:
        verification = recipe.verify(plan, execution, program)
        verdict = verification.verdict
        evidence = verification.evidence

    run = ReproRun(
        plan_id=plan_row.id,
        run_id=execution.run_id,
        status=ReproRunStatus.PASSED.value
        if verdict == Verdict.PROVEN
        else ReproRunStatus.FAILED.value,
        verdict=verdict.value,
        failed_step_index=execution.failed_step_index,
        evidence=evidence,
        request_log=[r.to_dict() for r in execution.step_results],
        duration_ms=execution.duration_ms,
    )
    session.add(run)
    session.flush()

    return RetestResult(
        report_id=report_id,
        still_reproducible=verdict == Verdict.PROVEN,
        verdict=verdict.value,
        run_id=execution.run_id,
        evidence=evidence,
        notes=[execution.error] if execution.error else [],
    )
