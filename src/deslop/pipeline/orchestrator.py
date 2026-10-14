"""Pipeline orchestration: intake -> filter -> parse -> validate -> execute -> verify -> route.

The orchestrator is provider-agnostic and executor-agnostic. It uses:
- deterministic filters (scope, excluded class, injection)
- the LLM parser (or the offline fallback)
- the deterministic validator
- an executor + a recipe verifier

Every outcome still queues the report for a human; nothing is auto-rejected.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from ..config.schema import ProgramConfig
from ..config.settings import Settings, get_settings
from ..db.enums import ReportStatus, RoutingCategory
from ..dedup.detector import NormalizedReport, retrieve_candidates
from ..dedup.judge import classify_for_routing, judge_candidates
from ..llm.client import LLMClient
from ..parser.step_parser import ParseOutcome, StepParser, canonical_bug_class
from ..recipes.registry import get_recipe
from ..repro.executor import WebExecutor
from ..repro.interfaces import ExecutionResult, VerificationResult
from ..repro.scope import check_scope
from ..repro.substitution import SubstitutionResult, apply_substitutions
from ..repro.validator import ValidationResult, validate_plan
from ..security.injection import InjectionReport, detect_injection
from .filters import FilterDecision, check_excluded_class, check_scope_for_report
from .routing import RoutingDecision, route_needs_info, route_no_recipe, route_verdict


@dataclass
class PipelineResult:
    run_id: str
    status: str
    routing: RoutingDecision | None = None
    injection: InjectionReport = field(default_factory=InjectionReport)
    scope: FilterDecision | None = None
    excluded: FilterDecision | None = None
    parse: ParseOutcome | None = None
    validation: ValidationResult | None = None
    substitutions: SubstitutionResult | None = None
    execution: ExecutionResult | None = None
    verification: VerificationResult | None = None
    duplicate_candidates: list = field(default_factory=list)
    cvss: dict | None = None
    notes: list[str] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    production_gate: bool = False

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "routing": {"category": self.routing.category, "reason": self.routing.reason},
            "injection": self.injection.to_dict(),
            "scope": self.scope.__dict__ if self.scope else None,
            "excluded": self.excluded.__dict__ if self.excluded else None,
            "steps": len(self.parse.plan.steps) if (self.parse and self.parse.plan) else 0,
            "validation_approved": self.validation.approved if self.validation else None,
            "verdict": self.verification.verdict.value if self.verification else None,
            "cvss": self.cvss,
            "notes": self.notes,
            "evidence_gaps": self.evidence_gaps,
            "production_gate": self.production_gate,
        }


class Pipeline:
    def __init__(
        self,
        program: ProgramConfig,
        *,
        settings: Settings | None = None,
        parser: StepParser | None = None,
        executor: WebExecutor | None = None,
        client: LLMClient | None = None,
        duplicate_corpus: list[NormalizedReport] | None = None,
    ) -> None:
        self.program = program
        self.settings = settings or get_settings()
        self.client = client or LLMClient(settings=self.settings)
        self.parser = parser or StepParser(client=self.client, settings=self.settings)
        self.executor = executor or WebExecutor(self.settings)
        self.duplicate_corpus = duplicate_corpus or []

    def _reset_staging(self, result: PipelineResult) -> None:
        """Call the program's configured staging reset endpoint, if any."""
        reset = self.program.staging.reset
        if reset is None or not reset.url:
            return
        import httpx

        try:
            headers = {reset.auth_header: "deslop"} if reset.auth_header else {}
            with httpx.Client(timeout=10.0) as client:
                r = client.request(reset.method, reset.url, headers=headers)
            if r.status_code >= 400:
                result.notes.append(f"staging reset returned HTTP {r.status_code}")
        except httpx.HTTPError as exc:
            result.notes.append(f"staging reset failed: {type(exc).__name__}")

    def _duplicate_check(self, result, plan):  # noqa: ANN001
        """Run retrieval + judgement against the corpus; True if duplicate.

        Candidates found by the earlier metadata check are kept — this check
        uses a plan-derived summary and only *adds* candidates, never removes
        the ones already surfaced to the triager.
        """
        if not self.duplicate_corpus:
            return False
        from ..llm.embeddings import HashingEmbedder

        summary = plan.bug_class
        if plan.steps:
            summary = f"{plan.bug_class} {plan.steps[0].request.url}"
        vec = HashingEmbedder(self.settings.embedding_dim).embed([summary])[0]
        target = NormalizedReport(
            report_id=result.run_id,
            asset=None,
            endpoint=None,
            vuln_class=plan.bug_class,
            root_cause_summary=summary,
            embedding=vec,
        )
        candidates = retrieve_candidates(target, self.duplicate_corpus, self.program.duplicates)
        lookup = {n.report_id: n for n in self.duplicate_corpus}
        judge_candidates(target, candidates, lookup, self.program, self.client)
        seen = {c.report_id for c in result.duplicate_candidates}
        result.duplicate_candidates.extend(c for c in candidates if c.report_id not in seen)
        category, reason = classify_for_routing(result.duplicate_candidates)
        if category == "duplicate":
            result.routing = RoutingDecision(category, reason)
            result.status = ReportStatus.DUPLICATE.value
            return True
        return False

    def _duplicate_by_metadata(self, result, *, title, asset, endpoint, vuln_class):  # noqa: ANN001
        """Duplicate detection using intake metadata, before parsing."""
        from ..llm.embeddings import HashingEmbedder

        summary = f"{title} {vuln_class or ''} {endpoint or ''}".strip()
        vec = HashingEmbedder(self.settings.embedding_dim).embed([summary])[0]
        target = NormalizedReport(
            report_id=result.run_id,
            asset=asset,
            endpoint=endpoint,
            vuln_class=vuln_class,
            root_cause_summary=summary,
            embedding=vec,
        )
        candidates = retrieve_candidates(target, self.duplicate_corpus, self.program.duplicates)
        lookup = {n.report_id: n for n in self.duplicate_corpus}
        judge_candidates(target, candidates, lookup, self.program, self.client)
        result.duplicate_candidates = candidates
        category, reason = classify_for_routing(candidates)
        if category == "duplicate":
            result.routing = RoutingDecision(category, reason)
            result.status = ReportStatus.DUPLICATE.value
            return True
        return False

    def run(
        self,
        *,
        title: str,
        body: str,
        asset: str | None = None,
        endpoint: str | None = None,
        vuln_class: str | None = None,
        run_id: str | None = None,
        production_approved: bool = False,
        evidence_blobs: list[str] | None = None,
    ) -> PipelineResult:
        run_id = run_id or uuid.uuid4().hex
        result = PipelineResult(run_id=run_id, status=ReportStatus.FILTERING.value)

        # 1. Injection detection (deterministic). Instructions to fetch an
        # in-scope host are normal reproduction steps, not injection.
        result.injection = detect_injection(
            body,
            extra_hosts=_out_of_scope_hosts(self.program),
            in_scope=lambda h: check_scope(h, self.program).allowed,
        )

        # 2. Scope check.
        result.scope = check_scope_for_report(asset, endpoint, self.program)
        if not result.scope.passed:
            result.routing = RoutingDecision(result.scope.category, result.scope.reason)
            result.status = ReportStatus.OUT_OF_SCOPE.value
            return result

        # 3. Excluded bug class.
        result.excluded = check_excluded_class(vuln_class, self.program)
        if not result.excluded.passed:
            result.routing = RoutingDecision(result.excluded.category, result.excluded.reason)
            result.status = ReportStatus.EXCLUDED_CLASS.value
            return result

        # 3b. Evidence checklist: deterministic per-class gaps become reviewer
        #     notes and needs_info questions — never an auto-reject.
        from ..intake.evidence import evidence_gaps as _evidence_gaps

        canon_declared = canonical_bug_class(vuln_class)
        blob = body + "\n" + "\n".join(evidence_blobs or [])
        result.evidence_gaps = [
            g.question
            for g in _evidence_gaps(
                canon_declared, blob, program_requirements=self.program.evidence_requirements
            )
        ]

        # 4. Prompt injection -> blocked_by_policy (human decides).
        if result.injection.flagged:
            result.routing = RoutingDecision(
                RoutingCategory.BLOCKED_BY_POLICY.value,
                "possible prompt injection detected; human review required",
            )
            result.status = ReportStatus.BLOCKED_BY_POLICY.value
            return result

        # 4b. Duplicate detection before parsing, using the declared metadata.
        if self.duplicate_corpus and self._duplicate_by_metadata(
            result, title=title, asset=asset, endpoint=endpoint, vuln_class=vuln_class
        ):
            return result

        # 5. Parse into a locked plan.
        result.status = ReportStatus.PARSING.value
        result.parse = self.parser.parse(body, account_hints=_account_hints(self.program))
        if not result.parse.ok or result.parse.plan is None:
            result.routing = route_needs_info(result.parse.missing_info)
            result.status = ReportStatus.NEEDS_INFO.value
            result.notes.append(result.parse.error or "could not parse steps")
            return result
        plan = result.parse.plan

        # If the parser could not infer the class but the researcher declared a
        # supported one at intake, use it (deterministic, no guessing of steps).
        if plan.bug_class == "unknown" and vuln_class:
            hinted = canonical_bug_class(vuln_class)
            if get_recipe(hinted) is not None:
                plan = plan.model_copy(update={"bug_class": hinted})
                result.parse.plan = plan

        # 5b. Duplicate detection (retrieval + judgement).
        if self._duplicate_check(result, plan):
            return result

        # 6. Recipe availability.
        recipe = get_recipe(plan.bug_class)
        if recipe is None:
            result.routing = route_no_recipe(plan.bug_class)
            result.status = ReportStatus.MANUAL_REPRODUCTION_REQUIRED.value
            return result

        # 7. Deterministic policy validation.
        result.status = ReportStatus.VALIDATING.value
        result.validation = validate_plan(plan, self.program, self.settings)
        if not result.validation.approved:
            result.routing = RoutingDecision(
                RoutingCategory.BLOCKED_BY_POLICY.value, result.validation.summary()
            )
            result.status = ReportStatus.BLOCKED_BY_POLICY.value
            return result

        # 8. Recipe state setup: per-run tokens (SSRF), ownership markers (IDOR),
        #    and any program-side seeding the recipe needs. Runs before
        #    substitution so generated tokens can be embedded into the plan.
        setup_data: dict = {}
        try:
            setup = recipe.setup(self.program, run_id=run_id)
            setup_data = dict(setup.data or {})
            if not setup.ok:
                result.notes.append(f"recipe setup reported: {setup.detail}")
        except Exception as exc:  # noqa: BLE001 - setup failure is not fatal
            result.notes.append(f"recipe setup failed: {type(exc).__name__}: {exc}")

        # Canary check: for bug classes where a planted canary is the expected
        # proof, note when the report never mentions it (the verifier still
        # checks responses; this flag is for the human reviewer).
        canary = self.program.canary
        if canary and canary.enabled and canary.token:
            setup_data.setdefault("canary", canary.token)
            if plan.bug_class in canary.required_for and canary.token not in body:
                for blob in evidence_blobs or []:
                    if canary.token in blob:
                        break
                else:
                    result.notes.append(
                        "report does not contain the program canary token required "
                        f"for {plan.bug_class!r} claims"
                    )

        # 9. Substitutions (host rewrites + credential/dynamic recording + OOB
        #    token embedding).
        result.substitutions = apply_substitutions(
            plan,
            self.program,
            oob_base_url=self.settings.oob_base_url,
            run_token=setup_data.get("run_token"),
        )
        exec_plan = plan.model_copy(update={"steps": result.substitutions.steps})

        # 10. Egress gate: every post-substitution step host must be reachable
        #     by sandbox policy. In-scope production hosts require explicit
        #     approval (settings.allow_production, program.allow_production, or
        #     a per-report approve_production decision).
        from ..sandbox.policy import build_egress_policy, host_of

        approved = (
            production_approved or self.settings.allow_production or self.program.allow_production
        )
        egress = build_egress_policy(
            self.program, self.settings.oob_base_url, production_approved=approved
        )
        denied_hosts = sorted(
            {host_of(s.request.url) for s in exec_plan.steps if not egress.permits(host_of(s.request.url))}
            - {""}
        )
        if denied_hosts:
            if any(egress.is_production(h) for h in denied_hosts):
                result.production_gate = True
                result.routing = RoutingDecision(
                    RoutingCategory.NEEDS_HUMAN_REVIEW.value,
                    "plan targets production host(s) "
                    f"{', '.join(denied_hosts)}; reproduction requires an "
                    "approve_production decision",
                )
            else:
                result.routing = RoutingDecision(
                    RoutingCategory.BLOCKED_BY_POLICY.value,
                    f"egress denied to host(s): {', '.join(denied_hosts)}",
                )
                result.status = ReportStatus.BLOCKED_BY_POLICY.value
                return result
            result.status = ReportStatus.NEEDS_HUMAN_REVIEW.value
            return result

        # 11. Optional staging reset so the run starts from a clean state.
        self._reset_staging(result)

        # 12. Execute.
        result.status = ReportStatus.REPRODUCING.value
        result.execution = self.executor.execute(
            exec_plan, self.program, run_id=run_id, egress=egress
        )

        # 13. Verify with the recipe's deterministic verifier.
        result.status = ReportStatus.VERIFYING.value
        result.verification = recipe.verify(
            exec_plan, result.execution, self.program, setup_data=setup_data
        )

        # 14. Route.
        result.routing = route_verdict(
            result.verification.verdict, bug_class=plan.bug_class
        )
        result.status = _status_for(result.routing.category)
        if not result.execution.completed:
            result.notes.append(result.execution.error or "execution did not complete")

        # Deterministic CVSS v3.1 second opinion (independent of any LLM).
        result.cvss = _suggest_cvss(body, plan.bug_class, result.verification)
        return result


def _suggest_cvss(body: str, bug_class: str, verification) -> dict | None:  # noqa: ANN001
    """Compute a provisional CVSS v3.1 base score from the report and verdict."""
    from ..cvss import compute_base, vector_from_text

    try:
        metrics = vector_from_text(body)
        # Bias the metrics by bug class where the impact is well understood, so a
        # proven high-impact bug does not score 0 just because the prose was terse.
        if bug_class in {"idor", "ssrf"}:
            metrics.AV = "N"
            metrics.C = "H"
        elif bug_class in {"xss_reflected", "xss_stored"}:
            metrics.AV = "N"
            metrics.UI = "R"
            metrics.C = "L"
            metrics.I = "L"
        elif bug_class == "open_redirect":
            metrics.AV = "N"
            metrics.UI = "R"
        elif bug_class == "command_injection":
            metrics.AV = "N"
            metrics.C = "H"
            metrics.I = "H"
            metrics.A = "H"
        result = compute_base(metrics)
        payload = result.to_dict()
        payload["source"] = "deterministic"
        payload["proven"] = bool(verification and verification.verdict.value == "proven")
        return payload
    except Exception:  # noqa: BLE001 - CVSS is a suggestion, never fatal
        return None


def _status_for(category: str) -> str:
    mapping = {
        RoutingCategory.REPRODUCED.value: ReportStatus.REPRODUCED.value,
        RoutingCategory.REPRODUCED_WITH_DEVIATION.value: ReportStatus.REPRODUCED_WITH_DEVIATION.value,
        RoutingCategory.NEEDS_INFO.value: ReportStatus.NEEDS_INFO.value,
        RoutingCategory.FAILED_REPLAY.value: ReportStatus.FAILED_REPLAY.value,
        RoutingCategory.MANUAL_REPRODUCTION_REQUIRED.value: ReportStatus.MANUAL_REPRODUCTION_REQUIRED.value,
        RoutingCategory.OUT_OF_SCOPE.value: ReportStatus.OUT_OF_SCOPE.value,
        RoutingCategory.EXCLUDED_CLASS.value: ReportStatus.EXCLUDED_CLASS.value,
        RoutingCategory.DUPLICATE.value: ReportStatus.DUPLICATE.value,
        RoutingCategory.BLOCKED_BY_POLICY.value: ReportStatus.BLOCKED_BY_POLICY.value,
        RoutingCategory.NEEDS_HUMAN_REVIEW.value: ReportStatus.NEEDS_HUMAN_REVIEW.value,
    }
    return mapping.get(category, ReportStatus.NEEDS_HUMAN_REVIEW.value)


def _account_hints(program: ProgramConfig) -> dict[str, str]:
    hints: dict[str, str] = {}
    for acct in program.test_accounts:
        hints[acct.username] = acct.id
        hints[acct.id] = acct.id
    return hints


def _out_of_scope_hosts(program: ProgramConfig) -> list[str]:
    hosts: list[str] = []
    for entry in program.out_of_scope:
        value = entry.value
        if value.startswith("*."):
            value = value[2:]
        hosts.append(value)
    return hosts
