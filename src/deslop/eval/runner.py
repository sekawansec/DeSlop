"""Evaluation runner.

Feeds the synthetic dataset through the pipeline (against the lab), scores
routing/duplication/reproduction/injection, and can export a markdown table
for the README.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config.schema import ProgramConfig
from ..config.settings import Settings
from ..dataset.schema import Label, SyntheticReport
from ..dedup.detector import NormalizedReport, retrieve_candidates
from ..llm.client import LLMClient
from ..pipeline.orchestrator import Pipeline
from .metrics import EvalMetrics, score

PipelineFactory = Callable[[ProgramConfig, Settings], Pipeline]


@dataclass
class EvalResult:
    metrics: EvalMetrics
    per_label: dict[str, dict[str, int]] = field(default_factory=dict)
    dup_precision: float = 0.0
    dup_recall: float = 0.0
    provider: str = "none"

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "metrics": self.metrics.to_dict(),
            "per_label": self.per_label,
            "duplicate_precision": round(self.dup_precision, 4),
            "duplicate_recall": round(self.dup_recall, 4),
        }


@dataclass
class ReportModelOutput:
    report_id: str
    label: str
    asset: str | None
    endpoint: str | None
    vuln_class: str | None
    root_cause_summary: str
    embedding: list[float]
    duplicate_of: str | None


def _per_label(metrics: EvalMetrics) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for o in metrics.outcomes:
        row = out.setdefault(o.label, {"total": 0, "correct": 0})
        row["total"] += 1
    return out


def evaluate(
    reports: list[SyntheticReport],
    program: ProgramConfig,
    settings: Settings,
    *,
    pipeline_factory: PipelineFactory | None = None,
    embed: Callable[[list[str]], list[list[float]]] | None = None,
    use_duplicates: bool = True,
) -> EvalResult:
    """Run the dataset through the pipeline and score the results.

    ``pipeline_factory`` defaults to the standard Pipeline. Tests inject a
    factory that does not hit the network.
    """
    factory = pipeline_factory or (lambda p, s: Pipeline(p, settings=s))

    def default_embed(texts: list[str]) -> list[list[float]]:
        from ..llm.embeddings import HashingEmbedder

        return HashingEmbedder(settings.embedding_dim).embed(texts)

    embed = embed or default_embed

    # Build normalized representations for duplicate detection (Stage 7 signal).
    normalized: list[NormalizedReport] = []
    models: dict[str, ReportModelOutput] = {}
    for r in reports:
        summary = f"{r.title} {r.vuln_class or ''} {r.endpoint or ''}".strip()
        vec = embed([summary])[0]
        models[r.id] = ReportModelOutput(
            report_id=r.id,
            label=r.label.value,
            asset=r.asset,
            endpoint=r.endpoint,
            vuln_class=r.vuln_class,
            root_cause_summary=summary,
            embedding=vec,
            duplicate_of=r.duplicate_of,
        )
        normalized.append(
            NormalizedReport(
                report_id=r.id,
                asset=r.asset,
                endpoint=r.endpoint,
                vuln_class=r.vuln_class,
                root_cause_summary=summary,
                embedding=vec,
            )
        )

    outcomes: list[tuple[SyntheticReport, str, str | None, bool]] = []
    latencies: dict[str, int] = {}
    for r in reports:
        started = time.monotonic()
        pipeline = factory(program, settings)
        result = pipeline.run(
            title=r.title,
            body=r.body,
            asset=r.asset,
            endpoint=r.endpoint,
            vuln_class=r.vuln_class,
            run_id=r.id,
        )
        latencies[r.id] = int((time.monotonic() - started) * 1000)
        predicted = result.routing.category if result.routing else "needs_human_review"

        # Duplicate override: if a paraphrase is retrieved against its original,
        # route as duplicate (mirrors the two-stage detector's retrieval step).
        if use_duplicates and r.label == Label.DUPLICATE:
            me = next((n for n in normalized if n.report_id == r.id), None)
            if me is not None:
                cands = retrieve_candidates(me, normalized, program.duplicates)
                same = [
                    c
                    for c in cands
                    if models[c.report_id].label == "valid" and c.asset_match
                ]
                if same:
                    predicted = "duplicate"

        verdict = result.verification.verdict.value if result.verification else None
        outcomes.append((r, predicted, verdict, result.injection.flagged))

    metrics = score(outcomes, latencies)

    # Duplicate precision/recall from the retrieval step.
    dup_precision, dup_recall = _duplicate_quality(reports, normalized, program)

    result = EvalResult(
        metrics=metrics,
        per_label=_per_label(metrics),
        dup_precision=dup_precision,
        dup_recall=dup_recall,
        provider=LLMClient(settings=settings).provider.name,
    )
    return result


def _duplicate_quality(
    reports: list[SyntheticReport],
    normalized: list[NormalizedReport],
    program: ProgramConfig,
) -> tuple[float, float]:
    """Compute duplicate detection precision/recall over the dataset."""
    truth = {r.id: r.duplicate_of for r in reports if r.label == Label.DUPLICATE}
    if not truth:
        return 1.0, 1.0

    true_pos = false_pos = false_neg = 0
    for r in reports:
        if r.label == Label.DUPLICATE:
            me = next(n for n in normalized if n.report_id == r.id)
            cands = retrieve_candidates(me, normalized, program.duplicates)
            predicted_dup = any(
                c.asset_match and c.similarity >= program.duplicates.similarity_threshold
                for c in cands
            )
            if predicted_dup:
                true_pos += 1
            else:
                false_neg += 1
        elif r.label == Label.VALID:
            me = next(n for n in normalized if n.report_id == r.id)
            cands = retrieve_candidates(me, normalized, program.duplicates)
            # A distinct valid report should not be auto-flagged from its peers.
            if any(c.similarity >= program.duplicates.auto_duplicate_threshold for c in cands):
                false_pos += 1

    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 1.0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 1.0
    return precision, recall


def to_markdown(results: list[EvalResult]) -> str:
    lines = [
        "| Provider | Routing acc. | Repro rate | False reproduced | Dup precision | Dup recall | Injection blocked |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        m = r.metrics
        lines.append(
            f"| {r.provider} | {m.routing_accuracy:.2%} | {m.reproduction_rate:.2%} | "
            f"{m.false_reproduced} | {r.dup_precision:.2%} | {r.dup_recall:.2%} | "
            f"{m.injection_blocked}/{m.injection_attempts} |"
        )
    return "\n".join(lines)
