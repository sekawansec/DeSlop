"""Duplicate detection: LLM judgement of retrieved candidates.

Each candidate is presented in condensed form and classified as
same_root_cause / same_asset_different_bug / unrelated. When no LLM is
available, a deterministic fallback classifies by asset/endpoint/class overlap
so the pipeline still produces a usable (if weaker) signal.
"""

from __future__ import annotations

from ..config.schema import ProgramConfig
from ..llm.client import LLMClient
from ..llm.prompts import DUPLICATE_SYSTEM, DUPLICATE_TEMPLATE, render, wrap_untrusted
from ..llm.schemas import DuplicateJudgements
from .detector import Candidate, NormalizedReport


def _condense(report: NormalizedReport) -> str:
    return (
        f"- id: {report.report_id}\n"
        f"  asset: {report.asset or 'unknown'}\n"
        f"  endpoint: {report.endpoint or 'unknown'}\n"
        f"  class: {report.vuln_class or 'unknown'}\n"
        f"  root cause: {report.root_cause_summary[:300]}"
    )


def judge_candidates(
    target: NormalizedReport,
    candidates: list[Candidate],
    corpus_lookup: dict[str, NormalizedReport],
    program: ProgramConfig,
    client: LLMClient | None = None,
) -> list[Candidate]:
    """Classify each candidate. Mutates and returns the candidate list."""
    if not candidates:
        return candidates

    if client is not None and client.available:
        report_text = (
            f"asset: {target.asset or 'unknown'}\n"
            f"endpoint: {target.endpoint or 'unknown'}\n"
            f"class: {target.vuln_class or 'unknown'}\n"
            f"root cause: {target.root_cause_summary}"
        )
        candidate_text = "\n".join(
            _condense(corpus_lookup[c.report_id]) for c in candidates if c.report_id in corpus_lookup
        )
        result = client.complete_validated(
            system=DUPLICATE_SYSTEM,
            user=render(
                DUPLICATE_TEMPLATE,
                report=wrap_untrusted(report_text),
                candidates=wrap_untrusted(candidate_text),
            ),
            schema=DuplicateJudgements,
        )
        if result.ok and isinstance(result.value, DuplicateJudgements):
            for cand, judgement in zip(candidates, result.value.judgements, strict=False):
                cand.verdict = judgement.verdict
                cand.reasoning = judgement.reasoning
            return candidates

    # Deterministic fallback.
    for cand in candidates:
        other = corpus_lookup.get(cand.report_id)
        if other is None:
            cand.verdict = "unrelated"
            continue
        same_class = bool(target.vuln_class and target.vuln_class == other.vuln_class)
        if cand.asset_match and cand.endpoint_match and same_class:
            cand.verdict = "same_root_cause"
            cand.reasoning = "same asset, endpoint, and bug class"
        elif cand.asset_match and same_class:
            # Same class on a different endpoint: surfaced for a human, not
            # auto-marked as a duplicate.
            cand.verdict = "same_asset_different_bug"
            cand.reasoning = "same asset and bug class but a different endpoint"
        elif cand.asset_match:
            cand.verdict = "same_asset_different_bug"
            cand.reasoning = "same asset but different bug class"
        else:
            cand.verdict = "unrelated"
            cand.reasoning = "different asset"
    return candidates


def classify_for_routing(candidates: list[Candidate]) -> tuple[str, str]:
    """Return (routing_category_or_empty, reason) based on candidate verdicts."""
    same = [c for c in candidates if c.verdict == "same_root_cause"]
    if same:
        best = same[0]
        return "duplicate", f"same root cause as {best.report_id} ({best.reasoning})"
    return "", ""
