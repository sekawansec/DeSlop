"""Two-stage duplicate detection.

1. Normalization   - extract asset/endpoint/param/CWE/root-cause summary.
2. Retrieval        - top-N candidates by vector similarity on the root cause,
                     boosted when asset and endpoint match.
3. Judgement        - classify each candidate (same_root_cause /
                     same_asset_different_bug / unrelated).

String matching alone is deliberately avoided: AI-written reports describe the
same bug in different words.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config.schema import DuplicateRules, ProgramConfig
from ..llm.embeddings import cosine


@dataclass
class NormalizedReport:
    report_id: str
    asset: str | None
    endpoint: str | None
    vuln_class: str | None
    root_cause_summary: str
    embedding: list[float] = field(default_factory=list)


@dataclass
class Candidate:
    report_id: str
    similarity: float
    boosted: float
    asset_match: bool = False
    endpoint_match: bool = False
    verdict: str | None = None
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "candidate_report_id": self.report_id,
            "similarity": round(self.similarity, 4),
            "boosted_score": round(self.boosted, 4),
            "asset_match": self.asset_match,
            "endpoint_match": self.endpoint_match,
            "verdict": self.verdict,
            "reasoning": self.reasoning,
        }


def retrieve_candidates(
    target: NormalizedReport,
    corpus: list[NormalizedReport],
    rules: DuplicateRules,
) -> list[Candidate]:
    """Vector similarity plus asset/endpoint boost."""
    scored: list[Candidate] = []
    for other in corpus:
        if other.report_id == target.report_id:
            continue
        sim = cosine(target.embedding, other.embedding)
        asset_match = bool(target.asset and other.asset and target.asset == other.asset)
        endpoint_match = bool(
            target.endpoint and other.endpoint and target.endpoint == other.endpoint
        )
        boosted = sim
        if asset_match:
            boosted += rules.same_asset_boost
        if endpoint_match:
            boosted += rules.same_endpoint_boost
        scored.append(
            Candidate(
                report_id=other.report_id,
                similarity=sim,
                boosted=boosted,
                asset_match=asset_match,
                endpoint_match=endpoint_match,
            )
        )
    scored.sort(key=lambda c: c.boosted, reverse=True)
    return [c for c in scored if c.similarity >= rules.similarity_threshold][
        : rules.candidate_count
    ]


def dedupe_stage(
    target: NormalizedReport,
    corpus: list[NormalizedReport],
    program: ProgramConfig,
    corpus_lookup: dict[str, NormalizedReport] | None = None,
) -> list[Candidate]:
    """Stages 1-3 without the LLM judgement (retrieval only)."""
    return retrieve_candidates(target, corpus, program.duplicates)


def build_normalized(
    report_id: str,
    *,
    asset: str | None,
    endpoint: str | None,
    vuln_class: str | None,
    root_cause_summary: str,
    embedding: list[float],
) -> NormalizedReport:
    return NormalizedReport(
        report_id=report_id,
        asset=asset,
        endpoint=endpoint,
        vuln_class=vuln_class,
        root_cause_summary=root_cause_summary,
        embedding=embedding,
    )
