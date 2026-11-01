"""Demo scenario for DeSlop.

Feeds a mix of synthetic reports through the pipeline and prints the sorting
result with evidence.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .config.loader import ProgramRegistry
from .config.settings import Settings
from .dataset import generate_dataset
from .dedup.detector import NormalizedReport
from .llm.embeddings import HashingEmbedder
from .pipeline.orchestrator import Pipeline
from .recipes.bootstrap import register_recipes_for

_CATEGORY_ORDER = [
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


def _build_corpus(reports, settings: Settings) -> list[NormalizedReport]:
    """Embed valid reports so later paraphrases can be detected as duplicates."""
    embedder = HashingEmbedder(settings.embedding_dim)
    corpus: list[NormalizedReport] = []
    for r in reports:
        if r.label.value != "valid":
            continue
        summary = f"{r.title} {r.vuln_class or ''} {r.endpoint or ''}".strip()
        corpus.append(
            NormalizedReport(
                report_id=r.id,
                asset=r.asset,
                endpoint=r.endpoint,
                vuln_class=r.vuln_class,
                root_cause_summary=summary,
                embedding=embedder.embed([summary])[0],
            )
        )
    return corpus


def run_demo(
    config_dir: str | Path,
    settings: Settings,
    *,
    seed: int = 1337,
    per: int | None = None,
    program_id: str = "lab",
    max_reports: int | None = None,
) -> int:
    program = ProgramRegistry.from_dir(config_dir).get(program_id)
    try:
        register_recipes_for(program_id)
    except ImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if program_id == "dvwa":
        from lab.recipes.dvwa_recipes import build_dvwa_dataset

        reports = build_dvwa_dataset()
    else:
        reports = generate_dataset(seed=seed, per_category=per)
    if max_reports:
        reports = reports[:max_reports]

    corpus = _build_corpus(reports, settings)
    pipeline = Pipeline(program, settings=settings, duplicate_corpus=corpus)

    buckets: dict[str, list] = {}
    for r in reports:
        result = pipeline.run(
            title=r.title, body=r.body, asset=r.asset, endpoint=r.endpoint,
            vuln_class=r.vuln_class, run_id=r.id,
        )
        category = result.routing.category if result.routing else "needs_human_review"
        buckets.setdefault(category, []).append((r, result))

    print("=" * 78)
    print("DeSlop demo: sorting a mixed batch of reports")
    print("=" * 78)
    print(f"{len(reports)} reports in\n")
    for category in _CATEGORY_ORDER:
        items = buckets.get(category, [])
        if not items:
            continue
        print(f"[{category}]  ({len(items)})")
        for r, result in items:
            verdict = result.verification.verdict.value if result.verification else "-"
            evidence = ""
            if result.verification and result.verification.evidence:
                ev = result.verification.evidence
                if "marker" in ev:
                    evidence = f" marker={ev['marker']}"
                elif "hit_count" in ev:
                    evidence = f" oob_hits={ev['hit_count']}"
                elif "location" in ev:
                    evidence = f" location={ev['location']}"
            print(f"    - {r.id} [{r.label.value}] {r.title[:52]} (verdict={verdict}){evidence}")
        print()

    print("Legend: reproduced = proven by a verifier and queued for human review.")
    print("Nothing is auto-rejected; failed_replay is a low-priority human queue.")
    return 0
