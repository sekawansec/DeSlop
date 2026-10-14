"""Duplicate detection (normalization, retrieval, judgement)."""

from .detector import (
    Candidate,
    NormalizedReport,
    build_normalized,
    dedupe_stage,
    retrieve_candidates,
)
from .judge import classify_for_routing, judge_candidates

__all__ = [
    "Candidate",
    "NormalizedReport",
    "build_normalized",
    "classify_for_routing",
    "dedupe_stage",
    "judge_candidates",
    "retrieve_candidates",
]
