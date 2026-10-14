"""Evaluation harness for DeSlop."""

from .metrics import EvalMetrics, ReportOutcome, expected_category, score
from .runner import EvalResult, evaluate, to_markdown

__all__ = [
    "EvalMetrics",
    "EvalResult",
    "ReportOutcome",
    "evaluate",
    "expected_category",
    "score",
    "to_markdown",
]
