"""Routing: map pipeline outcomes to internal statuses.

A routing status never rejects or closes a report on its own. Every category
still queues the report for a human, with ``failed_replay`` placed in a
low-priority queue.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..db.enums import RoutingCategory, Verdict
from ..recipes.registry import has_recipe

#: UI priority (higher = reviewed sooner). Used for dashboard sorting.
PRIORITY: dict[str, int] = {
    RoutingCategory.REPRODUCED.value: 100,
    RoutingCategory.REPRODUCED_WITH_DEVIATION.value: 95,
    RoutingCategory.NEEDS_INFO.value: 60,
    RoutingCategory.MANUAL_REPRODUCTION_REQUIRED.value: 50,
    RoutingCategory.DUPLICATE.value: 40,
    RoutingCategory.OUT_OF_SCOPE.value: 30,
    RoutingCategory.EXCLUDED_CLASS.value: 30,
    RoutingCategory.BLOCKED_BY_POLICY.value: 20,
    RoutingCategory.FAILED_REPLAY.value: 10,
    RoutingCategory.NEEDS_HUMAN_REVIEW.value: 70,
}


@dataclass
class RoutingDecision:
    category: str
    reason: str = ""

    @property
    def priority(self) -> int:
        return PRIORITY.get(self.category, 50)


def route_verdict(verdict: Verdict, *, deviation: bool = False, bug_class: str | None = None) -> RoutingDecision:
    if verdict == Verdict.PROVEN:
        if deviation:
            return RoutingDecision(
                RoutingCategory.REPRODUCED_WITH_DEVIATION.value,
                "proven after triager-approved deviations",
            )
        return RoutingDecision(RoutingCategory.REPRODUCED.value, "proven by a verifier")
    if verdict == Verdict.ERROR:
        return RoutingDecision(
            RoutingCategory.NEEDS_HUMAN_REVIEW.value, "verification could not complete"
        )
    return RoutingDecision(
        RoutingCategory.FAILED_REPLAY.value, "not proven at the reported step"
    )


def route_no_recipe(bug_class: str) -> RoutingDecision:
    return RoutingDecision(
        RoutingCategory.MANUAL_REPRODUCTION_REQUIRED.value,
        f"no recipe for bug class {bug_class!r}; manual reproduction required",
    )


def route_needs_info(missing: list[str]) -> RoutingDecision:
    detail = "; ".join(missing) if missing else "reproduction steps are incomplete"
    return RoutingDecision(RoutingCategory.NEEDS_INFO.value, detail)


def has_supported_recipe(bug_class: str) -> bool:
    return has_recipe(bug_class)
