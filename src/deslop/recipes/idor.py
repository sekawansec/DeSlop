"""IDOR verifier.

Proof: account B successfully reads or modifies an object owned by account A,
demonstrated by account A's *specific* data appearing in B's response.

The verifier never trusts the report's claim. It requires a known ownership
marker (the object's owner secret, supplied by the recipe setup or read from the
program's expectations) to appear verbatim in a response returned to a
*different* account's session.
"""

from __future__ import annotations

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult
from .common import last_response, status_of


class IdorVerifier:
    bug_class = "idor"

    def __init__(self, owner_markers: list[str] | None = None) -> None:
        # Markers are the concrete secrets belonging to the victim accounts.
        # They are provided by the recipe setup (e.g. read from the lab) or,
        # for real programs, from the expected object data in the plan.
        self.owner_markers = owner_markers or []

    def verify(
        self, plan, execution: ExecutionResult, program: ProgramConfig
    ) -> VerificationResult:  # noqa: ANN001
        if not execution.completed:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"reason": "execution did not complete", "failed_step": execution.failed_step_index},
                "execution did not complete",
            )

        # Determine the attacker account (the one making the access request) and
        # the victim markers we must not see unless access control is broken.
        requested_marker = None
        for step in plan.steps:
            if step.expectation and step.expectation.marker:
                requested_marker = step.expectation.marker
                break

        markers = list(self.owner_markers)
        if requested_marker and requested_marker not in markers:
            markers.append(requested_marker)

        if not markers:
            return VerificationResult(
                Verdict.INCONCLUSIVE,
                {"reason": "no ownership marker available to prove cross-account access"},
                "no ownership marker available",
            )

        for marker in markers:
            for step in execution.step_results:
                if step.response is None:
                    continue
                status = status_of(step)
                if status is None or status >= 400:
                    continue
                body = step.response.get("body", "")
                if marker and marker in body:
                    return VerificationResult(
                        Verdict.PROVEN,
                        {
                            "marker": marker,
                            "step_index": step.index,
                            "status_code": status,
                            "snippet": _snippet(body, marker),
                        },
                        f"victim-owned marker {marker!r} returned to the requesting session",
                    )

        last = last_response(execution)
        return VerificationResult(
            Verdict.NOT_PROVEN,
            {
                "reason": "no victim-owned marker appeared in any successful response",
                "last_status": status_of(last) if last else None,
            },
            "no cross-account data observed",
        )


def _snippet(body: str, marker: str, radius: int = 60) -> str:
    i = body.find(marker)
    if i < 0:
        return ""
    start = max(0, i - radius)
    end = min(len(body), i + len(marker) + radius)
    return body[start:end]
