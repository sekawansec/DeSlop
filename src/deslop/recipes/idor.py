"""IDOR verifier.

Proof: a response returned to account X (or to an unauthenticated request)
contains a secret owned by account Y — where ownership comes from trusted
program configuration, never from the report.

Markers are taken from ``test_accounts[].owned_markers`` and from a canary
with an ``owner`` set. The report's own claimed marker
(``step.expectation.marker``) is never used: it is untrusted researcher input
and proves nothing.
"""

from __future__ import annotations

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult
from .common import last_response, status_of


class IdorVerifier:
    bug_class = "idor"

    def __init__(self, owner_markers: dict[str, list[str]] | None = None) -> None:
        # Extra markers supplied by recipe setup, keyed by owning account id.
        self.extra_owner_markers = owner_markers or {}

    def _owner_map(self, program: ProgramConfig) -> dict[str, list[str]]:
        owners: dict[str, list[str]] = {}
        for acct in program.test_accounts:
            if acct.owned_markers:
                owners.setdefault(acct.id, []).extend(acct.owned_markers)
        canary = program.canary
        if canary and canary.enabled and canary.token and canary.owner:
            owners.setdefault(canary.owner, []).append(canary.token)
        for owner, markers in self.extra_owner_markers.items():
            owners.setdefault(owner, []).extend(markers)
        return {k: list(dict.fromkeys(v)) for k, v in owners.items()}

    def verify(
        self, plan, execution: ExecutionResult, program: ProgramConfig
    ) -> VerificationResult:  # noqa: ANN001
        if not execution.completed:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"reason": "execution did not complete", "failed_step": execution.failed_step_index},
                "execution did not complete",
            )

        owner_map = self._owner_map(program)
        if not owner_map:
            return VerificationResult(
                Verdict.INCONCLUSIVE,
                {
                    "reason": "no owned_markers configured on test accounts "
                    "(or a canary without an owner); cross-account access "
                    "cannot be proven automatically"
                },
                "no trusted ownership markers configured",
            )

        steps_by_index = {s.index: s for s in plan.steps}
        for step in execution.step_results:
            if step.response is None:
                continue
            status = status_of(step)
            if status is None or status >= 400:
                continue
            plan_step = steps_by_index.get(step.index)
            requester = plan_step.as_account if plan_step else None
            body = step.response.get("body", "")
            for owner, markers in owner_map.items():
                if requester is not None and owner == requester:
                    continue
                for marker in markers:
                    if marker and marker in body:
                        who = requester or "unauthenticated request"
                        return VerificationResult(
                            Verdict.PROVEN,
                            {
                                "marker": marker,
                                "owner": owner,
                                "requester": requester,
                                "step_index": step.index,
                                "status_code": status,
                                "snippet": _snippet(body, marker),
                            },
                            f"marker owned by {owner!r} returned to {who}",
                        )

        last = last_response(execution)
        return VerificationResult(
            Verdict.NOT_PROVEN,
            {
                "reason": "no marker owned by a different account appeared in "
                "any successful response",
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
