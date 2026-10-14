"""XSS verifiers (reflected and stored).

Proof: the payload actually executes in a headless browser, demonstrated by a
unique marker being observed (e.g. a marker the script writes to the page title
or body). Reflected XSS is observed directly from the response URL; stored XSS
navigates to the view where the persisted payload renders.
"""

from __future__ import annotations

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult
from .browser import Browser, get_browser


class _XssVerifierBase:
    bug_class = "xss"

    def __init__(self, browser: Browser | None = None, view_url: str | None = None) -> None:
        self._browser = browser
        self._view_url = view_url

    def _marker(self, plan) -> str | None:  # noqa: ANN001
        for step in plan.steps:
            if step.expectation and step.expectation.marker:
                return step.expectation.marker
        return None

    def _target_url(self, plan, execution) -> str | None:  # noqa: ANN001
        if self._view_url:
            return self._view_url
        if not plan.steps:
            return None
        # Use the last executed step's URL (the one that renders the payload).
        for r in reversed(execution.step_results):
            if r.response is not None:
                return r.response.get("url") or r.request.get("url")
        return plan.steps[0].request.url

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        if not execution.completed:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"reason": "execution did not complete", "failed_step": execution.failed_step_index},
                "execution did not complete",
            )
        marker = self._marker(plan)
        if not marker:
            return VerificationResult(
                Verdict.INCONCLUSIVE,
                {"reason": "payload has no execution marker to observe"},
                "no execution marker available",
            )
        url = self._target_url(plan, execution)
        if not url:
            return VerificationResult(
                Verdict.INCONCLUSIVE, {"reason": "no URL to observe"}, "no URL to observe"
            )

        browser = self._browser or get_browser()
        obs = browser.observe(url, expected_markers=[marker], headless=True)
        if obs.error:
            return VerificationResult(
                Verdict.ERROR, {"error": obs.error, "url": url}, "browser observation failed"
            )
        if marker in obs.executed_markers:
            return VerificationResult(
                Verdict.PROVEN,
                {"marker": marker, "url": url, "final_url": obs.final_url},
                f"payload marker {marker!r} executed in a headless browser",
            )
        return VerificationResult(
            Verdict.NOT_PROVEN,
            {"marker": marker, "url": url, "final_url": obs.final_url},
            "payload marker did not execute",
        )


class ReflectedXssVerifier(_XssVerifierBase):
    bug_class = "xss_reflected"


class StoredXssVerifier(_XssVerifierBase):
    bug_class = "xss_stored"
