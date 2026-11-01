"""Open redirect verifier.

Proof: the browser is actually redirected to a marker domain. We accept a
deterministic proof in two forms:

* the HTTP response carries a 3xx ``Location`` pointing at the marker domain
  (server-side redirect), or
* the browser's final URL after navigation lands on the marker domain
  (client-side redirect).

The marker domain is DeSlop's own (``marker.deslop.test``), never a host named
in the report: the substitution layer rewrites the report's external redirect
target to it before replay. A redirect to a host the report merely *named*
(an SSO provider the app always redirects to, say) proves nothing; landing on
a domain only the replayed parameter could have produced does.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult
from .browser import Browser, get_browser
from .common import header_of, status_of


class OpenRedirectVerifier:
    bug_class = "open_redirect"

    def __init__(
        self,
        marker_host: str = "marker.deslop.test",
        browser: Browser | None = None,
    ) -> None:
        self.marker_host = marker_host.lower()
        self._browser = browser

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        if not execution.completed:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"reason": "execution did not complete", "failed_step": execution.failed_step_index},
                "execution did not complete",
            )

        marker_host = self.marker_host

        # 1) Server-side redirect via Location header.
        saw_location = False
        for step in execution.step_results:
            if step.response is None:
                continue
            status = status_of(step)
            location = header_of(step, "location")
            if location:
                saw_location = True
            if status in (301, 302, 303, 307, 308) and location and _host_of(location) == marker_host:
                return VerificationResult(
                    Verdict.PROVEN,
                    {"method": "location_header", "status_code": status, "location": location},
                    f"server redirected to marker domain {marker_host!r}",
                )

        # If a redirect was observed but it did not point at the marker domain,
        # that is a definitive negative — no need to drive a browser.
        if saw_location:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"marker_host": marker_host, "method": "location_header"},
                "redirect Location did not point at the marker domain",
            )

        # 2) Client-side redirect: drive the browser and inspect the final URL.
        url = None
        for r in reversed(execution.step_results):
            if r.response is not None:
                url = r.response.get("url") or r.request.get("url")
                break
        if url:
            browser = self._browser or get_browser()
            obs = browser.observe(url, expected_markers=[], headless=True)
            if obs.error:
                return VerificationResult(
                    Verdict.ERROR, {"error": obs.error, "url": url}, "browser observation failed"
                )
            final_host = _host_of(obs.final_url or "")
            if final_host == marker_host:
                return VerificationResult(
                    Verdict.PROVEN,
                    {"method": "browser", "final_url": obs.final_url, "url": url},
                    f"browser was redirected to marker domain {marker_host!r}",
                )

        return VerificationResult(
            Verdict.NOT_PROVEN,
            {"marker_host": marker_host},
            "no redirect to the marker domain observed",
        )


def _host_of(url: str) -> str:
    if not url:
        return ""
    if "://" in url:
        return (urlparse(url).hostname or "").lower()
    return url.split("/", 1)[0].split(":", 1)[0].lower()
