"""Web executor: runs a validated, substituted plan with httpx.

Security properties:

* Every request carries the configured validator header (``X-Repro-Validator``).
* Request-count, wall-clock, and per-target rate limits are enforced.
* Credentials are redacted from the recorded request/response log.
* The executor never reads raw report text; it only sees locked steps.
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING, Any

import httpx

from ..config.schema import ProgramConfig
from ..config.settings import Settings, get_settings
from .interfaces import ExecutionResult, StepResult
from .login import Session, login_account
from .steps import ReproPlanModel, ReproStep

if TYPE_CHECKING:
    # sandbox.policy imports repro.scope; a runtime import here would cycle.
    from ..sandbox.policy import EgressPolicy

REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


class RateLimiter:
    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last: float = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()


def redact(headers: dict[str, str]) -> dict[str, str]:
    return {k: ("<redacted>" if k.lower() in REDACT_HEADERS else v) for k, v in headers.items()}


class WebExecutor:
    name = "web"

    def __init__(
        self,
        settings: Settings | None = None,
        client_factory: Any | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client_factory = client_factory or (lambda: httpx.Client(timeout=20.0))

    def _resolve_session(
        self, step: ReproStep, sessions: dict[str, Session], program: ProgramConfig
    ) -> Session | None:
        if not step.as_account:
            return None
        if step.as_account in sessions:
            return sessions[step.as_account]
        account = next((a for a in program.test_accounts if a.id == step.as_account), None)
        if account is None:
            return None
        session = login_account(account, program.login)
        sessions[account.id] = session
        return session

    def _build_request(
        self, step: ReproStep, session: Session | None, run_id: str
    ) -> tuple[str, str, dict[str, str], dict[str, str], str | None]:
        req = step.request
        headers = dict(req.headers)
        headers[self.settings.repro_header] = run_id
        # Log-correlation header: lets the target's WAF/reverse-proxy logs tie
        # reproduction traffic back to the report being verified.
        headers[self.settings.bounty_user_header] = f"deslop-repro-{run_id}"

        if session is not None:
            for k, v in session.headers.items():
                headers.setdefault(k, v)

        cookies = dict(req.cookies)
        if session is not None:
            for k, v in session.cookies.items():
                cookies.setdefault(k, v)

        # Strip any pre-existing cookie header so cookie-jar form is authoritative.
        headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}

        return req.method, req.url, headers, cookies, req.body

    def execute(
        self,
        plan: ReproPlanModel,
        program: ProgramConfig,
        *,
        run_id: str | None = None,
        egress: EgressPolicy | None = None,
    ) -> ExecutionResult:
        from ..sandbox.policy import build_egress_policy, host_of

        run_id = run_id or uuid.uuid4().hex
        result = ExecutionResult(run_id=run_id, bug_class=plan.bug_class)
        limiter = RateLimiter(self.settings.rate_limit_rps)
        max_requests = program.max_requests_per_run or self.settings.max_requests_per_run
        started = time.monotonic()
        sessions: dict[str, Session] = {}
        client = self._client_factory()
        # Egress policy is enforced on every request — a validated plan must
        # never reach a host outside the sandbox allowlist (or unapproved
        # production).
        policy = egress or build_egress_policy(
            program, self.settings.oob_base_url
        )

        try:
            for step in plan.steps:
                if len(result.step_results) >= max_requests:
                    result.error = f"request limit ({max_requests}) reached"
                    result.failed_step_index = step.index
                    break
                if time.monotonic() - started > self.settings.max_run_seconds:
                    result.error = "run time limit reached"
                    result.failed_step_index = step.index
                    break

                host = host_of(step.request.url)
                if not policy.permits(host):
                    reason = (
                        "production host; reproduction requires an approve_production decision"
                        if policy.is_production(host)
                        else "host not in the sandbox egress allowlist"
                    )
                    result.step_results.append(
                        StepResult(
                            index=step.index,
                            ok=False,
                            request={"method": step.request.method, "url": step.request.url},
                            error=f"egress denied: {reason}",
                        )
                    )
                    result.failed_step_index = step.index
                    result.error = f"step {step.index} egress denied: {reason}"
                    break

                try:
                    session = self._resolve_session(step, sessions, program)
                except Exception as exc:  # noqa: BLE001 - a failed login is a failed step
                    # A login request that never reaches the target must not
                    # crash the run — it is a failed step like any other.
                    result.step_results.append(
                        StepResult(
                            index=step.index,
                            ok=False,
                            request={"method": step.request.method, "url": step.request.url},
                            error=f"login for {step.as_account} failed: {type(exc).__name__}: {exc}",
                        )
                    )
                    result.failed_step_index = step.index
                    result.error = f"step {step.index} login failed: {exc}"
                    break
                method, url, headers, cookies, body = self._build_request(step, session, run_id)
                limiter.wait()

                recorded_req = {
                    "method": method,
                    "url": url,
                    "headers": redact(headers),
                    "cookies": {k: "<redacted>" for k in cookies},
                    "body": body,
                }
                try:
                    resp = client.request(
                        method, url, headers=headers, cookies=cookies, content=body
                    )
                except httpx.HTTPError as exc:
                    result.step_results.append(
                        StepResult(
                            index=step.index,
                            ok=False,
                            request=recorded_req,
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )
                    result.failed_step_index = step.index
                    result.error = f"step {step.index} failed: {exc}"
                    break

                resp_body = resp.text
                result.step_results.append(
                    StepResult(
                        index=step.index,
                        ok=resp.status_code < 400,
                        request=recorded_req,
                        response={
                            "status_code": resp.status_code,
                            "headers": redact(dict(resp.headers)),
                            "body": resp_body[:65536],
                            "url": str(resp.url),
                        },
                    )
                )
                if resp.status_code >= 500:
                    result.failed_step_index = step.index
                    result.error = f"step {step.index} returned HTTP {resp.status_code}"
                    break
        finally:
            client.close()

        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result
