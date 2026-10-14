"""The ``doctor`` command.

Verifies that an environment is ready for reproduction. Reproduction is refused
until every *required* check passes. Results are a pass/fail checklist with fix
instructions.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

import httpx

from .config.schema import ProgramConfig
from .config.settings import Settings, get_settings
from .repro.login import login_account
from .sandbox.policy import host_of


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str = ""
    fix: str = ""
    required: bool = True


@dataclass
class DoctorReport:
    results: list[CheckResult]

    @property
    def ok(self) -> bool:
        return not any(
            r.required and r.status == CheckStatus.FAIL for r in self.results
        )

    @property
    def required_failures(self) -> list[CheckResult]:
        return [r for r in self.results if r.required and r.status == CheckStatus.FAIL]

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "detail": r.detail,
                    "fix": r.fix,
                    "required": r.required,
                }
                for r in self.results
            ],
        }

    def render(self) -> str:
        lines = []
        for r in self.results:
            mark = {
                CheckStatus.PASS: "PASS",
                CheckStatus.FAIL: "FAIL",
                CheckStatus.WARN: "WARN",
                CheckStatus.SKIP: "SKIP",
            }[r.status]
            req = "" if r.required else " (optional)"
            lines.append(f"[{mark}]{req} {r.name}: {r.detail}")
            if r.status in {CheckStatus.FAIL, CheckStatus.WARN} and r.fix:
                lines.append(f"        fix: {r.fix}")
        lines.append("")
        lines.append("RESULT: READY" if self.ok else "RESULT: NOT READY (reproduction refused)")
        return "\n".join(lines)


def _check_staging_reachable(program: ProgramConfig, settings: Settings) -> CheckResult:
    base = program.staging.base_url
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as c:
            r = c.get(base)
        return CheckResult(
            "staging reachable",
            CheckStatus.PASS,
            f"{base} responded HTTP {r.status_code}",
        )
    except httpx.HTTPError as exc:
        return CheckResult(
            "staging reachable",
            CheckStatus.FAIL,
            f"could not reach {base}: {type(exc).__name__}",
            fix="Check the staging base_url, network access, and that staging is running.",
        )


def _check_accounts(program: ProgramConfig) -> list[CheckResult]:
    results: list[CheckResult] = []
    accounts = program.test_accounts
    if not accounts:
        return [
            CheckResult(
                "test accounts",
                CheckStatus.FAIL,
                "no test accounts are configured",
                fix="Define at least two same-role accounts and one different-role account.",
            )
        ]

    for acct in accounts:
        try:
            login_account(acct, program.login)
            results.append(
                CheckResult(
                    f"login {acct.id}",
                    CheckStatus.PASS,
                    f"logged in as {acct.username} (role={acct.role})",
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator
            results.append(
                CheckResult(
                    f"login {acct.id}",
                    CheckStatus.FAIL,
                    f"login failed: {exc}",
                    fix="Verify the credentials and the automated login configuration.",
                )
            )

    roles: dict[str, list[str]] = {}
    for a in accounts:
        roles.setdefault(a.role, []).append(a.id)
    same_role_ok = any(len(ids) >= 2 for ids in roles.values())
    results.append(
        CheckResult(
            "distinct same-role accounts",
            CheckStatus.PASS if same_role_ok else CheckStatus.FAIL,
            f"roles: { {r: len(i) for r, i in roles.items()} }",
            fix="Add at least two accounts with the same role but different identities.",
        )
    )

    usernames = [a.username for a in accounts]
    distinct = len(set(usernames)) == len(usernames)
    results.append(
        CheckResult(
            "accounts are distinct identities",
            CheckStatus.PASS if distinct else CheckStatus.FAIL,
            "all usernames unique" if distinct else "duplicate usernames found",
            fix="Ensure same-role accounts are genuinely different users.",
        )
    )
    return results


def _check_egress_blocked(program: ProgramConfig, settings: Settings, probe_host: str) -> CheckResult:
    """Confirm a connection to a host outside the allowlist actually fails."""
    allowed = {h.lower() for h in program.allowed_egress_hosts}
    staging = host_of(program.staging.base_url)
    oob = host_of(settings.oob_base_url)
    allowed |= {staging, oob}
    if probe_host.lower() in allowed:
        return CheckResult(
            "egress blocked outside allowlist",
            CheckStatus.FAIL,
            f"probe host {probe_host} is in the allowlist; pick a host that is not",
            fix="Choose a probe host that is definitely outside scope.",
        )
    try:
        with socket.create_connection((probe_host, 443), timeout=3.0):
            return CheckResult(
                "egress blocked outside allowlist",
                CheckStatus.FAIL,
                f"connection to {probe_host}:443 unexpectedly succeeded",
                fix="Restrict sandbox egress at the network level; only in-scope staging "
                "hosts and the OOB listener may be reachable.",
            )
    except OSError:
        return CheckResult(
            "egress blocked outside allowlist",
            CheckStatus.PASS,
            f"connection to {probe_host}:443 correctly failed",
        )


def _check_oob(settings: Settings) -> CheckResult:
    url = settings.oob_base_url.rstrip("/") + "/healthz"
    try:
        with httpx.Client(timeout=8.0) as c:
            r = c.get(url)
        if r.status_code == 200:
            return CheckResult("OOB listener", CheckStatus.PASS, f"{url} healthy")
        return CheckResult(
            "OOB listener",
            CheckStatus.FAIL,
            f"{url} returned HTTP {r.status_code}",
            fix="Start the OOB listener service.",
        )
    except httpx.HTTPError as exc:
        return CheckResult(
            "OOB listener",
            CheckStatus.FAIL,
            f"could not reach {url}: {type(exc).__name__}",
            fix="Start the OOB listener and check oob_base_url.",
        )


def _check_reset(program: ProgramConfig) -> CheckResult:
    if program.staging.reset is None or not program.staging.reset.url:
        return CheckResult(
            "data reset script",
            CheckStatus.WARN,
            "no reset endpoint or script configured",
            fix="Configure staging.reset so the sandbox can seed clean data.",
            required=False,
        )
    url = program.staging.reset.url
    try:
        with httpx.Client(timeout=15.0) as c:
            headers = {}
            if program.staging.reset.auth_header:
                headers[program.staging.reset.auth_header] = "configured"
            r = c.request(program.staging.reset.method, url, headers=headers)
        ok = r.status_code < 400
        return CheckResult(
            "data reset script",
            CheckStatus.PASS if ok else CheckStatus.FAIL,
            f"{url} responded HTTP {r.status_code}",
            fix="Check the reset endpoint and its auth header.",
        )
    except httpx.HTTPError as exc:
        return CheckResult(
            "data reset script",
            CheckStatus.FAIL,
            f"reset call failed: {type(exc).__name__}",
            fix="Check the reset endpoint URL and network access.",
        )


def run_doctor(
    program: ProgramConfig,
    settings: Settings | None = None,
    *,
    probe_host: str = "example.com",
    skip_network: bool = False,
    oob_probe: Callable[[Settings], CheckResult] | None = None,
) -> DoctorReport:
    """Run the readiness checklist for ``program``."""
    settings = settings or get_settings()
    results: list[CheckResult] = []

    if skip_network:
        results.append(
            CheckResult("staging reachable", CheckStatus.SKIP, "network checks skipped")
        )
    else:
        results.append(_check_staging_reachable(program, settings))

    results.extend(_check_accounts(program))

    if skip_network:
        results.append(CheckResult("egress blocked outside allowlist", CheckStatus.SKIP, "skipped"))
    else:
        results.append(_check_egress_blocked(program, settings, probe_host))

    if skip_network:
        results.append(CheckResult("OOB listener", CheckStatus.SKIP, "skipped"))
    else:
        results.append((oob_probe or _check_oob)(settings))

    results.append(_check_reset(program))

    if settings.email_enabled:
        results.append(
            CheckResult(
                "email sending",
                CheckStatus.WARN,
                "email is enabled; verify SMTP out of band",
                required=False,
            )
        )
    return DoctorReport(results=results)
