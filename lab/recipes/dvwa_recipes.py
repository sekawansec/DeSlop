"""DVWA lab recipes and report builders.

Wires DeSlop to the DVWA target from lab/docker-compose.yml. DVWA runs with
security level "low", so the planted bugs are reproducible.

Bug classes exercised:
  * reflected XSS   -> /vulnerabilities/xss_r/?name=
  * command inj.    -> POST /vulnerabilities/exec/  (ip=127.0.0.1; id)
"""

from __future__ import annotations

from deslop.dataset.schema import Attachment, Label, SyntheticReport
from deslop.recipes.concrete import CommandInjectionRecipe, ReflectedXssRecipe
from deslop.recipes.registry import register_recipe

DVWA_BASE = "http://127.0.0.1:14000"
DVWA_XSS_ENDPOINT = "/vulnerabilities/xss_r/"
DVWA_EXEC_ENDPOINT = "/vulnerabilities/exec/"
DVWA_ASSET = "127.0.0.1"

XSS_MARKER = "DESLOP_DVWA_XSS_MARKER"


def register_dvwa_recipes() -> None:
    register_recipe(ReflectedXssRecipe())
    register_recipe(CommandInjectionRecipe())


def build_dvwa_reflected_xss(report_id: str) -> SyntheticReport:
    body = (
        "## Summary\n"
        "DVWA's reflected XSS module echoes the name parameter without encoding.\n\n"
        "## Steps to reproduce\n"
        "1. Log in to DVWA (admin / password), security level low.\n"
        f"2. Request /vulnerabilities/xss_r/?name=<script>document.title='{XSS_MARKER}'"
        "</script>\n"
        "3. The script executes and sets the page title, proving XSS.\n\n"
        "## Evidence\nRaw request:\n\n```http\n"
        f"GET /vulnerabilities/xss_r/?name=<script>document.title='{XSS_MARKER}'</script>"
        " HTTP/1.1\nHost: 127.0.0.1:14000\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title="DVWA reflected XSS (xss_r)",
        body=body,
        asset=DVWA_ASSET,
        endpoint=DVWA_XSS_ENDPOINT,
        vuln_class="xss_reflected",
        claimed_severity="medium",
        attachments=[
            Attachment(
                name="request.http",
                kind="raw_http",
                content=(
                    f"GET /vulnerabilities/xss_r/?name=<script>document.title='{XSS_MARKER}'"
                    "</script> HTTP/1.1\nHost: 127.0.0.1:14000\n"
                ),
            )
        ],
        reproducible=True,
    )


def build_dvwa_command_injection(report_id: str) -> SyntheticReport:
    body = (
        "## Summary\n"
        "DVWA's command execution module passes the ip parameter to a shell "
        "without sanitisation, allowing command injection.\n\n"
        "## Steps to reproduce\n"
        "1. Log in to DVWA (admin / password), security level low.\n"
        "2. POST /vulnerabilities/exec/ with ip=127.0.0.1; id and Submit=Submit.\n"
        "3. The response contains the output of the id command "
        "(uid=... gid=...), proving command execution.\n\n"
        "## Evidence\nRaw request:\n\n```http\n"
        "POST /vulnerabilities/exec/ HTTP/1.1\nHost: 127.0.0.1:14000\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "ip=127.0.0.1;%20id&Submit=Submit\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title="DVWA OS command injection (exec)",
        body=body,
        asset=DVWA_ASSET,
        endpoint=DVWA_EXEC_ENDPOINT,
        vuln_class="command_injection",
        claimed_severity="critical",
        attachments=[
            Attachment(
                name="request.http",
                kind="raw_http",
                content=(
                    "POST /vulnerabilities/exec/ HTTP/1.1\nHost: 127.0.0.1:14000\n"
                    "Content-Type: application/x-www-form-urlencoded\n\n"
                    "ip=127.0.0.1;%20id&Submit=Submit\n"
                ),
            )
        ],
        reproducible=True,
    )


DVWA_BUILDERS = {
    "xss_reflected": build_dvwa_reflected_xss,
    "command_injection": build_dvwa_command_injection,
}


def build_dvwa_dataset(seed: int = 1) -> list[SyntheticReport]:
    """A small DVWA-specific dataset for demos and eval."""
    return [
        build_dvwa_reflected_xss("DVWA-001"),
        build_dvwa_command_injection("DVWA-002"),
    ]
