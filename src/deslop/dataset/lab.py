"""Constants describing the intentionally vulnerable lab targets.

These values are shared by the dataset generator, the recipes/verifiers, and
the lab docker-compose stack so they stay in sync. They are *lab* values and
must never be treated as program policy.
"""

from __future__ import annotations

# The custom vulnerable app (lab/custom_app/app.py), reached from inside the
# lab network. Overridden by DESLOP_LAB_BASE_URL when running the eval harness.
LAB_BASE_URL = "http://lab-app:8000"

# The OOB listener, reached from inside the lab network.
OOB_BASE_URL = "http://oob:8080"

# Lab accounts (mirror USERS in lab/custom_app/app.py).
LAB_ACCOUNTS: dict[str, dict[str, str]] = {
    "alice": {"username": "alice", "password": "alice-pass", "role": "user", "tenant": "tenant-one"},
    "bob": {"username": "bob", "password": "bob-pass", "role": "user", "tenant": "tenant-one"},
    "carol": {"username": "carol", "password": "carol-pass", "role": "user", "tenant": "tenant-two"},
    "admin": {"username": "admin", "password": "admin-pass", "role": "admin", "tenant": "tenant-one"},
}

# Invoices and their owners (mirror INVOICES in the lab app).
INVOICES: dict[int, dict[str, str]] = {
    1001: {"owner": "alice", "secret": "ACME-INVOICE-ALICE-1001"},
    1002: {"owner": "bob", "secret": "ACME-INVOICE-BOB-1002"},
    1003: {"owner": "carol", "secret": "ACME-INVOICE-CAROL-1003"},
}

# Endpoints.
IDOR_ENDPOINT = "/api/invoices/{id}"
XSS_ENDPOINT = "/search"
STORED_XSS_POST = "/api/comments"
STORED_XSS_VIEW = "/comments"
SSRF_ENDPOINT = "/api/fetch"
REDIRECT_ENDPOINT = "/redirect"
LOGIN_ENDPOINT = "/api/login"
RESET_ENDPOINT = "/__test__/reset"

# Marker domains/hosts.
REDIRECT_MARKER_HOST = "marker.deslop.test"
REDIRECT_MARKER_URL = f"https://{REDIRECT_MARKER_HOST}/landing"

# Bug class slugs used across the pipeline.
IDOR = "idor"
XSS_REFLECTED = "xss_reflected"
XSS_STORED = "xss_stored"
SSRF = "ssrf"
OPEN_REDIRECT = "open_redirect"

SUPPORTED = (IDOR, XSS_REFLECTED, XSS_STORED, SSRF, OPEN_REDIRECT)

CWE_BY_CLASS: dict[str, str] = {
    IDOR: "CWE-639",
    XSS_REFLECTED: "CWE-79",
    XSS_STORED: "CWE-79",
    SSRF: "CWE-918",
    OPEN_REDIRECT: "CWE-601",
}
