"""Content negotiation helpers for browser form posts vs. API clients.

The same endpoints serve both: browsers (HTML ``<form>`` posts, ``Accept:
text/html``) get page redirects so they never land on a raw JSON blob; API
clients (curl/httpx, ``Accept: */*`` or ``application/json``) keep JSON
responses.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import RedirectResponse


def wants_html(request: Request) -> bool:
    """True when the request looks like a browser form/navigation."""
    return "text/html" in request.headers.get("accept", "")


def redirect_back(url: str, *, notice: str | None = None) -> RedirectResponse:
    """303 redirect so a POST can safely be followed by a page reload."""
    if notice:
        sep = "&" if "?" in url else "?"
        from urllib.parse import quote

        url = f"{url}{sep}notice={quote(notice)}"
    return RedirectResponse(url=url, status_code=303)
