"""Self-hosted out-of-band (OOB) listener for blind bug classes.

SSRF and other blind bugs are proven when a callback arrives here carrying a
unique per-run token. This service is intentionally tiny and dependency-light
so it can run alongside the sandbox with no outbound access.

Endpoints:

* ``ANY /cb/{token}``     record a callback for ``token``
* ``GET  /healthz``       liveness
* ``GET  /hits``          list recorded hits (used by the SSRF verifier)
* ``GET  /hits/{token}``  hits for a specific token (verifier poll)
* ``POST /__test__/reset`` clear all hits
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

HOST = os.environ.get("OOB_LISTEN_HOST", "0.0.0.0")
PORT = int(os.environ.get("OOB_LISTEN_PORT", "8080"))

app = FastAPI(title="DeSlop OOB listener", version="0.1.0")

_hits: list[dict] = []
_started = time.time()


def _record(token: str, request: Request) -> None:
    _hits.append(
        {
            "token": token,
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "client": request.client.host if request.client else None,
            "time": datetime.now(UTC).isoformat(),
        }
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "uptime_s": round(time.time() - _started, 3), "hits": len(_hits)}


@app.api_route("/cb/{token}", methods=["GET", "POST", "PUT", "HEAD", "OPTIONS", "PATCH"])
async def callback(token: str, request: Request) -> PlainTextResponse:
    _record(token, request)
    return PlainTextResponse("ok")


@app.get("/hits")
def hits() -> JSONResponse:
    return JSONResponse({"hits": _hits})


@app.get("/hits/{token}")
def hits_for(token: str) -> JSONResponse:
    matching = [h for h in _hits if h["token"] == token]
    return JSONResponse({"token": token, "count": len(matching), "hits": matching})


@app.post("/__test__/reset")
def reset() -> PlainTextResponse:
    _hits.clear()
    return PlainTextResponse("reset ok")
