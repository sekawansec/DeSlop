"""SSRF verifier.

Proof: a callback carrying a unique per-run token reaches the self-hosted OOB
listener. The token is generated per run and embedded in the payload, so a
callback proves the target server actually made the outbound request.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..config.schema import ProgramConfig
from ..config.settings import Settings, get_settings
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult


@dataclass
class OobClient:
    base_url: str
    client: httpx.Client | None = None

    def hits_for(self, token: str) -> list[dict]:
        owns = self.client is None
        client = self.client or httpx.Client(timeout=8.0)
        try:
            r = client.get(f"{self.base_url.rstrip('/')}/hits/{token}")
            r.raise_for_status()
            return r.json().get("hits", [])
        finally:
            if owns:
                client.close()


class SsrfVerifier:
    bug_class = "ssrf"

    def __init__(
        self,
        oob_client: OobClient | None = None,
        settings: Settings | None = None,
        run_token: str | None = None,
    ) -> None:
        self._settings = settings
        self._client = oob_client
        self._run_token = run_token

    def _token(self, plan) -> str | None:  # noqa: ANN001
        if self._run_token:
            return self._run_token
        for step in plan.steps:
            if step.expectation and step.expectation.marker:
                return step.expectation.marker
        for step in plan.steps:
            blob = " ".join(
                [step.request.url, step.request.body or "", " ".join(step.request.headers.values())]
            )
            for tok in _extract_tokens(blob):
                return tok
        return None

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        token = self._token(plan)
        if not token:
            return VerificationResult(
                Verdict.INCONCLUSIVE,
                {"reason": "no per-run OOB token found in the plan"},
                "no OOB token to check",
            )
        settings = self._settings or get_settings()
        client = self._client or OobClient(settings.oob_base_url)
        try:
            hits = client.hits_for(token)
        except httpx.HTTPError as exc:
            return VerificationResult(
                Verdict.ERROR,
                {"error": f"{type(exc).__name__}: {exc}", "token": token},
                "could not query the OOB listener",
            )
        if hits:
            return VerificationResult(
                Verdict.PROVEN,
                {"token": token, "hit_count": len(hits), "first_hit": hits[0]},
                f"OOB listener received {len(hits)} callback(s) for the per-run token",
            )
        return VerificationResult(
            Verdict.NOT_PROVEN,
            {"token": token, "hit_count": 0},
            "no OOB callback received for the per-run token",
        )


def _extract_tokens(blob: str) -> list[str]:
    import re

    # Tokens look like <hex>.oob.test or oob.test/<token>; also a bare deslop token.
    tokens = re.findall(r"([a-f0-9]{16,64})\.oob\.", blob, re.I)
    tokens += re.findall(r"/cb/([A-Za-z0-9_\-]{8,})", blob)
    tokens += re.findall(r"([a-f0-9]{16,64})", blob)
    # De-duplicate, preserve order.
    seen: set[str] = set()
    out: list[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
