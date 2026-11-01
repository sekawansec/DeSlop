"""Command-injection verifier.

Proof: the target executed an OS command and echoed its output back in the
response. We require a *specific* marker that only command execution produces
(e.g. the output of ``id``), supplied by the recipe/plan, not a generic word.

A match that also appears in any request we sent is discarded: an endpoint
that merely reflects ``uid=0(root) gid=0(root)`` from the payload is
reflection, not execution.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult


def _request_blob(execution: ExecutionResult) -> str:
    """Everything we sent, fully URL-decoded, for the reflection check."""
    parts: list[str] = []
    for step in execution.step_results:
        req = step.request or {}
        parts.append(str(req.get("url") or ""))
        parts.append(str(req.get("body") or ""))
        parts.extend(str(v) for v in (req.get("headers") or {}).values())
    blob = "\n".join(parts)
    for _ in range(3):  # tolerate double/triple encoding
        decoded = unquote_plus(blob)
        if decoded == blob:
            break
        blob = decoded
    return blob


class CommandInjectionVerifier:
    bug_class = "command_injection"

    def __init__(self, proof_pattern: str = r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)") -> None:
        #: A regex that only matches when a real OS command executed.
        self.proof_pattern = proof_pattern

    def verify(self, plan, execution: ExecutionResult, program: ProgramConfig) -> VerificationResult:  # noqa: ANN001
        if not execution.completed:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"reason": "execution did not complete", "failed_step": execution.failed_step_index},
                "execution did not complete",
            )
        regex = re.compile(self.proof_pattern)
        sent = _request_blob(execution)
        reflected: list[str] = []
        for step in execution.step_results:
            if step.response is None:
                continue
            status = step.response.get("status_code")
            if status is None or status >= 400:
                continue
            body = step.response.get("body", "")
            for m in regex.finditer(body):
                if m.group(0) in sent:
                    reflected.append(m.group(0))
                    continue
                return VerificationResult(
                    Verdict.PROVEN,
                    {"marker": m.group(0), "step_index": step.index, "status_code": status},
                    f"command execution proven by output {m.group(0)!r}",
                )
        if reflected:
            return VerificationResult(
                Verdict.NOT_PROVEN,
                {"reason": "matching output was present in the request itself (reflection)",
                 "reflected": reflected[:3]},
                "command output only reflected from the request",
            )
        return VerificationResult(
            Verdict.NOT_PROVEN,
            {"reason": "no command-execution output matched"},
            "no command-execution output observed",
        )
