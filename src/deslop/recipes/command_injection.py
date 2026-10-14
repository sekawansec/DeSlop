"""Command-injection verifier.

Proof: the target executed an OS command and echoed its output back in the
response. We require a *specific* marker that only command execution produces
(e.g. the output of ``id``), supplied by the recipe/plan, not a generic word.
"""

from __future__ import annotations

import re

from ..config.schema import ProgramConfig
from ..db.enums import Verdict
from ..repro.interfaces import ExecutionResult, VerificationResult


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
        for step in execution.step_results:
            if step.response is None:
                continue
            status = step.response.get("status_code")
            if status is None or status >= 400:
                continue
            body = step.response.get("body", "")
            m = regex.search(body)
            if m:
                return VerificationResult(
                    Verdict.PROVEN,
                    {"marker": m.group(0), "step_index": step.index, "status_code": status},
                    f"command execution proven by output {m.group(0)!r}",
                )
        return VerificationResult(
            Verdict.NOT_PROVEN,
            {"reason": "no command-execution output matched"},
            "no command-execution output observed",
        )
