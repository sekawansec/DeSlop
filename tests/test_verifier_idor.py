from deslop.config.schema import ProgramConfig, StagingConfig
from deslop.recipes.idor import IdorVerifier
from deslop.repro.interfaces import ExecutionResult, StepResult

PROGRAM = ProgramConfig(id="lab", name="Lab", staging=StagingConfig(base_url="http://x"))


def _step(index, body, status=200):
    return StepResult(
        index=index,
        ok=status < 400,
        request={"method": "GET", "url": "http://staging/lab"},
        response={"status_code": status, "headers": {}, "body": body, "url": "http://staging/lab"},
    )


def _exec(*steps, failed=None, error=None):
    return ExecutionResult(
        run_id="run-1",
        bug_class="idor",
        step_results=list(steps),
        failed_step_index=failed,
        error=error,
    )


def test_idor_proven_when_victim_secret_in_other_accounts_response():
    verifier = IdorVerifier(["ACME-INVOICE-ALICE-1001"])
    execution = _exec(_step(0, '{"id":1001,"owner":"alice","secret":"ACME-INVOICE-ALICE-1001"}'))
    result = verifier.verify(_plan(), execution, PROGRAM)
    assert result.verdict == "proven"
    assert result.evidence["marker"] == "ACME-INVOICE-ALICE-1001"


def test_idor_not_proven_when_no_marker():
    verifier = IdorVerifier(["ACME-INVOICE-ALICE-1001"])
    execution = _exec(_step(0, '{"error":"forbidden"}', status=403))
    result = verifier.verify(_plan(), execution, PROGRAM)
    assert result.verdict == "not_proven"


def test_idor_inconclusive_without_markers():
    verifier = IdorVerifier([])
    execution = _exec(_step(0, "anything"))
    result = verifier.verify(_plan(), execution, PROGRAM)
    assert result.verdict == "inconclusive"


def test_idor_not_proven_on_incomplete_execution():
    verifier = IdorVerifier(["X"])
    execution = _exec(_step(0, "X"), failed=0, error="boom")
    result = verifier.verify(_plan(), execution, PROGRAM)
    assert result.verdict == "not_proven"


def _plan():
    from deslop.repro.steps import ReproPlanModel, ReproStep, StructuredRequest

    return ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(
                index=0,
                description="read invoice",
                request=StructuredRequest(url="http://staging/lab/api/invoices/1001"),
            )
        ],
    )
