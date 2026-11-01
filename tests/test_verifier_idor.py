from deslop.config.schema import (
    CanaryConfig,
    ProgramConfig,
    StagingConfig,
    TestAccount,
)
from deslop.recipes.idor import IdorVerifier
from deslop.repro.interfaces import ExecutionResult, StepResult

PROGRAM = ProgramConfig(
    id="lab",
    name="Lab",
    staging=StagingConfig(base_url="http://x"),
    test_accounts=[
        TestAccount(
            id="user_a",
            role="user",
            username="alice",
            password="x",
            owned_markers=["ACME-INVOICE-ALICE-1001"],
        ),
        TestAccount(
            id="user_b",
            role="user",
            username="bob",
            password="x",
            owned_markers=["ACME-INVOICE-BOB-1002"],
        ),
    ],
)


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


def _plan(as_account="user_b", marker=None):
    from deslop.repro.steps import (
        ReproPlanModel,
        ReproStep,
        StepExpectation,
        StructuredRequest,
    )

    return ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(
                index=0,
                description="read invoice",
                request=StructuredRequest(url="http://staging/lab/api/invoices/1001"),
                as_account=as_account,
                expectation=StepExpectation(marker=marker) if marker else None,
            )
        ],
    )


def test_idor_proven_when_victim_secret_in_other_accounts_response():
    verifier = IdorVerifier()
    execution = _exec(_step(0, '{"id":1001,"owner":"alice","secret":"ACME-INVOICE-ALICE-1001"}'))
    result = verifier.verify(_plan(as_account="user_b"), execution, PROGRAM)
    assert result.verdict == "proven"
    assert result.evidence["marker"] == "ACME-INVOICE-ALICE-1001"
    assert result.evidence["owner"] == "user_a"
    assert result.evidence["requester"] == "user_b"


def test_idor_not_proven_when_account_reads_own_data():
    """Alice fetching her own invoice returns her marker but proves nothing."""
    verifier = IdorVerifier()
    execution = _exec(_step(0, '{"id":1001,"owner":"alice","secret":"ACME-INVOICE-ALICE-1001"}'))
    result = verifier.verify(_plan(as_account="user_a"), execution, PROGRAM)
    assert result.verdict == "not_proven"


def test_idor_proven_for_unauthenticated_access_to_victim_data():
    verifier = IdorVerifier()
    execution = _exec(_step(0, '{"secret":"ACME-INVOICE-ALICE-1001"}'))
    result = verifier.verify(_plan(as_account=None), execution, PROGRAM)
    assert result.verdict == "proven"
    assert result.evidence["requester"] is None


def test_idor_ignores_marker_supplied_by_report():
    """A marker in the report's own expectation is untrusted — never proof."""
    verifier = IdorVerifier()
    execution = _exec(_step(0, '{"note":"EVIL-MARKER-FROM-REPORT"}'))
    result = verifier.verify(
        _plan(as_account="user_b", marker="EVIL-MARKER-FROM-REPORT"), execution, PROGRAM
    )
    assert result.verdict == "not_proven"


def test_idor_not_proven_when_no_marker():
    verifier = IdorVerifier()
    execution = _exec(_step(0, '{"error":"forbidden"}', status=403))
    result = verifier.verify(_plan(), execution, PROGRAM)
    assert result.verdict == "not_proven"


def test_idor_inconclusive_without_owned_markers():
    verifier = IdorVerifier()
    program = PROGRAM.model_copy(update={"test_accounts": []})
    execution = _exec(_step(0, "anything"))
    result = verifier.verify(_plan(), execution, program)
    assert result.verdict == "inconclusive"


def test_idor_canary_only_proves_when_owned():
    """An unowned canary is reviewer-note material, not IDOR proof."""
    token = "CANARY-123"
    execution = _exec(_step(0, f'{{"leak":"{token}"}}'))

    no_owner = PROGRAM.model_copy(
        update={"canary": CanaryConfig(enabled=True, token=token, required_for=["idor"])}
    )
    result = IdorVerifier().verify(_plan(), execution, no_owner)
    assert result.verdict == "not_proven"

    owned = PROGRAM.model_copy(
        update={
            "canary": CanaryConfig(
                enabled=True, token=token, owner="user_a", required_for=["idor"]
            )
        }
    )
    result = IdorVerifier().verify(_plan(), execution, owned)
    assert result.verdict == "proven"
    assert result.evidence["owner"] == "user_a"


def test_idor_not_proven_on_incomplete_execution():
    verifier = IdorVerifier()
    execution = _exec(_step(0, "X"), failed=0, error="boom")
    result = verifier.verify(_plan(), execution, PROGRAM)
    assert result.verdict == "not_proven"
