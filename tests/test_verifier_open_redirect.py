from deslop.recipes.open_redirect import OpenRedirectVerifier
from deslop.repro.interfaces import ExecutionResult, StepResult
from deslop.repro.steps import ReproPlanModel, ReproStep, StepExpectation, StructuredRequest

MARKER_URL = "https://marker.deslop.test/landing"


def _plan():
    return ReproPlanModel(
        bug_class="open_redirect",
        steps=[
            ReproStep(
                index=0,
                description="open redirect",
                request=StructuredRequest(url=f"http://staging/lab/redirect?next={MARKER_URL}"),
                expectation=StepExpectation(marker=MARKER_URL),
            )
        ],
    )


def _exec(status, location, url="http://staging/lab/redirect?next=x"):
    headers = {"Location": location} if location else {}
    return ExecutionResult(
        run_id="r",
        bug_class="open_redirect",
        step_results=[
            StepResult(
                index=0,
                ok=True,
                request={"url": url},
                response={"status_code": status, "headers": headers, "body": "", "url": url},
            )
        ],
    )


def test_open_redirect_proven_via_location_header(program):
    result = OpenRedirectVerifier().verify(_plan(), _exec(302, MARKER_URL), program)
    assert result.verdict == "proven"
    assert result.evidence["method"] == "location_header"


def test_open_redirect_not_proven_for_bad_location(program):
    result = OpenRedirectVerifier().verify(_plan(), _exec(302, "https://safe.example.org/"), program)
    assert result.verdict == "not_proven"


def test_open_redirect_proven_via_browser(fake_browser, program):
    fake_browser(final_url=MARKER_URL)
    result = OpenRedirectVerifier().verify(_plan(), _exec(200, None), program)
    assert result.verdict == "proven"
    assert result.evidence["method"] == "browser"


def test_open_redirect_not_proven_via_browser(fake_browser, program):
    fake_browser(final_url="http://staging/lab/home")
    result = OpenRedirectVerifier().verify(_plan(), _exec(200, None), program)
    assert result.verdict == "not_proven"


def test_open_redirect_not_proven_on_incomplete(program):
    execution = _exec(302, MARKER_URL)
    execution.failed_step_index = 0
    execution.error = "boom"
    result = OpenRedirectVerifier().verify(_plan(), execution, program)
    assert result.verdict == "not_proven"
