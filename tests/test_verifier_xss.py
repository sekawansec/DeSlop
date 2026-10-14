from deslop.recipes.xss import ReflectedXssVerifier, StoredXssVerifier
from deslop.repro.interfaces import ExecutionResult, StepResult
from deslop.repro.steps import ReproPlanModel, ReproStep, StepExpectation, StructuredRequest

MARKER = "XSS_REFLECTED_MARKER"


def _plan(url="http://staging/lab/search?q=x"):
    return ReproPlanModel(
        bug_class="xss_reflected",
        steps=[
            ReproStep(
                index=0,
                description="reflected xss",
                request=StructuredRequest(url=url),
                expectation=StepExpectation(marker=MARKER),
            )
        ],
    )


def _exec(body, url="http://staging/lab/search?q=x", failed=None):
    return ExecutionResult(
        run_id="r",
        bug_class="xss_reflected",
        step_results=[
            StepResult(
                index=0,
                ok=True,
                request={"url": url},
                response={"status_code": 200, "headers": {}, "body": body, "url": url},
            )
        ],
        failed_step_index=failed,
    )


def test_reflected_xss_proven_when_marker_executes(fake_browser, program):
    fake_browser(markers=[MARKER], final_url="http://staging/lab/search?q=x")
    result = ReflectedXssVerifier().verify(_plan(), _exec("<html>...marker...</html>"), program)
    assert result.verdict == "proven"
    assert result.evidence["marker"] == MARKER


def test_reflected_xss_not_proven_when_no_execution(fake_browser, program):
    fake_browser(markers=[], final_url="http://staging/lab/search?q=x")
    result = ReflectedXssVerifier().verify(_plan(), _exec("<p>Results for: x</p>"), program)
    assert result.verdict == "not_proven"


def test_xss_error_surfaced(fake_browser, program):
    fake_browser(error="TimeoutError: nav")
    result = ReflectedXssVerifier().verify(_plan(), _exec("<html></html>"), program)
    assert result.verdict == "error"


def test_xss_inconclusive_without_marker(fake_browser, program):
    fake_browser(markers=[MARKER])
    plan = ReproPlanModel(
        bug_class="xss_reflected",
        steps=[ReproStep(index=0, description="x", request=StructuredRequest(url="http://s/x"))],
    )
    result = ReflectedXssVerifier().verify(plan, _exec("body"), program)
    assert result.verdict == "inconclusive"


def test_stored_xss_proven(fake_browser, program):
    fake_browser(markers=[MARKER], final_url="http://staging/lab/comments")
    result = StoredXssVerifier().verify(_plan("http://staging/lab/comments"), _exec("<script>" + MARKER + "</script>", url="http://staging/lab/comments"), program)
    assert result.verdict == "proven"


def test_xss_not_proven_on_incomplete_execution(fake_browser, program):
    fake_browser(markers=[MARKER])
    result = ReflectedXssVerifier().verify(_plan(), _exec("x", failed=0), program)
    assert result.verdict == "not_proven"
