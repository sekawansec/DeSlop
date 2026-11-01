from deslop.recipes.command_injection import CommandInjectionVerifier
from deslop.repro.interfaces import ExecutionResult, StepResult
from deslop.repro.steps import ReproPlanModel, ReproStep, StructuredRequest

ID_OUTPUT = "uid=33(www-data) gid=33(www-data)"


def _plan(url):
    return ReproPlanModel(
        bug_class="command_injection",
        steps=[ReproStep(index=0, description="x", request=StructuredRequest(url=url))],
    )


def _exec(url, body):
    return ExecutionResult(
        run_id="r",
        bug_class="command_injection",
        step_results=[
            StepResult(
                index=0,
                ok=True,
                request={"method": "GET", "url": url},
                response={"status_code": 200, "headers": {}, "body": body, "url": url},
            )
        ],
    )


def test_real_command_output_is_proven(program):
    url = "http://staging/ping?host=127.0.0.1;id"
    result = CommandInjectionVerifier().verify(
        _plan(url), _exec(url, f"PING ok\n{ID_OUTPUT} groups=33(www-data)"), program
    )
    assert result.verdict == "proven"


def test_reflected_id_output_is_not_proven(program):
    """An endpoint that echoes the payload back is reflection, not execution."""
    url = "http://staging/search?q=uid%3D33%28www-data%29%20gid%3D33%28www-data%29"
    result = CommandInjectionVerifier().verify(
        _plan(url), _exec(url, f"<p>No results for {ID_OUTPUT}</p>"), program
    )
    assert result.verdict == "not_proven"
    assert "reflection" in result.evidence["reason"]


def test_no_output_is_not_proven(program):
    url = "http://staging/ping?host=127.0.0.1"
    result = CommandInjectionVerifier().verify(_plan(url), _exec(url, "PING ok"), program)
    assert result.verdict == "not_proven"
