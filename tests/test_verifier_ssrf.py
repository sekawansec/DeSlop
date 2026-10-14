import httpx

from deslop.recipes.ssrf import OobClient, SsrfVerifier
from deslop.repro.interfaces import ExecutionResult, StepResult
from deslop.repro.steps import ReproPlanModel, ReproStep, StructuredRequest

TOKEN = "abcdef0123456789abcdef0123456789"


def _plan(url=f"http://staging/lab/api/fetch?url=http://{TOKEN}.oob.test/cb"):
    return ReproPlanModel(
        bug_class="ssrf",
        steps=[ReproStep(index=0, description="ssrf", request=StructuredRequest(url=url))],
    )


def _exec():
    return ExecutionResult(
        run_id="r",
        bug_class="ssrf",
        step_results=[
            StepResult(index=0, ok=True, request={"url": "http://s/lab"}, response={"status_code": 200, "headers": {}, "body": "{}", "url": "http://s/lab"})
        ],
    )


class FakeOob:
    def __init__(self, hits):
        self._hits = hits

    def hits_for(self, token):
        return self._hits if token == TOKEN else []


def test_ssrf_proven_on_oob_callback(program):
    verifier = SsrfVerifier(oob_client=FakeOob([{"token": TOKEN, "client": "10.0.0.5"}]))
    result = verifier.verify(_plan(), _exec(), program)
    assert result.verdict == "proven"
    assert result.evidence["hit_count"] == 1


def test_ssrf_not_proven_without_callback(program):
    verifier = SsrfVerifier(oob_client=FakeOob([]))
    result = verifier.verify(_plan(), _exec(), program)
    assert result.verdict == "not_proven"


def test_ssrf_inconclusive_without_token(program):
    verifier = SsrfVerifier(oob_client=FakeOob([]))
    plan = ReproPlanModel(
        bug_class="ssrf",
        steps=[ReproStep(index=0, description="x", request=StructuredRequest(url="http://s/lab/fetch?url=x"))],
    )
    result = verifier.verify(plan, _exec(), program)
    assert result.verdict == "inconclusive"


def test_ssrf_error_when_oob_unreachable(program):
    def raise_exc(request):
        raise httpx.ConnectError("no oob", request=request)

    client = httpx.Client(transport=httpx.MockTransport(raise_exc))
    verifier = SsrfVerifier(oob_client=OobClient("http://oob:8080", client=client))
    result = verifier.verify(_plan(), _exec(), program)
    assert result.verdict == "error"


def test_oob_client_real_shape(program):
    def handler(request):
        assert "/hits/" in request.url.path
        return httpx.Response(200, json={"token": TOKEN, "count": 1, "hits": [{"token": TOKEN}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    oob = OobClient("http://oob:8080", client=client)
    assert oob.hits_for(TOKEN) == [{"token": TOKEN}]
