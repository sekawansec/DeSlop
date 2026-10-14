import httpx

from deslop.config.schema import (
    LoginConfig,
    ProgramConfig,
    ScopeEntry,
    StagingConfig,
    TestAccount,
)
from deslop.config.settings import Settings
from deslop.repro.executor import WebExecutor, redact
from deslop.repro.steps import ReproPlanModel, ReproStep, StructuredRequest

PROGRAM = ProgramConfig(
    id="demo",
    name="Demo",
    in_scope=[ScopeEntry(kind="wildcard", value="*.demo.test")],
    staging=StagingConfig(base_url="https://staging.demo.test"),
    test_accounts=[
        TestAccount(id="user_a", role="user", username="a", password="a"),
        TestAccount(id="user_b", role="user", username="b", password="b"),
    ],
    login=LoginConfig(kind="none"),
)


def _client_factory(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler), timeout=5.0)


def test_executor_adds_validator_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["header"] = request.headers.get("X-Repro-Validator")
        return httpx.Response(200, text="ok")

    executor = WebExecutor(Settings(_env_file=None), _client_factory(handler))
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[ReproStep(index=0, description="x", request=StructuredRequest(url="https://staging.demo.test/a"))],
    )
    result = executor.execute(plan, PROGRAM, run_id="run-abc")
    assert seen["header"] == "run-abc"
    assert result.completed
    assert result.step_results[0].response["status_code"] == 200


def test_executor_redacts_credentials_in_log():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    executor = WebExecutor(Settings(_env_file=None), _client_factory(handler))
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(
                index=0,
                description="x",
                request=StructuredRequest(
                    url="https://staging.demo.test/a",
                    headers={"Authorization": "Bearer supersecret"},
                ),
            )
        ],
    )
    result = executor.execute(plan, PROGRAM)
    logged_headers = result.step_results[0].request["headers"]
    assert logged_headers["Authorization"] == "<redacted>"


def test_executor_stops_on_network_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    executor = WebExecutor(Settings(_env_file=None), _client_factory(handler))
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(index=0, description="x", request=StructuredRequest(url="https://staging.demo.test/a")),
            ReproStep(index=1, description="y", request=StructuredRequest(url="https://staging.demo.test/b")),
        ],
    )
    result = executor.execute(plan, PROGRAM)
    assert result.failed_step_index == 0
    assert len(result.step_results) == 1


def test_executor_stops_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="down")

    executor = WebExecutor(Settings(_env_file=None), _client_factory(handler))
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(index=0, description="x", request=StructuredRequest(url="https://staging.demo.test/a")),
            ReproStep(index=1, description="y", request=StructuredRequest(url="https://staging.demo.test/b")),
        ],
    )
    result = executor.execute(plan, PROGRAM)
    assert result.failed_step_index == 0
    assert "503" in result.error


def test_executor_request_limit():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    settings = Settings(_env_file=None, max_requests_per_run=1)
    executor = WebExecutor(settings, _client_factory(handler))
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            ReproStep(index=0, description="x", request=StructuredRequest(url="https://staging.demo.test/a")),
            ReproStep(index=1, description="y", request=StructuredRequest(url="https://staging.demo.test/b")),
        ],
    )
    result = executor.execute(plan, PROGRAM)
    assert result.failed_step_index == 1
    assert "limit" in result.error


def test_redact_helper():
    assert redact({"Cookie": "abc", "X-Foo": "bar"}) == {"Cookie": "<redacted>", "X-Foo": "bar"}
