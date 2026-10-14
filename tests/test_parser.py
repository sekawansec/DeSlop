from deslop.config.settings import Settings
from deslop.llm.client import LLMClient
from deslop.llm.providers import LLMResponse
from deslop.parser.step_parser import StepParser, canonical_bug_class, parse_from_raw_http

RAW_HTTP_REPORT = """IDOR on invoices.

Steps:
1. Login as bob.
2. Send this request:

GET /api/invoices/1001 HTTP/1.1
Host: api.lab.test
Cookie: session=bob-session

3. Observe alice's invoice is returned.
"""


class FakeProvider:
    name = "fake"
    model = "fake-1"

    def __init__(self, text):
        self._text = text

    def complete(self, *, system, user, max_tokens=2048):
        return LLMResponse(text=self._text, model=self.model)


def test_canonical_bug_class():
    assert canonical_bug_class("IDOR") == "idor"
    assert canonical_bug_class("Reflected XSS") == "xss_reflected"
    assert canonical_bug_class("Server-Side Request Forgery") == "ssrf"
    assert canonical_bug_class("open redirect") == "open_redirect"
    assert canonical_bug_class(None) == "unknown"


def test_parse_from_raw_http_extracts_step():
    outcome = parse_from_raw_http(RAW_HTTP_REPORT)
    assert outcome is not None
    assert outcome.ok
    plan = outcome.plan
    assert plan.bug_class == "idor"
    assert len(plan.steps) == 1
    assert plan.steps[0].request.method == "GET"
    assert plan.steps[0].request.url == "http://api.lab.test/api/invoices/1001"


def test_parse_from_raw_http_returns_none_without_request():
    assert parse_from_raw_http("Just prose, no request block here.") is None


def test_parser_uses_llm_when_available():
    llm_json = (
        '{"bug_class": "idor", "asset": "api.lab.test", "endpoint": "/api/invoices/1001",'
        ' "steps": [{"description": "read invoice", "method": "GET",'
        ' "url": "https://api.lab.test/api/invoices/1001", "source_quote": "GET /api/invoices/1001",'
        ' "as_account": "user_b"}], "missing_info": []}'
    )
    provider = FakeProvider(llm_json)
    client = LLMClient(provider=provider, settings=Settings(_env_file=None))
    parser = StepParser(client=client)
    outcome = parser.parse(RAW_HTTP_REPORT)
    assert outcome.ok
    assert outcome.used_llm
    assert outcome.plan.bug_class == "idor"
    assert outcome.plan.steps[0].as_account == "user_b"
    assert outcome.plan.steps[0].source.quote == "GET /api/invoices/1001"


def test_parser_falls_back_to_raw_http_when_llm_unavailable():
    client = LLMClient(settings=Settings(_env_file=None, llm_provider="none"))
    parser = StepParser(client=client)
    outcome = parser.parse(RAW_HTTP_REPORT)
    assert outcome.ok
    assert outcome.used_fallback
    assert not outcome.used_llm


def test_parser_reports_failure_without_llm_or_raw_http():
    client = LLMClient(settings=Settings(_env_file=None, llm_provider="none"))
    parser = StepParser(client=client)
    outcome = parser.parse("A vague report with no request and no steps.")
    assert not outcome.ok
    assert outcome.plan is None


def test_parser_llm_invalid_json_does_not_guess():
    provider = FakeProvider("this is not json")
    client = LLMClient(provider=provider, settings=Settings(_env_file=None, llm_max_retries=0))
    parser = StepParser(client=client)
    # fallback allowed: report has raw http so it should fall back
    outcome = parser.parse(RAW_HTTP_REPORT)
    assert outcome.ok
    assert outcome.used_fallback
