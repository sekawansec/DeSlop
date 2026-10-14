from deslop.config.settings import Settings
from deslop.llm.client import LLMClient
from deslop.llm.providers import LLMError, LLMResponse
from deslop.llm.schemas import ReplyDraft


class ScriptedProvider:
    def __init__(self, responses):
        self.name = "scripted"
        self.model = "scripted-1"
        self._responses = list(responses)
        self.calls = 0

    def complete(self, *, system, user, max_tokens=2048):
        self.calls += 1
        r = self._responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return LLMResponse(text=r, model=self.model)


def test_valid_json_first_try():
    p = ScriptedProvider(['{"body": "hello"}'])
    client = LLMClient(provider=p, settings=Settings(_env_file=None))
    result = client.complete_validated(system="s", user="u", schema=ReplyDraft)
    assert result.ok
    assert result.value.body == "hello"
    assert result.attempts == 1
    assert not result.repair_used


def test_repair_on_invalid_json():
    p = ScriptedProvider(["not json", '{"body": "fixed"}'])
    client = LLMClient(provider=p, settings=Settings(_env_file=None, llm_max_retries=2))
    result = client.complete_validated(system="s", user="u", schema=ReplyDraft)
    assert result.ok
    assert result.value.body == "fixed"
    assert result.attempts == 2
    assert result.repair_used
    assert p.calls == 2


def test_falls_back_after_repair_fails():
    p = ScriptedProvider(["nope", "still nope"])
    client = LLMClient(provider=p, settings=Settings(_env_file=None, llm_max_retries=1))
    result = client.complete_validated(system="s", user="u", schema=ReplyDraft)
    assert not result.ok
    assert result.value is None


def test_provider_error_then_repair_succeeds():
    p = ScriptedProvider([LLMError("boom"), '{"body": "recovered"}'])
    client = LLMClient(provider=p, settings=Settings(_env_file=None, llm_max_retries=2))
    result = client.complete_validated(system="s", user="u", schema=ReplyDraft)
    assert result.ok
    assert result.value.body == "recovered"


def test_unavailable_provider_reports_not_ok():
    client = LLMClient(settings=Settings(_env_file=None, llm_provider="none"))
    assert not client.available
    result = client.complete_validated(system="s", user="u", schema=ReplyDraft)
    assert not result.ok
    assert result.value is None
