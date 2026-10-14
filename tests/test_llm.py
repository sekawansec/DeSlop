import httpx
import pytest

from deslop.config.settings import Settings
from deslop.llm.embeddings import HashingEmbedder, build_embedder, cosine
from deslop.llm.providers import (
    AnthropicProvider,
    CompatibleProvider,
    LLMError,
    NoneProvider,
    OllamaProvider,
    build_provider,
    extract_json,
)


def test_extract_json_plain():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    text = "here you go:\n```json\n{\"a\": 1}\n```\nthanks"
    assert extract_json(text) == {"a": 1}


def test_extract_json_embedded_prose():
    assert extract_json('The answer is {"a": [1,2,3]} ok') == {"a": [1, 2, 3]}


def test_extract_json_failure():
    with pytest.raises(LLMError):
        extract_json("no json here at all")


def test_none_provider_raises():
    with pytest.raises(LLMError):
        NoneProvider().complete(system="s", user="u")


def test_build_provider_none_when_unset():
    assert build_provider(Settings(_env_file=None, llm_provider="none")).name == "none"
    empty_model = Settings(_env_file=None, llm_provider="openai", llm_model="")
    assert build_provider(empty_model).name == "none"


def test_build_provider_ollama():
    p = build_provider(Settings(_env_file=None, llm_provider="ollama", llm_model="llama3"))
    assert p.name == "ollama"
    assert p.model == "llama3"


def test_anthropic_provider_parses_response():
    def handler(request):
        return httpx.Response(200, json={"content": [{"type": "text", "text": "hello"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    p = AnthropicProvider("key", "claude-x", client=client)
    assert p.complete(system="s", user="u").text == "hello"


def test_compatible_provider_parses_response():
    def handler(request):
        assert request.headers.get("authorization") == "Bearer key"
        return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    p = CompatibleProvider("key", "gpt-x", client=client)
    assert p.complete(system="s", user="u").text == "hi"


def test_ollama_provider_parses_response():
    def handler(request):
        return httpx.Response(200, json={"message": {"content": "local"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    p = OllamaProvider("llama3", client=client)
    assert p.complete(system="s", user="u").text == "local"


def test_provider_http_error_raises():
    def handler(request):
        return httpx.Response(500, text="boom")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError):
        CompatibleProvider("k", "m", client=client).complete(system="s", user="u")


def test_hashing_embedder_is_deterministic_and_normalized():
    e = HashingEmbedder(32)
    a = e.embed(["hello world"])[0]
    b = e.embed(["hello world"])[0]
    assert a == b
    assert abs(sum(x * x for x in a) - 1.0) < 1e-6


def test_cosine_similarity():
    e = HashingEmbedder(128)
    v1, v2, v3 = e.embed(["idor invoice access control", "idor invoice access control", "reflected xss search"])
    assert cosine(v1, v2) > cosine(v1, v3)


def test_build_embedder_falls_back_to_hashing():
    e = build_embedder(Settings(_env_file=None, embedding_provider="local", embedding_dim=48))
    assert e.name in {"local", "hashing"}
    assert len(e.embed(["x"])[0]) == e.dim
