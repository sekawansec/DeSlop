"""LLM provider abstraction.

The user picks their model. Supported providers:

- anthropic : Anthropic Messages API
- openai    : any OpenAI-compatible chat/completions endpoint
              (OpenAI, Azure, Together, Groq, vLLM, LM Studio, ...)
- ollama    : local models served by Ollama
- none      : no LLM; the pipeline routes to human review

Selection is via config/env (DESLOP_LLM_PROVIDER, DESLOP_LLM_MODEL, ...).
This module handles transport and JSON extraction only. Callers validate the
parsed JSON with Pydantic.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx

from ..config.settings import Settings, get_settings


class LLMError(RuntimeError):
    """Raised when an LLM call fails at the transport or parse level."""


@dataclass
class LLMResponse:
    text: str
    model: str
    raw: dict[str, Any] | None = None


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> LLMResponse: ...


def extract_json(text: str) -> Any:
    """Recover JSON from a model response that may wrap it in prose or fences."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = text.find(open_ch)
        end = text.rfind(close_ch)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except ValueError:
                continue
    raise LLMError("could not extract JSON from model response")


class NoneProvider:
    """A provider that always fails; used when no LLM is configured."""

    name = "none"
    model = ""

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        raise LLMError("no LLM provider is configured")


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, *, base_url: str = "https://api.anthropic.com",
                 timeout: float = 60.0, client: httpx.Client | None = None) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": 0,
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        owns = self._client is None
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            r = client.post(f"{self.base_url}/v1/messages", json=payload, headers=headers)
            if r.status_code >= 400:
                raise LLMError(f"anthropic HTTP {r.status_code}: {r.text[:300]}")
            data = r.json()
            parts = data.get("content", [])
            text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
            return LLMResponse(text=text, model=self.model, raw=data)
        finally:
            if owns:
                client.close()


class CompatibleProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, *, base_url: str = "https://api.openai.com/v1",
                 timeout: float = 60.0, client: httpx.Client | None = None) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        owns = self._client is None
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            r = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            if r.status_code >= 400:
                raise LLMError(f"openai HTTP {r.status_code}: {r.text[:300]}")
            data = r.json()
            text = data["choices"][0]["message"]["content"]
            return LLMResponse(text=text, model=self.model, raw=data)
        finally:
            if owns:
                client.close()


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, *, base_url: str = "http://localhost:11434",
                 timeout: float = 120.0, client: httpx.Client | None = None) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        owns = self._client is None
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            r = client.post(f"{self.base_url}/api/chat", json=payload)
            if r.status_code >= 400:
                raise LLMError(f"ollama HTTP {r.status_code}: {r.text[:300]}")
            data = r.json()
            text = data.get("message", {}).get("content", "")
            return LLMResponse(text=text, model=self.model, raw=data)
        finally:
            if owns:
                client.close()


def build_provider(settings: Settings | None = None) -> LLMProvider:
    """Construct the configured provider. Returns NoneProvider when unset."""
    settings = settings or get_settings()
    provider = settings.llm_provider
    model = settings.llm_model
    if provider == "none" or not model:
        return NoneProvider()
    if provider == "anthropic":
        return AnthropicProvider(settings.anthropic_api_key, model)
    if provider == "openai":
        base = settings.openai_base_url or "https://api.openai.com/v1"
        return CompatibleProvider(settings.openai_api_key, model, base_url=base)
    if provider == "ollama":
        return OllamaProvider(model, base_url=settings.ollama_base_url)
    return NoneProvider()
