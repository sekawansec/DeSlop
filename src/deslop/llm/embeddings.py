"""Embedding abstraction.

Default is a local multilingual model (bge-m3) so fully-local mode needs no
outbound connection. OpenAI- and Ollama-backed embeddings are available when a
deployment prefers them. A dependency-free hashing embedder is included for
tests and CI.
"""

from __future__ import annotations

import hashlib
import math
import re

import httpx

from ..config.settings import Settings, get_settings


def _normalize(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0:
        return vec
    return [x / norm for x in vec]


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_]+", text.lower())


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class HashingEmbedder:
    """Deterministic, dependency-free fallback embedder."""

    name = "hashing"

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in _tokenize(text):
            h = int(hashlib.blake2b(token.encode("utf-8"), digest_size=8).hexdigest(), 16)
            idx = h % self.dim
            sign = 1.0 if (h >> 8) & 1 else -1.0
            vec[idx] += sign
        return _normalize(vec)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(t) for t in texts]


class LocalEmbedder:
    """Local sentence-transformers model (default: BAAI/bge-m3)."""

    name = "local"

    def __init__(self, model_name: str = "BAAI/bge-m3") -> None:
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name
        self._model = SentenceTransformer(model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self._model.encode(texts, normalize_embeddings=True)
        return [list(map(float, v)) for v in vectors]


class CompatibleEmbedder:
    name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        dim: int = 1536,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        r = httpx.post(
            f"{self.base_url}/embeddings",
            headers={"authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "input": texts},
            timeout=60.0,
        )
        r.raise_for_status()
        return [item["embedding"] for item in r.json()["data"]]


class OllamaEmbedder:
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        dim: int = 1024,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for t in texts:
            r = httpx.post(
                f"{self.base_url}/api/embeddings",
                json={"model": self.model, "prompt": t},
                timeout=120.0,
            )
            r.raise_for_status()
            vectors.append(r.json()["embedding"])
        return vectors


def build_embedder(settings: Settings | None = None) -> object:
    """Construct the configured embedder, falling back to hashing if unavailable."""
    settings = settings or get_settings()
    provider = settings.embedding_provider
    try:
        if provider == "local":
            return LocalEmbedder(settings.embedding_model)
        if provider == "openai":
            return CompatibleEmbedder(
                settings.openai_api_key, settings.embedding_model, dim=settings.embedding_dim
            )
        if provider == "ollama":
            return OllamaEmbedder(
                settings.embedding_model,
                base_url=settings.ollama_base_url,
                dim=settings.embedding_dim,
            )
    except Exception:
        return HashingEmbedder(settings.embedding_dim)
    return HashingEmbedder(settings.embedding_dim)
