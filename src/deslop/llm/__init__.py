"""LLM and embedding abstraction layer.

The user chooses the model via config. All LLM output is validated with Pydantic
by the caller; on failure we retry with a repair prompt, then fall back to
needs_human_review. The LLM never decides whether a bug is proven.
"""

from .embeddings import (
    CompatibleEmbedder,
    HashingEmbedder,
    LocalEmbedder,
    OllamaEmbedder,
    build_embedder,
    cosine,
)
from .providers import (
    AnthropicProvider,
    CompatibleProvider,
    LLMError,
    LLMProvider,
    LLMResponse,
    NoneProvider,
    OllamaProvider,
    build_provider,
    extract_json,
)

__all__ = [
    "AnthropicProvider",
    "CompatibleEmbedder",
    "CompatibleProvider",
    "HashingEmbedder",
    "LLMError",
    "LLMProvider",
    "LLMResponse",
    "LocalEmbedder",
    "NoneProvider",
    "OllamaEmbedder",
    "OllamaProvider",
    "build_embedder",
    "build_provider",
    "cosine",
    "extract_json",
]
