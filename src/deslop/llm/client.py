"""High-level LLM client with Pydantic validation, repair retries, and fallback.

``complete_validated`` runs the provider, parses and validates the JSON against a
Pydantic model, and on failure retries once with a repair prompt. If it still
fails, the caller receives ``None`` and is expected to route the report to
``needs_human_review``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from ..config.settings import Settings, get_settings
from .providers import LLMError, LLMProvider, build_provider, extract_json

log = logging.getLogger("deslop.llm")

T = TypeVar("T", bound=BaseModel)


@dataclass
class ValidatedResult:
    ok: bool
    value: BaseModel | None = None
    error: str | None = None
    attempts: int = 0
    repair_used: bool = False


class LLMClient:
    def __init__(self, provider: LLMProvider | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.provider = provider or build_provider(self.settings)

    @property
    def available(self) -> bool:
        return self.provider.name != "none"

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> str:
        return self.provider.complete(system=system, user=user, max_tokens=max_tokens).text

    def complete_validated(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int = 2048,
    ) -> ValidatedResult:
        """Run the LLM and validate the result against ``schema``.

        Retries once with a repair prompt on validation/parse failure. Returns a
        :class:`ValidatedResult`; never raises for model/parse errors.
        """
        if not self.available:
            return ValidatedResult(ok=False, error="no LLM provider configured", attempts=0)

        attempts = 0
        repair_used = False
        last_error: str | None = None
        prompt_user = user

        max_attempts = 1 + max(0, self.settings.llm_max_retries)
        while attempts < max_attempts:
            attempts += 1
            try:
                raw = self.provider.complete(system=system, user=prompt_user, max_tokens=max_tokens)
            except LLMError as exc:
                last_error = f"provider error: {exc}"
                if attempts >= max_attempts:
                    break
                continue

            try:
                data = extract_json(raw.text)
                value = schema.model_validate(data)
                return ValidatedResult(ok=True, value=value, attempts=attempts, repair_used=repair_used)
            except (LLMError, ValidationError) as exc:
                last_error = str(exc)
                log.warning("LLM output failed validation (attempt %d): %s", attempts, exc)
                if attempts < max_attempts:
                    repair_used = True
                    prompt_user = _repair_prompt(user, raw.text, last_error)

        return ValidatedResult(
            ok=False, error=last_error or "validation failed", attempts=attempts, repair_used=repair_used
        )


def _repair_prompt(original_user: str, bad_output: str, error: str) -> str:
    return (
        f"{original_user}\n\n"
        "---\n"
        "Your previous response could not be parsed as the required JSON. "
        f"Error: {error}\n"
        "Previous response was:\n"
        f"{bad_output[:2000]}\n\n"
        "Return ONLY valid JSON matching the required schema. No prose, no markdown."
    )
