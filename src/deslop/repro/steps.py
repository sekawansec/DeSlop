"""Structured reproduction plan models.

The LLM parser produces :class:`ReproStep` objects. These are *locked*: the
executor runs them exactly as written, applying only whitelisted substitutions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


class SourceRef(BaseModel):
    """Back-reference from a step to the sentence/line it was parsed from."""

    model_config = ConfigDict(extra="forbid")

    quote: str = Field(..., description="verbatim snippet from the report")
    start: int | None = Field(None, description="character offset in the report body")
    end: int | None = None


class StructuredRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: HttpMethod = "GET"
    url: str = Field(..., description="absolute or host-relative URL as written in the report")
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    cookies: dict[str, str] = Field(default_factory=dict)

    @field_validator("method", mode="before")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper() if isinstance(v, str) else v


class StepExpectation(BaseModel):
    """What the report claims should happen; used for detection/verification hints."""

    model_config = ConfigDict(extra="forbid")

    description: str | None = None
    marker: str | None = Field(
        None, description="unique token expected in the response (e.g. XSS marker)"
    )
    status_code: int | None = None


class ReproStep(BaseModel):
    """One request/action in the reproduction plan."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(..., ge=0)
    description: str
    request: StructuredRequest
    expectation: StepExpectation | None = None
    source: SourceRef | None = None
    # Which logical account (from program config) should carry this step.
    as_account: str | None = Field(
        None, description="logical test-account id, e.g. user_b"
    )


class ReproPlanModel(BaseModel):
    """A complete, ordered, locked reproduction plan."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    steps: list[ReproStep]

    @field_validator("steps")
    @classmethod
    def _ordered(cls, v: list[ReproStep]) -> list[ReproStep]:
        if [s.index for s in v] != list(range(len(v))):
            raise ValueError("step indices must be contiguous starting at 0")
        return v
