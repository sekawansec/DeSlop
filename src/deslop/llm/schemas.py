"""Schemas for LLM outputs. Every LLM result is validated against one of these."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ParsedHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    value: str


class ParsedStep(BaseModel):
    """One structured request parsed from the report's reproduction steps."""

    model_config = ConfigDict(extra="forbid")

    description: str = Field(..., description="what this step does, in one line")
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    # Which logical account performs this step, if stated (e.g. 'user_b').
    as_account: str | None = None
    # Verbatim sentence in the report this step came from.
    source_quote: str | None = None
    # A unique marker the report expects in the response, if any.
    marker: str | None = None


class ParsedPlan(BaseModel):
    """The full structured plan extracted from a report."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str = Field(..., description="canonical slug: idor, xss_reflected, xss_stored, ssrf, open_redirect")
    asset: str | None = None
    endpoint: str | None = None
    steps: list[ParsedStep] = Field(default_factory=list)
    missing_info: list[str] = Field(
        default_factory=list,
        description="specific information the report does not provide that is needed to reproduce",
    )


class ExtractedFields(BaseModel):
    """Field extraction for intake/filtering."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    asset: str | None = None
    endpoint: str | None = None
    vuln_class: str | None = None
    claimed_severity: str | None = None
    cwe: str | None = None
    root_cause_summary: str = Field("", description="one-sentence description of the root cause")


class DuplicateJudgement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(..., description="same_root_cause | same_asset_different_bug | unrelated")
    reasoning: str = ""


class DuplicateJudgements(BaseModel):
    model_config = ConfigDict(extra="forbid")

    judgements: list[DuplicateJudgement] = Field(default_factory=list)


class CVSSSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: str = Field(..., description="critical | high | medium | low | info")
    score: float | None = None
    vector: str | None = None
    reasoning: str = ""


class ReplyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str
