"""Pydantic models describing a single program's YAML configuration.

A "program" is one VDP / bug bounty scope. Everything policy-related is data
here, never hardcoded, so DeSlop stays generic across organizations.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]

ScopeKind = Literal["domain", "wildcard", "ip_range", "app_id", "url"]


class ScopeEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: ScopeKind
    value: str = Field(..., description="e.g. example.com, *.example.com, 10.0.0.0/24, app-123")
    note: str | None = None

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("scope value must not be empty")
        return v


class ExcludedClass(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="stable slug, e.g. self-xss")
    match: list[str] = Field(
        default_factory=list,
        description="keywords/CWE ids that map to this excluded class, matched case-insensitively",
    )
    reason: str | None = None


class TestAccount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="logical name, e.g. user_a")
    role: str
    tenant: str | None = None
    username: str
    password: str = Field("", repr=False)
    otp_secret: str | None = Field(None, repr=False, description="TOTP seed for staging OTP")


class LoginConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["form", "api", "none"] = "none"
    url: str | None = None
    method: Literal["GET", "POST"] = "POST"
    username_field: str = "username"
    password_field: str = "password"
    otp_field: str | None = None
    extra_fields: dict[str, str] = Field(default_factory=dict)
    success_indicator: str | None = Field(
        None, description="substring or JSONPath expected in a successful login response"
    )
    session_cookie: str | None = Field(None, description="cookie name holding the session")
    # Anti-CSRF: when set, the login flow first GETs ``url``, extracts the token
    # from the named field, and submits it back with the credentials.
    csrf_field: str | None = Field(
        None, description="hidden form field carrying an anti-CSRF token, e.g. user_token"
    )
    csrf_regex: str | None = Field(
        None,
        description="optional regex (group 1) to extract the token; defaults to the field's value",
    )


class ResetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    method: Literal["GET", "POST"] = "POST"
    script: str | None = Field(None, description="path to a local reset/seed script")
    auth_header: str | None = Field(None, repr=False)


class StagingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str
    host_map: dict[str, str] = Field(
        default_factory=dict, description="production host -> staging host"
    )
    reset: ResetConfig | None = None


class DuplicateRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_count: int = 10
    similarity_threshold: float = 0.82
    same_asset_boost: float = 0.08
    same_endpoint_boost: float = 0.12
    auto_duplicate_threshold: float = 0.95


class BountyTier(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    amount: float = 0.0
    currency: str = "USD"
    note: str | None = None


class ReplyTemplates(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str = "en"
    received: str | None = None
    needs_info: str | None = None
    accepted: str | None = None
    not_accepted: str | None = None
    duplicate: str | None = None
    fixed: str | None = None


class StatusPageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    token_ttl: timedelta = Field(default=timedelta(days=90))
    base_url: str | None = Field(None, description="public base URL used to build status links")


class ProgramConfig(BaseModel):
    """Root model for one program YAML file."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="stable program slug; used as program_id everywhere")
    name: str
    in_scope: list[ScopeEntry] = Field(default_factory=list)
    out_of_scope: list[ScopeEntry] = Field(default_factory=list)
    excluded_classes: list[ExcludedClass] = Field(default_factory=list)
    staging: StagingConfig
    test_accounts: list[TestAccount] = Field(default_factory=list)
    login: LoginConfig = Field(default_factory=LoginConfig)
    duplicates: DuplicateRules = Field(default_factory=DuplicateRules)
    bounty: list[BountyTier] = Field(default_factory=list)
    replies: ReplyTemplates = Field(default_factory=ReplyTemplates)
    status_page: StatusPageConfig = Field(default_factory=StatusPageConfig)
    max_requests_per_run: int | None = None
    allowed_egress_hosts: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _slug(cls, v: str) -> str:
        v = v.strip()
        if not v or any(c.isspace() for c in v):
            raise ValueError("program id must be a non-empty slug without spaces")
        return v

    def account_by_role(self, role: str, tenant: str | None = None) -> list[TestAccount]:
        return [
            a
            for a in self.test_accounts
            if a.role == role and (tenant is None or a.tenant == tenant)
        ]

    def bounty_for(self, severity: Severity) -> BountyTier | None:
        for tier in self.bounty:
            if tier.severity == severity:
                return tier
        return None


ScopeEntryList = Annotated[list[ScopeEntry], Field(default_factory=list)]
