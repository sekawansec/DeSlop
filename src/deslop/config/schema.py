"""Pydantic models describing a single program's YAML configuration.

A "program" is one VDP / bug bounty scope. Everything policy-related is data
here, never hardcoded, so DeSlop stays generic across organizations.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low", "info"]

ScopeKind = Literal["domain", "wildcard", "ip_range", "app_id", "url"]


def normalize_host_pattern(value: str) -> str:
    """Reduce a scope/egress value to a bare host pattern.

    Operators habitually paste URL-ish values such as ``https://*.example.com/*``
    or ``api.example.com/path``. Matching happens on hosts, so the scheme, port,
    path, and a leading ``*.`` glob marker are preserved semantically: the return
    value is either ``*.<domain>``, a bare host/IP, or a CIDR (untouched).
    """
    v = value.strip().strip(".")
    if "://" in v:
        parsed = urlparse(v)
        host = parsed.hostname or ""
        v = host
        # ``*.example.com`` survives hostname parsing; keep the marker below.
        raw = parsed.netloc.split("@")[-1]
        if raw.startswith("*."):
            v = "*." + v.lstrip("*.")
    else:
        v = v.split("/", 1)[0]
        if ":" in v and v.count(":") == 1:
            v = v.split(":", 1)[0]
    return v.lower().strip(".")


def _netloc_of(value: str) -> str:
    """Like :func:`normalize_host_pattern` but preserves an explicit port."""
    v = value.strip()
    if "://" in v:
        parts = urlparse(v)
        host = (parts.hostname or "").lstrip("*.")
        return host if parts.port is None else f"{host}:{parts.port}"
    v = v.split("/", 1)[0]
    return v.lower().strip(".")


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

    @model_validator(mode="after")
    def _normalize(self) -> ScopeEntry:
        """Coerce pasted URL/glob values into the matching ``kind``.

        ``domain``/``wildcard``/``url`` values are host patterns; anything else
        (scheme, port, path) is stripped. A leading ``*.`` forces ``wildcard``;
        a ``wildcard`` without ``*.`` becomes ``domain`` (the closest intent:
        apex plus subdomains). ``ip_range``/``app_id`` values pass through.
        """
        if self.kind in {"ip_range", "app_id"}:
            return self
        v = normalize_host_pattern(self.value)
        if not v:
            raise ValueError("scope value has no usable host")
        if v.startswith("*."):
            object.__setattr__(self, "kind", "wildcard")
            if "*" in v[2:]:
                raise ValueError(f"'*' is only allowed as a '*.' prefix: {v!r}")
        else:
            if self.kind == "wildcard":
                object.__setattr__(self, "kind", "domain")
            if "*" in v:
                raise ValueError(f"'*' is only allowed as a '*.' prefix: {v!r}")
        object.__setattr__(self, "value", v)
        return self


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
    owned_markers: list[str] = Field(
        default_factory=list,
        description=(
            "secrets only this account's data should contain on staging "
            "(e.g. an invoice token). IDOR proof requires a marker owned by a "
            "different account to appear in a response; without these, IDOR "
            "verdicts stay inconclusive."
        ),
    )


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

    @field_validator("base_url")
    @classmethod
    def _normalize_base_url(cls, v: str) -> str:
        v = v.strip()
        if "://" not in v:
            v = "http://" + v
        parts = urlparse(v)
        host = (parts.hostname or "").lstrip("*.")
        if not host:
            raise ValueError("staging.base_url must contain a host")
        netloc = host if parts.port is None else f"{host}:{parts.port}"
        return f"{parts.scheme or 'http'}://{netloc}"

    @field_validator("host_map")
    @classmethod
    def _normalize_host_map(cls, v: dict[str, str]) -> dict[str, str]:
        """Keys are production hosts; values are staging host[:port] or URLs."""
        out: dict[str, str] = {}
        for prod, staging in v.items():
            prod_host = normalize_host_pattern(prod)
            staging_netloc = _netloc_of(staging)
            if prod_host and staging_netloc:
                out[prod_host] = staging_netloc
        return out


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


class CanaryConfig(BaseModel):
    """A unique token planted in staging that a real bug can reveal.

    Claims in ``required_for`` bug classes are expected to surface the canary
    value — either quoted in the report or observed in a reproduction response.
    A missing canary is flagged for the triager; it never auto-rejects.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    token: str = Field("", description="unique secret planted in staging, e.g. CANARY-<random>")
    owner: str | None = Field(
        None,
        description=(
            "test-account id whose data contains the canary. Required for the "
            "IDOR verifier to treat the canary as victim-owned proof; without "
            "an owner the canary only feeds the reviewer note."
        ),
    )
    required_for: list[str] = Field(
        default_factory=list,
        description="bug classes where the canary is the expected proof (e.g. idor, lfi)",
    )


class EvidenceRequirement(BaseModel):
    """Per-bug-class evidence checklist applied at intake.

    ``expect`` holds deterministic checks (see ``deslop.intake.evidence``);
    unmet items become follow-up questions for the researcher.
    """

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    expect: list[str] = Field(default_factory=list)


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
    allowed_egress_hosts: list[str] = Field(
        default_factory=list,
        description=(
            "staging-side hosts the sandbox may reach (bare host, 'host:port', "
            "'*.domain', or URL). In-scope production hosts are NOT implied here: "
            "reproducing against them requires allow_production or a per-report "
            "approve_production decision."
        ),
    )
    allow_production: bool = Field(
        False,
        description="permit automated reproduction against in-scope production hosts",
    )
    canary: CanaryConfig | None = None
    evidence_requirements: list[EvidenceRequirement] = Field(default_factory=list)

    @field_validator("allowed_egress_hosts")
    @classmethod
    def _normalize_egress(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for item in v:
            host = normalize_host_pattern(item)
            if host:
                out.append(host)
        return out

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
