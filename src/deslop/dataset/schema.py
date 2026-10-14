"""Schema for the synthetic evaluation dataset.

Every generated report carries a ground-truth label used by the eval harness.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Label(StrEnum):
    """Ground-truth category of a synthetic report."""

    VALID = "valid"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED_CLASS = "excluded_class"
    SLOP = "slop"
    INCOMPLETE = "incomplete"
    INJECTION = "injection"


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    kind: str
    content: str


class SyntheticReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: Label
    title: str
    body: str
    asset: str
    endpoint: str | None = None
    vuln_class: str | None = None
    claimed_severity: str | None = None
    attachments: list[Attachment] = Field(default_factory=list)
    # Ground-truth helpers for scoring.
    duplicate_of: str | None = None
    injection_attempt: bool = False
    reproducible: bool = False
    notes: str | None = None


class DatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program_id: str = "lab"
    seed: int
    count: int
    by_label: dict[str, int]
