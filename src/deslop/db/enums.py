"""Enumerations shared across the pipeline, data model, and UI.

Internal statuses are *never* shown to researchers; the public status is a
deliberately smaller, triager-controlled set.
"""

from __future__ import annotations

from enum import StrEnum


class ReportStatus(StrEnum):
    """Internal pipeline status. Never exposed to researchers."""

    RECEIVED = "received"
    FILTERING = "filtering"
    PARSING = "parsing"
    VALIDATING = "validating"
    REPRODUCING = "reproducing"
    VERIFYING = "verifying"
    REPRODUCED = "reproduced"
    REPRODUCED_WITH_DEVIATION = "reproduced_with_deviation"
    NEEDS_INFO = "needs_info"
    FAILED_REPLAY = "failed_replay"
    MANUAL_REPRODUCTION_REQUIRED = "manual_reproduction_required"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED_CLASS = "excluded_class"
    DUPLICATE = "duplicate"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    CLOSED = "closed"


class PublicStatus(StrEnum):
    """Statuses a researcher may see on the status page."""

    RECEIVED = "received"
    UNDER_REVIEW = "under_review"
    NEEDS_INFO = "needs_info"
    ACCEPTED = "accepted"
    NOT_ACCEPTED = "not_accepted"
    DUPLICATE = "duplicate"
    FIXED = "fixed"


class ReproRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class Verdict(StrEnum):
    """Verifier outcome. 'proven' is the only positive result."""

    PROVEN = "proven"
    NOT_PROVEN = "not_proven"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class RoutingCategory(StrEnum):
    REPRODUCED = "reproduced"
    REPRODUCED_WITH_DEVIATION = "reproduced_with_deviation"
    NEEDS_INFO = "needs_info"
    FAILED_REPLAY = "failed_replay"
    MANUAL_REPRODUCTION_REQUIRED = "manual_reproduction_required"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED_CLASS = "excluded_class"
    DUPLICATE = "duplicate"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class DuplicateVerdict(StrEnum):
    SAME_ROOT_CAUSE = "same_root_cause"
    SAME_ASSET_DIFFERENT_BUG = "same_asset_different_bug"
    UNRELATED = "unrelated"


class MessageDirection(StrEnum):
    TO_RESEARCHER = "to_researcher"
    FROM_RESEARCHER = "from_researcher"


class Decision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DUPLICATE = "duplicate"
    REQUEST_INFO = "request_info"
    APPROVE_DEVIATION = "approve_deviation"
    APPROVE_PRODUCTION = "approve_production"
    UPDATE_PUBLIC_STATUS = "update_public_status"
    REVOKE_TOKEN = "revoke_token"
    SEND_REPLY = "send_reply"


#: Bug classes with a built-in recipe in v1.
SUPPORTED_BUG_CLASSES = frozenset({
    "idor",
    "xss_reflected",
    "xss_stored",
    "ssrf",
    "open_redirect",
    "command_injection",
})
