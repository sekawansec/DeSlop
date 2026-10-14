"""Tracks whether first-run setup has been completed.

A small JSON file (``DESLOP_SETUP_STATE_FILE``) records the state so it survives
restarts. The wizard is shown until ``complete`` is true.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..config.settings import Settings, get_settings


def _state_path(settings: Settings) -> Path:
    return Path(getattr(settings, "setup_state_file", "./data/setup.json"))


@dataclass
class SetupState:
    complete: bool = False
    completed_at: str | None = None
    admin_user: str | None = None
    programs: list[str] = field(default_factory=list)
    llm_provider: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def load_state(settings: Settings | None = None) -> SetupState:
    settings = settings or get_settings()
    path = _state_path(settings)
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return SetupState(**{k: v for k, v in data.items() if k in SetupState.__dataclass_fields__})
        except (ValueError, OSError):
            pass
    return SetupState()


def save_state(state: SetupState, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    path = _state_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")


def is_setup_complete(settings: Settings | None = None) -> bool:
    """True when setup is done *or* a dashboard account is already configured.

    The second condition keeps existing deployments (that set a password hash via
    .env) working without forcing them through the wizard.
    """
    settings = settings or get_settings()
    if settings.dashboard_password_hash:
        return True
    return load_state(settings).complete


def mark_complete(
    *,
    admin_user: str,
    programs: list[str],
    llm_provider: str,
    notes: list[str] | None = None,
    settings: Settings | None = None,
) -> SetupState:
    settings = settings or get_settings()
    state = SetupState(
        complete=True,
        completed_at=datetime.now(UTC).isoformat(),
        admin_user=admin_user,
        programs=programs,
        llm_provider=llm_provider,
        notes=notes or [],
    )
    save_state(state, settings)
    return state
