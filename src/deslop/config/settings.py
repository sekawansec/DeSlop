"""Environment-driven settings for DeSlop.

All runtime configuration that is *not* per-program lives here. Per-program
policy (scope, staging map, bounty table, ...) lives in YAML and is loaded by
:mod:`deslop.config.loader`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

LLMProvider = Literal["anthropic", "openai", "ollama", "none"]
EmbeddingProvider = Literal["local", "openai", "ollama"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DESLOP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "dev"
    database_url: str = "sqlite+pysqlite:///./deslop.db"
    config_dir: Path = Path("./config/programs")

    llm_provider: LLMProvider = "none"
    llm_model: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    openai_base_url: str = ""
    ollama_base_url: str = "http://localhost:11434"
    llm_max_retries: int = 2

    embedding_provider: EmbeddingProvider = "local"
    embedding_model: str = "BAAI/bge-m3"
    embedding_dim: int = 1024

    max_requests_per_run: int = 50
    max_run_seconds: int = 120
    rate_limit_rps: float = 5.0
    repro_header: str = "X-Repro-Validator"
    #: Header stamped on reproduction requests so target-side logs can be
    #: correlated with the report being verified (value: deslop-repro-<run_id>).
    bounty_user_header: str = "X-Bounty-User"
    allow_production: bool = False

    oob_base_url: str = "http://oob.local:8080"
    oob_listen_host: str = "0.0.0.0"
    oob_listen_port: int = 8080

    email_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "deslop@example.test"

    dashboard_user: str = "admin"
    dashboard_password_hash: str = ""
    #: Persisted first-run setup state.
    setup_state_file: str = "./data/setup.json"
    #: Additional dashboard users as JSON, e.g.
    #: [{"username":"triager","password_hash":"...","role":"triager"}]
    #: Roles: admin (all actions), triager (decide/reply), readonly (view only).
    dashboard_users_json: str = ""

    # --- Notifications (outbound) ---
    notify_enabled: bool = False
    slack_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    notify_base_url: str = ""  # public base URL used to link reports in notifications

    # --- Intake anti-abuse ---
    intake_rate_limit: int = 10  # submissions per window per IP
    intake_rate_window_seconds: int = 60
    blacklist_enabled: bool = True
    blacklist_file: str = "./data/blacklist.json"

    log_level: str = Field(default="INFO")
    log_json: bool = False
    log_file: str = ""  # if set, logs are also written here

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def is_prod(self) -> bool:
        return self.env.lower() in {"prod", "production"}


# Fields the setup wizard persists to ``data/setup.env``. Real environment
# variables (including compose ``environment:`` entries) always win over the
# overlay; the overlay only fills values that are unset or empty.
_OVERLAY_FIELDS = {
    "DESLOP_DASHBOARD_USER": "dashboard_user",
    "DESLOP_DASHBOARD_PASSWORD_HASH": "dashboard_password_hash",
    "DESLOP_LLM_PROVIDER": "llm_provider",
    "DESLOP_LLM_MODEL": "llm_model",
    "DESLOP_OOB_BASE_URL": "oob_base_url",
}


def _load_setup_overlay() -> dict[str, str]:
    """Read the wizard-written ``data/setup.env`` overlay, if present."""
    import os

    overlay = Path("data/setup.env")
    updates: dict[str, str] = {}
    if not overlay.is_file():
        return updates
    for line in overlay.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        field = _OVERLAY_FIELDS.get(key)
        if field is None or os.environ.get(key):
            continue
        updates[field] = value.strip()
    return updates


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance.

    Applies the setup-wizard overlay (``data/setup.env``) on top of
    environment/.env settings so wizard choices survive restarts.
    """
    return Settings(**_load_setup_overlay())


def reset_settings_cache() -> None:
    """Clear the cached settings (used by tests)."""
    get_settings.cache_clear()
