"""Central logging configuration.

Supports plain or JSON logs and optional file output with size-based rotation
(so a long-running deployment does not fill its disk).
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import UTC, datetime

from ..config.settings import Settings, get_settings

_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(settings: Settings | None = None, *, force: bool = False) -> None:
    """Install handlers on the root logger. Idempotent unless ``force``."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    settings = settings or get_settings()

    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter: logging.Formatter = (
        JsonFormatter()
        if settings.log_json
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    if settings.log_file:
        from pathlib import Path

        Path(settings.log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            settings.log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    _CONFIGURED = True


def reset_logging() -> None:
    global _CONFIGURED
    _CONFIGURED = False
