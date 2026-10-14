"""Outbound notifications to Slack and Telegram.

Two things trigger a notification: a new report arrives, and a triager changes a
report's status or decides. Notifications are best-effort and never block or
fail the pipeline/intake path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from .config.settings import Settings, get_settings

log = logging.getLogger("deslop.notify")


@dataclass
class Notifier:
    settings: Settings

    @property
    def enabled(self) -> bool:
        if not self.settings.notify_enabled:
            return False
        return bool(self.settings.slack_webhook_url or self.settings.telegram_bot_token)

    def _link(self, report_id: str) -> str:
        base = self.settings.notify_base_url.rstrip("/")
        if not base:
            return report_id
        return f"{base}/dashboard/reports/{report_id}"

    def notify(self, text: str, *, report_id: str | None = None) -> list[str]:
        """Send ``text`` to every configured channel. Returns channels used."""
        if not self.enabled:
            return []
        if report_id:
            text = f"{text}\n{self._link(report_id)}"
        used: list[str] = []
        if self.settings.slack_webhook_url and self._send_slack(text):
            used.append("slack")
        if (
            self.settings.telegram_bot_token
            and self.settings.telegram_chat_id
            and self._send_telegram(text)
        ):
            used.append("telegram")
        return used

    def _send_slack(self, text: str) -> bool:
        try:
            r = httpx.post(
                self.settings.slack_webhook_url, json={"text": text}, timeout=10.0
            )
            return r.status_code < 400
        except httpx.HTTPError as exc:
            log.warning("slack notification failed: %s", exc)
            return False

    def _send_telegram(self, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
        try:
            r = httpx.post(
                url,
                json={"chat_id": self.settings.telegram_chat_id, "text": text},
                timeout=10.0,
            )
            return r.status_code < 400
        except httpx.HTTPError as exc:
            log.warning("telegram notification failed: %s", exc)
            return False


def get_notifier(settings: Settings | None = None) -> Notifier:
    return Notifier(settings or get_settings())


def new_report_message(title: str, report_id: str, routing: str | None = None) -> str:
    route = f" [{routing}]" if routing else ""
    return f"DeSlop: new report {report_id}{route} - {title}"


def status_change_message(report_id: str, public_status: str, actor: str) -> str:
    return f"DeSlop: report {report_id} public status -> {public_status} (by {actor})"


def decision_message(report_id: str, decision: str, actor: str) -> str:
    return f"DeSlop: report {report_id} decision={decision} (by {actor})"
