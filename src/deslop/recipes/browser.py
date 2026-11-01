"""Headless browser abstraction for client-side verification.

Playwright is used in production. To keep verifiers deterministic and testable,
the concrete browser is injected behind this small interface; tests supply a
fake that reports whether a marker executed or a redirect target was visited.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class BrowserObservation:
    #: Markers (e.g. document.title values set by a payload) that were observed.
    executed_markers: set[str] = field(default_factory=set)
    #: The final URL the browser ended up at after navigation/redirects.
    final_url: str | None = None
    #: Ordered list of URLs navigated to (for redirect chains).
    navigation_urls: list[str] = field(default_factory=list)
    #: Captured console output, for debugging.
    console: list[str] = field(default_factory=list)
    error: str | None = None


def markers_in_title(title: str, expected_markers: list[str]) -> set[str]:
    """The only channel that counts as payload execution: the page title.

    A marker that merely appears in the served HTML (``page.content()``) may be
    an *escaped* reflection — safe output, not a bug. Payloads are required to
    write a unique marker to ``document.title``, so title membership is the
    strict execution signal.
    """
    return {m for m in expected_markers if m and m in title}


@runtime_checkable
class Browser(Protocol):
    def observe(self, url: str, *, expected_markers: list[str], headless: bool = True) -> BrowserObservation: ...


class PlaywrightBrowser:
    """Real headless-browser implementation backed by Playwright."""

    def __init__(self, *, timeout_ms: int = 15000) -> None:
        self.timeout_ms = timeout_ms

    def observe(
        self, url: str, *, expected_markers: list[str], headless: bool = True
    ) -> BrowserObservation:
        from playwright.sync_api import sync_playwright

        obs = BrowserObservation()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.on("console", lambda msg: obs.console.append(msg.text))
                page.goto(url, timeout=self.timeout_ms, wait_until="load")
                # Allow inline scripts a moment to run.
                page.wait_for_timeout(300)
                obs.final_url = page.url
                obs.navigation_urls = [page.url]
                obs.executed_markers = markers_in_title(page.title(), expected_markers)
                browser.close()
        except Exception as exc:  # noqa: BLE001 - reported as observation error
            obs.error = f"{type(exc).__name__}: {exc}"
        return obs


_default_browser: Browser = PlaywrightBrowser()


def get_browser() -> Browser:
    return _default_browser


def set_browser(browser: Browser) -> None:
    global _default_browser
    _default_browser = browser
