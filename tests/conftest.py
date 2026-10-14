import pytest

from deslop.config.schema import ProgramConfig, StagingConfig
from deslop.recipes.browser import BrowserObservation, set_browser


class FakeBrowser:
    """Deterministic browser stub for tests."""

    def __init__(self, *, markers=None, final_url=None, error=None):
        self._markers = set(markers or [])
        self._final_url = final_url
        self._error = error

    def observe(self, url, *, expected_markers, headless=True):
        executed = {m for m in expected_markers if m in self._markers}
        return BrowserObservation(
            executed_markers=executed,
            final_url=self._final_url or url,
            navigation_urls=[url, self._final_url or url],
            error=self._error,
        )


@pytest.fixture()
def fake_browser():
    def _install(**kwargs):
        b = FakeBrowser(**kwargs)
        set_browser(b)
        return b

    yield _install
    set_browser(__import__("deslop.recipes.browser", fromlist=["PlaywrightBrowser"]).PlaywrightBrowser())


@pytest.fixture()
def program():
    return ProgramConfig(
        id="lab",
        name="Lab",
        staging=StagingConfig(base_url="http://127.0.0.1:18000"),
    )
