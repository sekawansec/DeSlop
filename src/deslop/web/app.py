"""FastAPI application: submission form, status page, and triage dashboard."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..config.loader import ProgramRegistry
from ..config.settings import Settings, get_settings

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

#: Paths reachable even before first-time setup is complete.
_SETUP_EXEMPT_PREFIXES = ("/setup", "/static", "/healthz")
_SETUP_EXEMPT_EXACT = ("/favicon.ico",)


def _is_setup_exempt(path: str) -> bool:
    if path in _SETUP_EXEMPT_EXACT:
        return True
    return any(path == p or path.startswith(p + "/") for p in _SETUP_EXEMPT_PREFIXES)


def create_app(settings: Settings | None = None, registry: ProgramRegistry | None = None) -> FastAPI:
    settings = settings or get_settings()
    registry = registry or ProgramRegistry.from_dir(settings.config_dir)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Configure logging (plain or JSON, optional rotating file).
        try:
            from ..logging_setup import configure_logging

            configure_logging(settings)
        except Exception:  # noqa: BLE001
            pass

        # Register the built-in recipes (idor, xss, ssrf, open_redirect,
        # command_injection) and any lab recipes so the pipeline can verify them.
        try:
            from ..recipes.concrete import register_default_recipes

            register_default_recipes()
        except Exception as exc:  # noqa: BLE001
            import logging

            logging.getLogger("deslop.web").warning("recipe registration failed: %s", exc)

        # Create the pgvector extension and tables if they do not exist. Safe to
        # run on every start; in a real deployment use Alembic for migrations.
        try:
            from ..db.session import init_db

            init_db(settings)
        except Exception as exc:  # noqa: BLE001 - surfaced in logs, not fatal
            import logging

            logging.getLogger("deslop.web").warning("database init skipped: %s", exc)
        yield

    app = FastAPI(title="DeSlop", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.registry = registry
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    from .routes_dashboard import router as dashboard_router
    from .routes_public import router as public_router
    from .routes_setup import router as setup_router
    from .routes_status import router as status_router

    app.include_router(setup_router)
    app.include_router(public_router)
    app.include_router(status_router)
    app.include_router(dashboard_router)

    @app.middleware("http")
    async def setup_gate(request: Request, call_next):  # noqa: ANN001
        """Redirect everything to the setup wizard until first-run setup is done."""
        path = request.url.path
        if _is_setup_exempt(path):
            return await call_next(request)
        from .setup_state import is_setup_complete

        if not is_setup_complete(settings):
            return RedirectResponse(url="/setup", status_code=307)
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> dict:
        from .setup_state import is_setup_complete

        return {
            "status": "ok",
            "programs": registry.ids(),
            "setup_complete": is_setup_complete(settings),
        }

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        current = getattr(request.app.state, "registry", registry)
        return templates.TemplateResponse(
            request, "index.html", {"programs": list(current), "active": ""}
        )

    return app
