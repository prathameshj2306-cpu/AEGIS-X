"""
AEGIS-X FastAPI Application Factory & Main Entry Point.

Configures:
- Strict CORS for http://127.0.0.1:5173
- Global structured error handling
- REST API routers
- Application state and dependency lifecycle
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.errors import register_exception_handlers
from app.api.middleware import RequestSizeLimitMiddleware
from app.api.routes.health import router as health_router
from app.api.routes.upload import router as upload_router
from app.api.routes.pipeline import router as pipeline_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.reports import router as reports_router
from app.api.routes.batches import router as batches_router
from app.config import AegisConfig

logger = logging.getLogger("aegis.api")


def create_app(
    config: Optional[AegisConfig] = None,
    db_path: Optional[str] = None,
) -> FastAPI:
    """Create and configure an AEGIS-X FastAPI application instance."""

    app_config = config or AegisConfig()
    resolved_db_path = db_path or "backend/aegis.db"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: Store global config and database path in application state
        app.state.config = app_config
        app.state.db_path = resolved_db_path
        logger.info(f"AEGIS-X API starting up with DB: {resolved_db_path}")
        yield
        # Shutdown
        logger.info("AEGIS-X API shutting down.")

    app = FastAPI(
        title="AEGIS-X — Offline Security Investigation Platform API",
        description="REST API for offline log ingestion, threat detection, incident correlation, AI explanation, and audit reporting.",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # Attach config and resolved db path directly to app.state
    app.state.config = app_config
    app.state.db_path = resolved_db_path

    # Configure Request Size Limit: Enforce strict 10 MB payload ceiling at ASGI level
    # Note: Applies to complete multipart request including multipart boundary/headers
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=10 * 1024 * 1024)

    # Configure CORS: Strictly allow http://127.0.0.1:5173 for Vite/React frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )

    # Register standardized error handlers
    register_exception_handlers(app)

    # Mount API routers
    app.include_router(health_router)
    app.include_router(upload_router)
    app.include_router(pipeline_router)
    app.include_router(incidents_router)
    app.include_router(reports_router)
    app.include_router(batches_router)

    return app


# Default application instance for ASGI servers (e.g. uvicorn app.main:app)
app = create_app()
