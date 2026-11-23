"""
Route definitions for AEGIS-X REST API.
"""

from app.api.routes.health import router as health_router
from app.api.routes.upload import router as upload_router
from app.api.routes.pipeline import router as pipeline_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.reports import router as reports_router

__all__ = [
    "health_router",
    "upload_router",
    "pipeline_router",
    "incidents_router",
    "reports_router",
]
