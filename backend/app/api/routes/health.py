"""
Health check and system diagnostics endpoint.
"""

from fastapi import APIRouter, Depends
from datetime import datetime, timezone

from app.ai.client import OllamaClient
from app.api.dependencies import get_config, get_db, get_ollama_client
from app.api.schemas import HealthResponse
from app.config import AegisConfig
from app.database.store import AegisDatabase

router = APIRouter(prefix="/api", tags=["System Diagnostics"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & Diagnostic Status",
    description="Inspects SQLite telemetry database connectivity, record counts, and local Ollama daemon status.",
)
async def check_health(
    config: AegisConfig = Depends(get_config),
    db: AegisDatabase = Depends(get_db),
    ollama_client: OllamaClient = Depends(get_ollama_client),
) -> HealthResponse:
    # 1. Database check
    db_connected = False
    event_count = 0
    incident_count = 0
    latest_batch_id = None
    try:
        event_count = db.get_event_count()
        incident_count = db.get_incident_count()
        latest = db.get_latest_batch()
        if latest:
            latest_batch_id = latest.get("batch_id")
        db_connected = True
    except Exception:
        db_connected = False

    # 2. Local Ollama daemon health check
    ollama_online = False
    try:
        ollama_online = await ollama_client.check_health()
    except Exception:
        ollama_online = False

    # Overall status: degraded if Ollama is offline or database fails
    status_str = "healthy" if (db_connected and ollama_online) else ("degraded" if db_connected else "unhealthy")

    return HealthResponse(
        platform="AEGIS-X",
        tagline="From Raw Security Logs to Explainable Cyber Threat Investigations",
        status=status_str,
        database_connected=db_connected,
        event_count=event_count,
        incident_count=incident_count,
        latest_batch_id=latest_batch_id,
        ollama_online=ollama_online,
        ollama_model=config.ollama_model,
        checked_at=datetime.now(timezone.utc),
    )
