"""
Incident Management & SLM Analysis API Routes for AEGIS-X.

Provides:
- GET /api/incidents: List all incidents with optional severity, status, and user filters.
- GET /api/incidents/{incident_id}: Retrieve incident details, detections, and evidence timeline.
- POST /api/incidents/{incident_id}/analyze: Execute local SLM investigation (or deterministic fallback)
  and independent evidence verification, updating SQLite.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.ai.client import OllamaClient
from app.api.dependencies import get_db, get_ollama_client
from app.api.schemas import (
    AnalyzeIncidentResponse,
    IncidentDetailResponse,
    IncidentSummaryResponse,
)
from app.database.store import AegisDatabase
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection

logger = logging.getLogger("aegis.api.incidents")

router = APIRouter(prefix="/api", tags=["Incidents"])


@router.get(
    "/incidents",
    response_model=list[IncidentSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="List Correlated Incidents",
    description="Retrieve all correlated security incidents from SQLite with optional severity, status, or user filters.",
)
async def list_incidents(
    batch_id: Optional[str] = Query(None, description="Filter incidents by ingestion batch ID ('latest', 'all', or BATCH-XXXXXX)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, RESOLVED, CLOSED)"),
    user: Optional[str] = Query(None, description="Filter by associated username substring"),
    db: AegisDatabase = Depends(get_db),
) -> list[IncidentSummaryResponse]:
    """Retrieve all correlated incidents matching optional query filters."""

    target_batch_id: Optional[str] = None
    if batch_id:
        cleaned_batch = batch_id.strip()
        if cleaned_batch.lower() == "latest":
            latest = db.get_latest_batch()
            target_batch_id = latest["batch_id"] if latest else None
        elif cleaned_batch.lower() == "all":
            target_batch_id = None
        else:
            target_batch_id = cleaned_batch

    all_incidents = db.get_all_incidents(batch_id=target_batch_id)
    results: list[IncidentSummaryResponse] = []

    for inc in all_incidents:
        # Apply severity filter
        if severity and inc.severity.value != severity.strip().upper():
            continue

        # Apply status filter
        if status_filter and inc.status.value != status_filter.strip().upper():
            continue

        # Apply user filter
        if user:
            inc_user = inc.user or ""
            if user.strip().lower() not in inc_user.lower():
                continue

        # Extract verification status if attached
        ver_status = None
        if inc.ai_verification and isinstance(inc.ai_verification, dict):
            ver_status = inc.ai_verification.get("status")

        results.append(
            IncidentSummaryResponse(
                incident_id=inc.incident_id,
                batch_id=inc.batch_id,
                title=inc.title,
                severity=inc.severity.value,
                status=inc.status.value,
                detected_patterns=inc.detected_patterns,
                user=inc.user,
                device=inc.device,
                start_time=inc.start_time,
                end_time=inc.end_time,
                evidence_count=len(inc.evidence_event_ids),
                detection_count=len(inc.detection_ids),
                risk_score=inc.risk_score,
                severity_rationale=inc.severity_rationale,
                ai_status=inc.ai_status,
                verification_status=ver_status,
            )
        )

    return results


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Incident Details",
    description="Retrieve complete incident context including associated detections and chronological evidence events.",
)
async def get_incident_detail(
    incident_id: str,
    db: AegisDatabase = Depends(get_db),
) -> IncidentDetailResponse:
    """Retrieve full incident details, associated detections, and evidence timeline."""

    inc = db.get_incident(incident_id.strip())
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    # 1. Retrieve associated detections
    all_detections = db.get_all_detections()
    matching_dets = [
        d.model_dump(mode="json")
        for d in all_detections
        if d.detection_id in inc.detection_ids
    ]

    # 2. Retrieve chronological evidence events
    evidence_events: list[dict] = []
    for eid in inc.evidence_event_ids:
        event = db.get_event(eid)
        if event:
            evidence_events.append(event.model_dump(mode="json"))

    # Sort evidence events chronologically by timestamp
    evidence_events.sort(key=lambda e: str(e.get("timestamp", "")))

    return IncidentDetailResponse(
        incident=inc.model_dump(mode="json"),
        detections=matching_dets,
        evidence_events=evidence_events,
        ai_analysis=inc.ai_analysis,
        ai_verification=inc.ai_verification,
    )


@router.post(
    "/incidents/{incident_id}/analyze",
    response_model=AnalyzeIncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Incident with Local SLM & Verify Evidence",
    description="Run local Qwen SLM inference (or deterministic fallback) to generate attack narrative, root cause, and MITRE tactics, then verify citations independently.",
)
async def analyze_incident(
    incident_id: str,
    db: AegisDatabase = Depends(get_db),
    ollama_client: OllamaClient = Depends(get_ollama_client),
) -> AnalyzeIncidentResponse:
    """Execute AI investigation and independent evidence verification for an incident."""

    inc = db.get_incident(incident_id.strip())
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    # Gather supporting evidence events and detections
    events: list[NormalizedEvent] = []
    for eid in inc.evidence_event_ids:
        ev = db.get_event(eid)
        if ev:
            events.append(ev)

    all_dets = db.get_all_detections()
    detections: list[Detection] = [
        d for d in all_dets if d.detection_id in inc.detection_ids
    ]

    # Execute AI analysis and independent evidence verification
    analysis_output, ai_status, err_msg, verification_result = (
        await ollama_client.analyze_and_verify_incident(
            incident=inc,
            db=db,
            events=events,
            detections=detections,
        )
    )

    # Persist the enriched incident with attached analysis and verification
    db.store_incidents([inc])

    logger.info(
        f"Incident '{incident_id}' analyzed: AI Status={ai_status.value}, "
        f"Verification={verification_result.status.value}"
    )

    return AnalyzeIncidentResponse(
        incident_id=inc.incident_id,
        ai_status=ai_status.value,
        ai_analysis=analysis_output.model_dump(mode="json"),
        verification_status=verification_result.status.value,
        ai_verification=verification_result.model_dump(mode="json"),
        error_message=err_msg,
    )
