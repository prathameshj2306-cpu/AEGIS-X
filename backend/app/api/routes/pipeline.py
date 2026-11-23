"""
Pipeline Execution API Route for AEGIS-X.

Exposes the full deterministic detection, correlation, and severity classification pipeline:
1. Loads stored normalized events from SQLite.
2. Executes 4 deterministic detection rules.
3. Groups detections into correlated incidents across 15-minute sliding windows.
4. Classifies deterministic incident severity with audit rationales.
5. Persists detections and incidents in SQLite.
6. Returns execution metrics and severity distribution.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import get_config, get_db
from app.api.schemas import PipelineRunResponse
from app.config import AegisConfig
from app.correlation.correlator import build_incidents, correlate_detections
from app.database.store import AegisDatabase
from app.detection.engine import run_detection
from app.severity.classifier import classify_all

logger = logging.getLogger("aegis.api.pipeline")

router = APIRouter(prefix="/api", tags=["Pipeline"])


@router.post(
    "/pipeline/run",
    response_model=PipelineRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Threat Investigation Pipeline",
    description="Run detection rules, correlate events into incidents, assign deterministic severity, and store results in SQLite. Supports scoping to a specific batch, 'latest', or 'all'.",
)
async def run_pipeline(
    batch_id: Optional[str] = Query(None, description="Ingestion batch ID to run pipeline on ('latest', 'all', or specific BATCH-XXXXXX)"),
    config: AegisConfig = Depends(get_config),
    db: AegisDatabase = Depends(get_db),
) -> PipelineRunResponse:
    """Execute the end-to-end security investigation pipeline on scoped or all stored telemetry."""

    # 1. Resolve target batch scope
    target_batch_id: Optional[str] = None
    if not batch_id or batch_id.strip().lower() == "latest":
        latest_batch = db.get_latest_batch()
        if latest_batch:
            target_batch_id = latest_batch["batch_id"]
    elif batch_id.strip().lower() == "all":
        target_batch_id = "all"
    else:
        target_batch_id = batch_id.strip()

    # 2. Fetch scoped events and scoped existing incidents for stable reconciliation
    if target_batch_id and target_batch_id != "all":
        events_to_process = db.get_events_by_batch(target_batch_id)
        existing_incidents = db.get_incidents_by_batch(target_batch_id)
    else:
        events_to_process = db.get_all_events()
        existing_incidents = db.get_all_incidents()

    if not events_to_process:
        logger.info(f"Pipeline execution skipped: No events found for scope '{target_batch_id or 'all'}'.")
        return PipelineRunResponse(
            status="empty",
            batch_id=target_batch_id,
            events_processed=0,
            detections_found=0,
            incidents_created=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            executed_at=datetime.now(timezone.utc),
        )

    # 3. Detection Engine: execute 4 core rules strictly on scoped events
    detections = run_detection(events_to_process, config)

    # 4. Correlation Engine: group into incidents and reconcile with existing records
    id_offset = db.get_max_incident_id_number() + 1
    groups = correlate_detections(detections, events_to_process, config)
    incidents = build_incidents(groups, id_offset=id_offset, existing_incidents=existing_incidents)

    # 5. Tag incidents with batch_id if scoped to a specific batch
    if target_batch_id and target_batch_id != "all":
        incidents = [inc.model_copy(update={"batch_id": target_batch_id}) for inc in incidents]

    # 6. Severity Classifier: deterministic scoring
    incidents = classify_all(incidents, config)

    # 7. Persistence: store detections and incidents
    if detections:
        db.store_detections(detections)
    if incidents:
        db.store_incidents(incidents, batch_id=target_batch_id if target_batch_id != "all" else None)

    # 8. Update batch status to INVESTIGATED if scoped
    if target_batch_id and target_batch_id != "all":
        db.update_batch_status(target_batch_id, status="INVESTIGATED", incident_count=len(incidents))

    # 9. Compute severity distribution
    critical_c = sum(1 for inc in incidents if inc.severity.value == "CRITICAL")
    high_c = sum(1 for inc in incidents if inc.severity.value == "HIGH")
    medium_c = sum(1 for inc in incidents if inc.severity.value == "MEDIUM")
    low_c = sum(1 for inc in incidents if inc.severity.value == "LOW")

    logger.info(
        f"Pipeline executed successfully for batch '{target_batch_id}': {len(events_to_process)} events evaluated, "
        f"{len(detections)} detections, {len(incidents)} incidents generated."
    )

    return PipelineRunResponse(
        status="success",
        batch_id=target_batch_id,
        events_processed=len(events_to_process),
        detections_found=len(detections),
        incidents_created=len(incidents),
        critical_count=critical_c,
        high_count=high_c,
        medium_count=medium_c,
        low_count=low_c,
        executed_at=datetime.now(timezone.utc),
    )
