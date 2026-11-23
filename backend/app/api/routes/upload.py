"""
Upload API Route for AEGIS-X.

Provides secure multipart file upload for authentication and endpoint log files (.csv and .json).

Remediations & Guarantees:
1. True Request-Level Size Enforcement:
   Complemented by ASGI RequestSizeLimitMiddleware at the application boundary,
   preventing unbounded buffering.
2. Concurrency-Safe Monotonic Event ID Allocation:
   Delegates to AegisDatabase.allocate_and_store_events() which executes under
   an atomic SQLite BEGIN IMMEDIATE transaction lock, querying the maximum existing
   numeric ID (not row count) and inserting with collision detection and rollback.
3. Content- & Signature-Aware Source Inference:
   Inspects filename, columns/keys, and event types to classify authentication vs. endpoint.
   Rejects ambiguous files with HTTP 400 rather than silently defaulting to authentication.
"""

import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from app.api.dependencies import get_db
from app.api.schemas import UploadResponse
from app.database.store import AegisDatabase
from app.ingestion.ingestor import (
    MAX_FILE_SIZE_BYTES,
    SOURCE_MAPPINGS,
    ingest_csv,
    ingest_json,
)
from app.schemas.events import EventSource

logger = logging.getLogger("aegis.api.upload")

router = APIRouter(prefix="/api", tags=["Ingestion"])

CHUNK_SIZE = 64 * 1024  # 64 KB read buffer
ALLOWED_EXTENSIONS = {".csv", ".json"}
ALLOWED_MIME_TYPES = {
    "text/csv",
    "application/csv",
    "application/json",
    "application/x-ndjson",
    "text/plain",
    "application/octet-stream",
    "text/json",
    "application/x-javascript",
    "text/x-json",
}


def infer_log_source(
    filename: str,
    content_text: str,
    ext: str,
    explicit_source: Optional[str] = None,
) -> EventSource:
    """Resolve log source category with strict safety guarantees.

    Priority order:
    1. Explicit source parameter (via Form body or Query param).
    2. Content signatures (columns, keys, and normalized event types).
    3. Filename keywords.
    4. Rejection with HTTP 400 if ambiguous or unidentifiable.
    """
    # 1. Explicit source selection has highest priority
    if explicit_source:
        cleaned = explicit_source.strip().lower()
        if cleaned not in SOURCE_MAPPINGS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid log source '{explicit_source}'. Permitted sources: 'authentication', 'endpoint'.",
            )
        return SOURCE_MAPPINGS[cleaned]

    # 2. Extract column headers and sample event types from content
    cols: set[str] = set()
    sample_event_types: set[str] = set()

    if ext == ".csv":
        try:
            reader = csv.reader(io.StringIO(content_text))
            header_row = next(reader, None)
            if header_row:
                cols = {c.strip().lower() for c in header_row if c and isinstance(c, str)}
                event_type_idx = -1
                for idx, c in enumerate(header_row):
                    if c.strip().lower() in ("event_type", "eventtype", "type", "action", "activity"):
                        event_type_idx = idx
                        break
                if event_type_idx >= 0:
                    for _ in range(15):
                        row = next(reader, None)
                        if not row:
                            break
                        if len(row) > event_type_idx:
                            sample_event_types.add(row[event_type_idx].strip().lower())
        except Exception:
            pass
    elif ext == ".json":
        try:
            parsed = json.loads(content_text)
            records = []
            if isinstance(parsed, list):
                records = [r for r in parsed if isinstance(r, dict)][:15]
            elif isinstance(parsed, dict):
                records = [parsed]
            for r in records:
                for k in r.keys():
                    cols.add(str(k).strip().lower())
                ev_type = r.get("event_type") or r.get("type") or r.get("action")
                if ev_type and isinstance(ev_type, str):
                    sample_event_types.add(ev_type.strip().lower())
        except Exception:
            # Try NDJSON fallback
            for line in content_text.strip().splitlines()[:15]:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        for k in obj.keys():
                            cols.add(str(k).strip().lower())
                        ev_type = obj.get("event_type") or obj.get("type") or obj.get("action")
                        if ev_type and isinstance(ev_type, str):
                            sample_event_types.add(ev_type.strip().lower())
                except Exception:
                    pass

    # Content signatures
    endpoint_cols = {"process", "process_name", "command_line", "command", "executable", "program", "edr", "sysmon"}
    endpoint_event_types = {
        "process_start", "process_stop", "file_access", "file_modify",
        "network_connection", "service_start", "service_stop", "registry_modify"
    }

    auth_cols = {"ip", "client_ip", "source_ip", "src_ip", "remote_ip"}
    auth_event_types = {
        "login_success", "login_failure", "logout", "password_change",
        "mfa_success", "mfa_failure", "account_lockout"
    }

    endpoint_score = 0
    auth_score = 0

    if cols & endpoint_cols:
        endpoint_score += 2
    if sample_event_types & endpoint_event_types:
        endpoint_score += 3

    if sample_event_types & auth_event_types:
        auth_score += 3
    if (cols & auth_cols) and not (cols & endpoint_cols):
        auth_score += 1

    # Filename signatures
    fname_lower = filename.lower()
    ep_filename_kws = ["endpoint", "host", "sysmon", "edr", "process"]
    auth_filename_kws = ["auth", "login", "logon", "credential", "signin", "sso", "identity"]

    if any(kw in fname_lower for kw in ep_filename_kws):
        endpoint_score += 1
    if any(kw in fname_lower for kw in auth_filename_kws):
        auth_score += 1

    # Resolve with strict safety
    if endpoint_score > 0 and auth_score == 0:
        return EventSource.ENDPOINT
    if auth_score > 0 and endpoint_score == 0:
        return EventSource.AUTHENTICATION
    if endpoint_score > auth_score:
        return EventSource.ENDPOINT
    if auth_score > endpoint_score:
        return EventSource.AUTHENTICATION

    # Reject ambiguous log files to prevent silent misclassification
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            f"Ambiguous log source for '{filename}': The log source could not be uniquely identified from filename or content. "
            "Please explicitly provide the 'source' parameter ('authentication' or 'endpoint')."
        ),
    )


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload Security Log File",
    description="Upload an authentication or endpoint log file (.csv or .json) up to 10 MB for ingestion and database persistence.",
)
async def upload_log_file(
    request: Request,
    file: UploadFile = File(..., description="Log file (.csv or .json)"),
    source: Optional[str] = Form(None, description="Log source category ('authentication' or 'endpoint')"),
    db: AegisDatabase = Depends(get_db),
) -> UploadResponse:
    """Ingest an uploaded security log file and persist normalized events."""

    # 1. Validate filename and extension
    filename = file.filename or ""
    if not filename.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or empty filename in upload request.",
        )

    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Only .csv and .json files are allowed.",
        )

    # 2. Validate MIME type if declared
    if file.content_type:
        mime_clean = file.content_type.split(";")[0].strip().lower()
        if mime_clean not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported MIME type '{file.content_type}'. Allowed types are CSV and JSON.",
            )

    # 3. Stream content in chunks and enforce 10 MB limit dynamically
    total_bytes = 0
    chunks: list[bytes] = []

    try:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"Upload exceeded maximum permitted limit of {MAX_FILE_SIZE_BYTES} bytes (10 MB) while reading.",
                )
            chunks.append(chunk)
    finally:
        await file.close()

    if total_bytes == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # 4. Decode content as UTF-8
    try:
        content_text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is not valid UTF-8 encoded text.",
        )

    if not content_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file contains only whitespace or blank lines.",
        )

    # 5. Resolve log source category safely
    effective_source_str = source or request.query_params.get("source")
    target_source = infer_log_source(
        filename=filename,
        content_text=content_text,
        ext=ext,
        explicit_source=effective_source_str,
    )

    # 6. Ingest using core ingestion routines
    if ext == ".csv":
        result = ingest_csv(
            csv_content=content_text,
            default_source=target_source,
            id_offset=1,  # Initial offset; will be atomically renumbered by allocate_and_store_events
        )
    else:
        result = ingest_json(
            json_content=content_text,
            default_source=target_source,
            id_offset=1,
        )

    # 7. Verify that at least one valid event was ingested
    if result.success_count == 0:
        error_details = [e.to_dict() for e in result.errors[:10]]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Malformed log file: No valid events could be ingested.",
                "validation_errors": error_details,
            },
        )

    # 8. Persist normalized events into SQLite database with atomic ID allocation and batch assignment
    try:
        batch = db.create_batch(
            filename=filename,
            source=target_source.value,
            event_count=0,
            status="UPLOADED",
        )
        batch_id = batch["batch_id"]
        stored_events = db.allocate_and_store_events(result.events, batch_id=batch_id)
        with db._write_lock:
            db.conn.execute(
                "UPDATE ingestion_batches SET event_count = ? WHERE batch_id = ?",
                (len(stored_events), batch_id),
            )
            db.conn.commit()
    except Exception as exc:
        logger.error(f"Database failure while persisting events from {filename}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database failure while persisting ingested events: {str(exc)}",
        )

    total_in_db = db.get_event_count()
    logger.info(
        f"Successfully uploaded '{filename}' (Batch: {batch_id}): {len(stored_events)} events stored, "
        f"{result.error_count} errors, total in DB: {total_in_db}"
    )

    return UploadResponse(
        batch_id=batch_id,
        filename=filename,
        source=target_source.value,
        event_count=len(stored_events),
        error_count=result.error_count,
        errors=[e.to_dict() for e in result.errors[:20]],
        total_events_in_db=total_in_db,
        uploaded_at=datetime.now(timezone.utc),
    )
