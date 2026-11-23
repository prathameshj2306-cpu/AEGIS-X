"""
Report Generation & Download API Routes for AEGIS-X.

Provides:
- POST /api/incidents/{incident_id}/report: Generate HTML and/or JSON reports with SHA-256 sidecars.
- GET /api/reports/{filename}: Safely serve generated reports with path traversal protection.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse

from app.api.dependencies import get_db
from app.api.schemas import GenerateReportResponse
from app.database.store import AegisDatabase
from generate_report import generate_reports

logger = logging.getLogger("aegis.api.reports")

router = APIRouter(prefix="/api", tags=["Reports"])

ALLOWED_REPORT_EXTENSIONS = {".html", ".json", ".sha256"}
REPORTS_DIR = Path("reports").resolve()


@router.post(
    "/incidents/{incident_id}/report",
    response_model=GenerateReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Incident Report",
    description="Generate a standalone HTML and/or deterministic JSON report with SHA-256 sidecar for an incident.",
)
async def create_incident_report(
    incident_id: str,
    format_type: str = Query("both", alias="format", description="Report format ('html', 'json', 'both')"),
    sidecar: bool = Query(True, description="Generate companion SHA-256 sidecar file for JSON export"),
    overwrite: bool = Query(True, description="Overwrite existing reports if present"),
    db: AegisDatabase = Depends(get_db),
) -> GenerateReportResponse:
    """Generate HTML and/or JSON incident reports using the core reporting engine."""

    clean_id = incident_id.strip()
    inc = db.get_incident(clean_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{clean_id}' not found.",
        )

    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)

    try:
        generated_map = generate_reports(
            incident_id=clean_id,
            output_format=format_type.lower(),
            output_dir="reports",
            overwrite=overwrite,
            sidecar=sidecar,
            db_path=db.db_path,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except FileExistsError as fe:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(fe))
    except Exception as ex:
        logger.error(f"Report generation error for {clean_id}: {ex}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(ex)}",
        )

    # Extract clean file basenames for client downloads
    clean_files = {k: os.path.basename(v) for k, v in generated_map.items()}

    logger.info(f"Report generated for incident '{clean_id}': {clean_files}")

    return GenerateReportResponse(
        incident_id=clean_id,
        generated_files=clean_files,
        output_dir="reports",
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/reports/{filename}",
    status_code=status.HTTP_200_OK,
    summary="Download Generated Report",
    description="Securely download a generated HTML, JSON, or SHA-256 report artifact.",
)
async def download_report_file(filename: str):
    """Safely stream a generated report file to the client with path traversal protection."""

    # 1. Reject path traversal sequences
    if ".." in filename or "/" in filename or "\\" in filename or ":" in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename: Path traversal characters are forbidden.",
        )

    if filename.startswith("."):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename: Hidden files are forbidden.",
        )

    # 2. Validate allowed file extension
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_REPORT_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Only .html, .json, and .sha256 files can be downloaded.",
        )

    # 3. Resolve path and ensure it is contained strictly within reports/
    file_path = (REPORTS_DIR / filename).resolve()
    try:
        file_path.relative_to(REPORTS_DIR)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: File is outside the reports directory.",
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report file '{filename}' not found.",
        )

    # 4. Determine media type
    if ext == ".html":
        media_type = "text/html; charset=utf-8"
    elif ext == ".json":
        media_type = "application/json"
    else:
        media_type = "text/plain; charset=utf-8"

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type=media_type,
    )
