"""
Ingestion Batches API Routes for AEGIS-X.

Provides:
- GET /api/batches: List all ingestion batches ordered by recency.
- GET /api/batches/{batch_id}: Retrieve details of a specific batch.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import get_db
from app.api.schemas import BatchResponse
from app.database.store import AegisDatabase

logger = logging.getLogger("aegis.api.batches")

router = APIRouter(prefix="/api", tags=["Batches"])


@router.get(
    "/batches",
    response_model=list[BatchResponse],
    status_code=status.HTTP_200_OK,
    summary="List Ingestion Batches",
    description="Retrieve all ingestion batches ordered by upload timestamp.",
)
async def list_batches(
    db: AegisDatabase = Depends(get_db),
) -> list[BatchResponse]:
    """Retrieve all ingestion batches."""
    batches = db.get_all_batches()
    return [BatchResponse(**b) for b in batches]


@router.get(
    "/batches/{batch_id}",
    response_model=BatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Ingestion Batch Details",
    description="Retrieve details of a single ingestion batch by its batch ID.",
)
async def get_batch_detail(
    batch_id: str,
    db: AegisDatabase = Depends(get_db),
) -> BatchResponse:
    """Retrieve details for a specific batch."""
    batch = db.get_batch(batch_id)
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Batch '{batch_id}' not found.",
        )
    return BatchResponse(**batch)
