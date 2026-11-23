"""
Data models for the AEGIS-X Evidence Verification Engine (Phase 2 Checkpoint 3A).

Defines rigid, immutable Pydantic schemas for:
- Verification status enum (VERIFIED, PARTIAL, UNVERIFIED)
- Mismatch and discrepancy categorization
- Structured claims (user, device, IP, process, timestamps)
- Immutable evidence verification results with full audit ledgers
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime has timezone-aware UTC representation."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class VerificationStatus(str, Enum):
    """Deterministic status resulting from evidence verification."""
    VERIFIED = "VERIFIED"      # 100% evidence resolved, citations valid, claims match, bounds respected
    PARTIAL = "PARTIAL"        # Evidence resolved, no contradictions, but partial coverage or nullable attributes
    UNVERIFIED = "UNVERIFIED"  # Missing evidence, invalid citations, contradictions, or database error


class MismatchType(str, Enum):
    """Categorized types of evidence discrepancies and audit anomalies."""
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    FABRICATED_CITATION = "FABRICATED_CITATION"
    CROSS_INCIDENT_CITATION = "CROSS_INCIDENT_CITATION"
    USER_MISMATCH = "USER_MISMATCH"
    DEVICE_MISMATCH = "DEVICE_MISMATCH"
    IP_MISMATCH = "IP_MISMATCH"
    PROCESS_MISMATCH = "PROCESS_MISMATCH"
    TIMESTAMP_OUT_OF_BOUNDS = "TIMESTAMP_OUT_OF_BOUNDS"
    EMPTY_EVIDENCE = "EMPTY_EVIDENCE"
    DATABASE_ERROR = "DATABASE_ERROR"


class StructuredClaims(BaseModel):
    """Optional structured facts/claims to verify against evidence telemetry.

    Claims are optional. The verification engine does not infer unstated claims.
    """
    claimed_user: Optional[str] = Field(None, description="Expected user identity")
    claimed_device: Optional[str] = Field(None, description="Expected device/hostname")
    claimed_ip: Optional[str] = Field(None, description="Expected source IP address")
    claimed_process: Optional[str] = Field(None, description="Expected process path or name")
    claimed_event_ids: list[str] = Field(
        default_factory=list,
        description="Target event IDs this claim specifically applies to (empty applies to incident scope)"
    )
    claimed_start_time: Optional[datetime] = Field(None, description="Claimed window start")
    claimed_end_time: Optional[datetime] = Field(None, description="Claimed window end")

    @field_validator("claimed_start_time", "claimed_end_time")
    @classmethod
    def validate_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None:
            return _ensure_utc(v)
        return None

    model_config = {"frozen": False, "extra": "forbid"}


class EventDiscrepancy(BaseModel):
    """An identified factual discrepancy, out-of-bounds timestamp, or missing reference."""
    event_id: Optional[str] = Field(None, description="Event ID involved, if identifiable")
    mismatch_type: MismatchType = Field(..., description="Category of discrepancy")
    expected_value: Optional[str] = Field(None, description="Expected ground-truth value")
    actual_value: Optional[str] = Field(None, description="Actual observed value in evidence")
    explanation: str = Field(..., description="Detailed audit explanation of discrepancy")

    model_config = {"frozen": True, "extra": "forbid"}


class EvidenceVerificationResult(BaseModel):
    """Immutable, deterministic verification audit outcome produced by AEGIS-X."""
    incident_id: str = Field(..., description="Target incident identifier")
    status: VerificationStatus = Field(..., description="Final verification verdict")
    total_evidence_count: int = Field(..., description="Count of evidence event IDs declared in incident")
    resolved_evidence_count: int = Field(..., description="Count of evidence events successfully loaded from SQLite")
    missing_evidence_count: int = Field(..., description="Count of evidence events unresolvable from database")
    cited_evidence_count: int = Field(..., description="Count of citations provided (e.g. by SLM or analyst)")
    valid_citation_count: int = Field(..., description="Count of citations verified to belong to incident evidence")
    verified_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Incident evidence event IDs verified free of discrepancies"
    )
    uncited_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Ground-truth evidence event IDs present in incident but omitted from citations"
    )
    missing_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Declared incident evidence event IDs that could not be found in database"
    )
    invalid_citation_ids: list[str] = Field(
        default_factory=list,
        description="Cited event IDs that do not belong to incident evidence or do not exist"
    )
    duplicate_citation_ids: list[str] = Field(
        default_factory=list,
        description="Cited event IDs that were submitted multiple times"
    )
    discrepancies: list[EventDiscrepancy] = Field(
        default_factory=list,
        description="List of all detected contradictions, mismatches, and anomalies"
    )
    verification_rationale: list[str] = Field(
        default_factory=list,
        description="Human-auditable explanations for the verification verdict"
    )
    database_error: Optional[str] = Field(
        None,
        description="Sanitized database error description if lookup failure occurred"
    )
    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when verification was executed"
    )

    @field_validator("verified_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    model_config = {"frozen": True, "extra": "forbid"}
