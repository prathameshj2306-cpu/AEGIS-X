"""
AEGIS-X Verification Subsystem (Phase 2 Checkpoint 3A).

Provides deterministic evidence verification against SQLite telemetry records,
structured claims cross-examination, and audit discrepancy detection.
"""

from app.verification.models import (
    EventDiscrepancy,
    EvidenceVerificationResult,
    MismatchType,
    StructuredClaims,
    VerificationStatus,
)
from app.verification.verifier import verify_incident_evidence

__all__ = [
    "EventDiscrepancy",
    "EvidenceVerificationResult",
    "MismatchType",
    "StructuredClaims",
    "VerificationStatus",
    "verify_incident_evidence",
]
