"""
Incident and detection schemas — the output data contract for AEGIS-X.

Detection: a single pattern match found by one detection rule.
Incident: a correlated group of detections with severity classification.

Key design decisions:
- Detection carries the rule name, explanation, and triggering event IDs.
- Incident aggregates detections, assigns severity deterministically,
  and carries all evidence references needed for reporting.
- Severity is an enum: LOW, MEDIUM, HIGH, CRITICAL.
- Status tracks investigation progress: OPEN → UNDER_REVIEW → CLOSED.
- SLM analysis fields (Phase 2+) are optional and never affect severity.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    CLOSED = "CLOSED"


class Detection(BaseModel):
    """A single detection: one rule matched one pattern in the data.

    Fields:
        detection_id: Unique identifier, e.g. "D000001".
        rule_name: Which rule triggered (e.g., "brute_force_login").
        explanation: Human-readable description of what was found.
        event_ids: List of event IDs that triggered this detection.
        timestamp: When the detection was created (UTC).
        user: User involved, if any.
        device: Device involved, if any.
        confidence: Rule confidence or rationale tag.
        metadata: Additional context from the rule.
    """
    detection_id: str = Field(..., description="Unique detection ID, e.g. D000001")
    rule_name: str = Field(..., description="Detection rule name")
    explanation: str = Field(..., description="Human-readable explanation")
    event_ids: list[str] = Field(..., description="Triggering event IDs")
    timestamp: datetime = Field(..., description="Detection creation time (UTC)")
    user: Optional[str] = Field(None, description="User involved")
    device: Optional[str] = Field(None, description="Device involved")
    confidence: str = Field("rule_match", description="Confidence level or rationale")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional detection context"
    )

    model_config = {"frozen": False, "extra": "forbid"}


class Incident(BaseModel):
    """A correlated security incident with severity classification.

    Fields:
        incident_id: Unique identifier, e.g. "INC000001".
        title: Short human-readable title.
        severity: Deterministic severity classification.
        status: Investigation status.
        detected_patterns: List of detection rule names involved.
        user: Primary user involved.
        device: Primary device involved.
        start_time: Earliest event timestamp in the incident.
        end_time: Latest event timestamp in the incident.
        evidence_event_ids: All event IDs supporting this incident.
        detection_ids: All detection IDs grouped into this incident.
        risk_score: Optional numeric risk score (0-100).
        severity_rationale: Human-readable explanation of severity assignment.
        created_at: When this incident record was created (UTC).
        ai_analysis: SLM-generated analysis (Phase 2+, None until then).
        ai_status: SLM status: None, "SUCCESS", "FALLBACK", "UNAVAILABLE".
        ai_verification: Evidence verification results (Phase 2+).
    """
    incident_id: str = Field(..., description="Unique incident ID, e.g. INC000001")
    title: str = Field(..., description="Short incident title")
    severity: Severity = Field(..., description="Deterministic severity")
    status: IncidentStatus = Field(
        IncidentStatus.OPEN, description="Investigation status"
    )
    detected_patterns: list[str] = Field(..., description="Rule names involved")
    user: Optional[str] = Field(None, description="Primary user")
    device: Optional[str] = Field(None, description="Primary device")
    start_time: datetime = Field(..., description="Earliest event time")
    end_time: datetime = Field(..., description="Latest event time")
    evidence_event_ids: list[str] = Field(..., description="All supporting event IDs")
    detection_ids: list[str] = Field(..., description="All grouped detection IDs")
    risk_score: Optional[float] = Field(None, description="Optional risk score 0-100")
    severity_rationale: str = Field(..., description="Why this severity was assigned")
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Incident creation time"
    )

    # Phase 2+ fields (SLM integration)
    ai_analysis: Optional[dict[str, Any]] = Field(
        None, description="SLM-generated analysis"
    )
    ai_status: Optional[str] = Field(
        None, description="SLM status: SUCCESS, FALLBACK, UNAVAILABLE"
    )
    ai_verification: Optional[dict[str, Any]] = Field(
        None, description="Evidence verification results"
    )

    model_config = {"frozen": False, "extra": "forbid"}
