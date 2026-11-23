"""
Pydantic data models for the AEGIS-X Reporting System (Phase 3).

Defines the rigid, validated data contracts for assembled incident reports.
Every report model guarantees:
- UTC-normalized timestamps.
- Explicit distinction between deterministic findings and AI-generated analysis.
- Full evidence traceability (preserving event IDs, detection IDs, and raw telemetry).
- Safe handling of optional or absent fields without inventing data.
"""

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


def _ensure_utc(dt: datetime) -> datetime:
    """Normalize datetime object to timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ReportHeader(BaseModel):
    """Metadata and branding for the incident report."""
    platform: str = Field("AEGIS-X", description="Platform name")
    tagline: str = Field(
        "From Raw Security Logs to Explainable Cyber Threat Investigations",
        description="Platform tagline"
    )
    report_title: str = Field(..., description="Human-readable report title")
    report_version: str = Field("1.0", description="Report schema version")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Report generation timestamp in UTC"
    )
    incident_id: str = Field(..., description="Target incident identifier")
    batch_id: Optional[str] = Field(None, description="Associated ingestion batch identifier")
    source_filename: Optional[str] = Field(None, description="Original source log filename")

    @field_validator("generated_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    model_config = {"frozen": False, "extra": "forbid"}


class ExecutiveSummary(BaseModel):
    """High-level executive briefing of the security incident."""
    incident_id: str
    title: str
    severity: str
    status: str
    summary_text: str
    user: Optional[str] = None
    device: Optional[str] = None
    risk_score: Optional[float] = None
    potential_impact: Optional[str] = None
    batch_id: Optional[str] = None
    source_filename: Optional[str] = None

    model_config = {"frozen": False, "extra": "forbid"}


class IncidentOverview(BaseModel):
    """Structural overview and time boundary parameters."""
    incident_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    primary_user: Optional[str] = None
    primary_device: Optional[str] = None
    detected_patterns: list[str]
    total_detections: int
    total_evidence_events: int

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    model_config = {"frozen": False, "extra": "forbid"}


class DetectionFinding(BaseModel):
    """A deterministic detection rule pattern match contributing to the incident."""
    detection_id: str
    rule_name: str
    explanation: str
    timestamp: datetime
    confidence: str
    user: Optional[str] = None
    device: Optional[str] = None
    triggering_event_ids: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    model_config = {"frozen": False, "extra": "forbid"}


class TimelineEvent(BaseModel):
    """Supporting security event plotted chronologically along the incident timeline."""
    event_id: str
    timestamp: datetime
    event_type: str
    source: str
    user: Optional[str] = None
    device: Optional[str] = None
    ip: Optional[str] = None
    process: Optional[str] = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    is_primary_evidence: bool = True

    @field_validator("timestamp")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    model_config = {"frozen": False, "extra": "forbid"}


class SeverityAssessment(BaseModel):
    """Deterministic severity evaluation and mathematical score."""
    severity: str
    risk_score: Optional[float] = None
    severity_rationale: str
    contributing_patterns: list[str]
    assessment_type: str = "Deterministic Rule-Based"

    model_config = {"frozen": False, "extra": "forbid"}


class AIInvestigationSection(BaseModel):
    """Explainability analysis produced by local SLM or deterministic fallback."""
    has_ai_analysis: bool = False
    status: Optional[str] = None  # SUCCESS, FALLBACK, UNAVAILABLE, or None
    model: Optional[str] = None
    summary: Optional[str] = None
    attack_interpretation: Optional[str] = None
    potential_impact: Optional[str] = None
    recommended_actions: list[str] = Field(default_factory=list)
    cited_event_ids: list[str] = Field(default_factory=list)
    uncited_evidence_ids: list[str] = Field(default_factory=list)
    is_fallback: bool = False
    notes: Optional[str] = None

    model_config = {"frozen": False, "extra": "forbid"}


class EvidenceDiscrepancyItem(BaseModel):
    """A single evidence discrepancy surfaced by the verification engine."""
    event_id: Optional[str] = None
    mismatch_type: str
    expected_value: Optional[str] = None
    actual_value: Optional[str] = None
    explanation: str

    model_config = {"frozen": False, "extra": "forbid"}


class EvidenceVerificationSection(BaseModel):
    """Evidence verification results from the deterministic verification engine.

    Supports canonical statuses:
    - VERIFIED: All evidence resolved, citations valid, claims match.
    - PARTIAL: Evidence resolved with partial coverage or nullable attributes.
    - UNVERIFIED: Missing evidence, invalid citations, contradictions, or verification failure.
    - NOT_AVAILABLE: Verification has not been performed.

    This section is strictly independent of AI analysis status.
    """
    verification_performed: bool = False
    status: str = "NOT_AVAILABLE"
    status_label: str = "PENDING_PHASE_2_CHECKPOINT_3"
    is_verified: bool = False
    verification_type: str = "Deterministic Evidence Verification Engine"
    verification_rationale: list[str] = Field(default_factory=list)
    total_evidence_count: int = 0
    resolved_evidence_count: int = 0
    missing_evidence_count: int = 0
    cited_evidence_count: int = 0
    valid_citation_count: int = 0
    ai_cited_count: int = 0
    verified_evidence_ids: list[str] = Field(default_factory=list)
    uncited_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence_ids: list[str] = Field(default_factory=list)
    invalid_citation_ids: list[str] = Field(default_factory=list)
    duplicate_citation_ids: list[str] = Field(default_factory=list)
    discrepancies: list[EvidenceDiscrepancyItem] = Field(default_factory=list)
    database_error: Optional[str] = None
    details: str = "Evidence verification has not been performed for this incident."

    model_config = {"frozen": False, "extra": "forbid"}


# Backward-compatibility alias
EvidenceVerificationStatus = EvidenceVerificationSection


class CategorizedRecommendations(BaseModel):
    """Structured, actionable remediation recommendations."""
    immediate_containment: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    remediation_and_hardening: list[str] = Field(default_factory=list)

    model_config = {"frozen": False, "extra": "forbid"}


class EvidenceInventory(BaseModel):
    """Inventory of evidence and detection identifiers with reconciliation checks."""
    all_evidence_event_ids: list[str]
    resolved_event_count: int
    missing_event_ids: list[str] = Field(default_factory=list)
    detection_ids: list[str]
    resolved_detection_count: int
    missing_detection_ids: list[str] = Field(default_factory=list)

    model_config = {"frozen": False, "extra": "forbid"}


class IncidentReport(BaseModel):
    """The root container for an assembled, fully validated incident investigation report."""
    header: ReportHeader
    executive_summary: ExecutiveSummary
    incident_overview: IncidentOverview
    detection_findings: list[DetectionFinding]
    timeline: list[TimelineEvent]
    severity_assessment: SeverityAssessment
    ai_investigation: AIInvestigationSection
    evidence_verification: EvidenceVerificationSection
    recommendations: CategorizedRecommendations
    evidence_inventory: EvidenceInventory

    model_config = {"frozen": False, "extra": "forbid"}
