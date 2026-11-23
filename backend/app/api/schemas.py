"""
Pydantic schemas and DTOs for the AEGIS-X REST API.
"""

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Standardized error envelope for all REST API error responses."""
    error: str = Field(..., description="High-level error category or reason")
    detail: Any = Field(..., description="Detailed error explanation or validation errors")
    status_code: int = Field(..., description="HTTP status code")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of error occurrence"
    )

    model_config = {"frozen": True, "extra": "forbid"}


class HealthResponse(BaseModel):
    """System health and operational status report."""
    platform: str = Field("AEGIS-X", description="Platform name")
    tagline: str = Field(
        "From Raw Security Logs to Explainable Cyber Threat Investigations",
        description="Platform tagline"
    )
    status: str = Field("healthy", description="Overall platform status (healthy / degraded)")
    database_connected: bool = Field(..., description="Whether SQLite telemetry database is reachable")
    event_count: int = Field(0, description="Total normalized events in storage")
    incident_count: int = Field(0, description="Total correlated incidents in storage")
    ollama_online: bool = Field(..., description="Whether local Ollama SLM daemon is reachable")
    ollama_model: str = Field(..., description="Configured local SLM model name")
    latest_batch_id: Optional[str] = Field(None, description="Most recently ingested batch ID")
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when health check was performed"
    )

    model_config = {"frozen": True, "extra": "forbid"}


class BatchResponse(BaseModel):
    """Details of an ingestion batch."""
    batch_id: str = Field(..., description="Unique batch identifier, e.g. BATCH-000001")
    filename: str = Field(..., description="Original uploaded log filename")
    source: str = Field(..., description="Log source category ('authentication' or 'endpoint')")
    event_count: int = Field(0, description="Total events ingested in this batch")
    status: str = Field("UPLOADED", description="Processing status ('UPLOADED', 'INVESTIGATED', 'FAILED')")
    incident_count: int = Field(0, description="Total incidents generated for this batch")
    created_at: datetime = Field(..., description="Timestamp of batch ingestion")

    model_config = {"frozen": True, "extra": "forbid"}


class UploadResponse(BaseModel):
    """Result of log file ingestion and persistence."""
    batch_id: str = Field(..., description="Unique ingestion batch identifier")
    filename: str = Field(..., description="Name of the uploaded file")
    source: str = Field(..., description="Log source category ('authentication' or 'endpoint')")
    event_count: int = Field(..., description="Number of events successfully ingested and stored")
    error_count: int = Field(0, description="Number of validation errors encountered during ingestion")
    errors: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Details of validation errors encountered during ingestion"
    )
    total_events_in_db: int = Field(..., description="Cumulative total of events now stored in the database")
    uploaded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of upload"
    )

    model_config = {"frozen": True, "extra": "forbid"}


class PipelineRunResponse(BaseModel):
    """Result of executing the full detection and correlation pipeline."""
    status: str = Field(..., description="Execution status ('success' or 'empty')")
    batch_id: Optional[str] = Field(None, description="Ingestion batch processed by this run")
    events_processed: int = Field(..., description="Number of events evaluated")
    detections_found: int = Field(..., description="Total detection rules triggered")
    incidents_created: int = Field(..., description="Total correlated incidents generated")
    critical_count: int = Field(0, description="Critical severity incidents")
    high_count: int = Field(0, description="High severity incidents")
    medium_count: int = Field(0, description="Medium severity incidents")
    low_count: int = Field(0, description="Low severity incidents")
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of pipeline execution"
    )

    model_config = {"frozen": True, "extra": "forbid"}


class IncidentSummaryResponse(BaseModel):
    """Concise summary of an incident for listing and triage."""
    incident_id: str = Field(..., description="Incident ID, e.g. INC000001")
    title: str = Field(..., description="Human-readable title")
    severity: str = Field(..., description="Severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    status: str = Field(..., description="Lifecycle status (OPEN, RESOLVED, CLOSED)")
    detected_patterns: list[str] = Field(default_factory=list, description="Rule names that contributed")
    user: Optional[str] = Field(None, description="Associated user identity")
    device: Optional[str] = Field(None, description="Associated hostname or device")
    start_time: datetime = Field(..., description="Earliest event timestamp in incident")
    end_time: datetime = Field(..., description="Latest event timestamp in incident")
    evidence_count: int = Field(..., description="Number of supporting evidence events")
    detection_count: int = Field(..., description="Number of supporting detections")
    risk_score: Optional[float] = Field(None, description="Deterministic risk score")
    severity_rationale: str = Field(..., description="Deterministic rationale for severity")
    ai_status: Optional[str] = Field(None, description="AI analysis status (SUCCESS, FALLBACK, UNAVAILABLE)")
    verification_status: Optional[str] = Field(None, description="Evidence verification status (VERIFIED, PARTIAL, UNVERIFIED)")
    batch_id: Optional[str] = Field(None, description="Associated ingestion batch ID")

    model_config = {"frozen": True, "extra": "forbid"}


class IncidentDetailResponse(BaseModel):
    """Full detail of an incident including detections, timeline, and AI analysis."""
    incident: dict[str, Any] = Field(..., description="Complete incident data model")
    detections: list[dict[str, Any]] = Field(default_factory=list, description="Associated detections")
    evidence_events: list[dict[str, Any]] = Field(default_factory=list, description="Chronological evidence events")
    ai_analysis: Optional[dict[str, Any]] = Field(None, description="SLM or fallback analysis")
    ai_verification: Optional[dict[str, Any]] = Field(None, description="Evidence verification result")

    model_config = {"frozen": True, "extra": "forbid"}


class AnalyzeIncidentResponse(BaseModel):
    """Response returned when running SLM analysis and evidence verification."""
    incident_id: str = Field(..., description="Analyzed incident ID")
    ai_status: str = Field(..., description="AI inference status ('SUCCESS', 'FALLBACK', 'UNAVAILABLE')")
    ai_analysis: dict[str, Any] = Field(..., description="Pydantic-validated AI analysis output")
    verification_status: str = Field(..., description="Deterministic evidence verification status ('VERIFIED', 'PARTIAL', 'UNVERIFIED')")
    ai_verification: dict[str, Any] = Field(..., description="Independent evidence verification breakdown")
    error_message: Optional[str] = Field(None, description="Error or fallback reason, if any")

    model_config = {"frozen": True, "extra": "forbid"}


class GenerateReportResponse(BaseModel):
    """Result of generating incident report artifacts."""
    incident_id: str = Field(..., description="Reported incident ID")
    generated_files: dict[str, str] = Field(..., description="Artifact type to resolved filename mapping")
    output_dir: str = Field(..., description="Directory where reports are stored")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of report generation"
    )

    model_config = {"frozen": True, "extra": "forbid"}
