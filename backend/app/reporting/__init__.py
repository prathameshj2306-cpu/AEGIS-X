"""
AEGIS-X Reporting Subsystem (Phase 3).

Generates evidence-based, human-auditable HTML and versioned JSON incident reports.
"""

from app.reporting.html_report import (
    export_html_report,
    render_incident_report_to_html,
)
from app.reporting.json_report import (
    JsonReportExportResult,
    compute_report_sha256,
    export_json_report,
    serialize_report_to_bytes,
    serialize_report_to_json,
    verify_report_digest,
)
from app.reporting.models import (
    AIInvestigationSection,
    CategorizedRecommendations,
    DetectionFinding,
    EvidenceDiscrepancyItem,
    EvidenceInventory,
    EvidenceVerificationSection,
    EvidenceVerificationStatus,
    ExecutiveSummary,
    IncidentOverview,
    IncidentReport,
    ReportHeader,
    SeverityAssessment,
    TimelineEvent,
)
from app.reporting.report_builder import (
    build_incident_report,
    build_incident_report_from_db,
)

__all__ = [
    "AIInvestigationSection",
    "CategorizedRecommendations",
    "DetectionFinding",
    "EvidenceDiscrepancyItem",
    "EvidenceInventory",
    "EvidenceVerificationSection",
    "EvidenceVerificationStatus",
    "ExecutiveSummary",
    "IncidentOverview",
    "IncidentReport",
    "JsonReportExportResult",
    "ReportHeader",
    "SeverityAssessment",
    "TimelineEvent",
    "build_incident_report",
    "build_incident_report_from_db",
    "compute_report_sha256",
    "export_html_report",
    "export_json_report",
    "render_incident_report_to_html",
    "serialize_report_to_bytes",
    "serialize_report_to_json",
    "verify_report_digest",
]
