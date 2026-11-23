"""
Unit and integration tests for AEGIS-X Reporting System (Phase 3 Checkpoint 2).

Tests cover:
1. Report models validation and schema constraints:
   - Strict Pydantic models (extra fields forbidden).
   - UTC normalization on all timestamps.
2. Context builder (`build_incident_report`):
   - Assembly of report from Incident, events, and detections.
   - Preservation of deterministic severity and severity rationale.
   - Chronological timeline ordering of supporting events.
   - Full preservation of raw telemetry and event attributes.
   - Explicit tracking of missing evidence and missing detections (no synthetic data invention).
   - Handling of missing AI analysis (deterministic-only triage).
   - Handling of active AI analysis (SUCCESS, FALLBACK, UNAVAILABLE).
   - Uncited evidence calculation.
   - Categorization of actionable recommendations into containment, investigation, and hardening.
   - Phase 2 Checkpoint 3 verification status representation.
3. Database retrieval (`build_incident_report_from_db`):
   - Retrieval from SQLite database without modifying records.
   - Rejection of unknown incident IDs with ValueError.
"""

from datetime import datetime, timezone, timedelta
import pytest
from pydantic import ValidationError

from app.database.store import AegisDatabase
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
from generate_report import main as cli_main, generate_reports
from app.reporting.models import (
    CategorizedRecommendations,
    DetectionFinding,
    EvidenceInventory,
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
    _categorize_recommendations,
)
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Detection, Incident, IncidentStatus, Severity


def _create_sample_incident(
    incident_id: str = "INC000001",
    severity: Severity = Severity.HIGH,
    patterns: list[str] | None = None,
    user: str = "bob",
    device: str = "WS-001",
    evidence_ids: list[str] | None = None,
    detection_ids: list[str] | None = None,
    ai_analysis: dict | None = None,
    ai_status: str | None = None,
    ai_verification: dict | None = None,
) -> Incident:
    return Incident(
        incident_id=incident_id,
        title=f"Incident {incident_id} — {user}",
        severity=severity,
        status=IncidentStatus.OPEN,
        detected_patterns=patterns or ["brute_force_login", "suspicious_process"],
        user=user,
        device=device,
        start_time=datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc),
        end_time=datetime(2024, 11, 20, 10, 30, tzinfo=timezone.utc),
        evidence_event_ids=evidence_ids or ["E001", "E002"],
        detection_ids=detection_ids or ["D001"],
        risk_score=75.0,
        severity_rationale="HIGH: 2 serious detection types correlated.",
        ai_analysis=ai_analysis,
        ai_status=ai_status,
        ai_verification=ai_verification,
    )


def _create_sample_event(
    event_id: str,
    timestamp: datetime,
    event_type: str = "login_failure",
    source: EventSource = EventSource.AUTHENTICATION,
    user: str = "bob",
    device: str = "WS-001",
    ip: str = "192.168.1.10",
    process: str | None = None,
    raw_data: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user=user,
        device=device,
        ip=ip,
        event_type=event_type,
        process=process,
        source=source,
        raw_data=raw_data or {"log_line": f"raw content for {event_id}"},
    )


def _create_sample_detection(
    detection_id: str = "D001",
    rule_name: str = "brute_force_login",
    event_ids: list[str] | None = None,
    user: str = "bob",
    device: str = "WS-001",
) -> Detection:
    return Detection(
        detection_id=detection_id,
        rule_name=rule_name,
        explanation=f"Detection explanation for {rule_name}",
        event_ids=event_ids or ["E001"],
        timestamp=datetime(2024, 11, 20, 10, 15, tzinfo=timezone.utc),
        user=user,
        device=device,
        confidence="high",
        metadata={"detail": "sample metadata"},
    )


# =============================================================================
# 1. REPORT MODELS VALIDATION TESTS
# =============================================================================

class TestReportModels:
    def test_report_header_utc_normalization(self):
        # Non-UTC timezone (IST is +05:30)
        ist = timezone(timedelta(hours=5, minutes=30))
        local_dt = datetime(2024, 11, 20, 15, 30, tzinfo=ist)
        header = ReportHeader(
            report_title="Test Report",
            generated_at=local_dt,
            incident_id="INC000001",
        )
        assert header.generated_at.tzinfo == timezone.utc
        assert header.generated_at.hour == 10  # 15:30 IST is 10:00 UTC

    def test_report_models_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            ReportHeader(
                report_title="Test",
                incident_id="INC001",
                disallowed_field="illegal",  # Extra field
            )

    def test_timeline_event_preserves_raw_data(self):
        ev = TimelineEvent(
            event_id="E001",
            timestamp=datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc),
            event_type="process_start",
            source="endpoint",
            raw_data={"cmd": "mimikatz.exe", "pid": 1234},
        )
        assert ev.raw_data["cmd"] == "mimikatz.exe"
        assert ev.raw_data["pid"] == 1234


# =============================================================================
# 2. REPORT CONTEXT BUILDER TESTS
# =============================================================================

class TestReportBuilder:
    def test_build_report_basic_assembly(self):
        incident = _create_sample_incident()
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        t2 = datetime(2024, 11, 20, 10, 15, tzinfo=timezone.utc)
        events = [
            _create_sample_event("E001", t1),
            _create_sample_event("E002", t2),
        ]
        detections = [_create_sample_detection("D001", event_ids=["E001"])]

        report = build_incident_report(incident, events=events, detections=detections)

        assert isinstance(report, IncidentReport)
        assert report.header.incident_id == "INC000001"
        assert report.executive_summary.severity == "HIGH"
        assert report.severity_assessment.severity == "HIGH"
        assert report.severity_assessment.severity_rationale == incident.severity_rationale
        assert len(report.timeline) == 2
        assert len(report.detection_findings) == 1
        assert report.incident_overview.total_evidence_events == 2
        assert report.incident_overview.total_detections == 1

    def test_timeline_events_are_chronologically_sorted(self):
        incident = _create_sample_incident(evidence_ids=["E001", "E002", "E003"])
        t_early = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
        t_mid = datetime(2024, 11, 20, 10, 10, tzinfo=timezone.utc)
        t_late = datetime(2024, 11, 20, 10, 20, tzinfo=timezone.utc)

        # Pass in reverse chronological order
        events = [
            _create_sample_event("E003", t_late),
            _create_sample_event("E001", t_early),
            _create_sample_event("E002", t_mid),
        ]

        report = build_incident_report(incident, events=events)

        assert report.timeline[0].event_id == "E001"
        assert report.timeline[1].event_id == "E002"
        assert report.timeline[2].event_id == "E003"
        assert report.timeline[0].timestamp <= report.timeline[1].timestamp <= report.timeline[2].timestamp

    def test_missing_evidence_is_tracked_explicitly(self):
        incident = _create_sample_incident(evidence_ids=["E001", "E_MISSING_999"])
        events = [_create_sample_event("E001", datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc))]

        report = build_incident_report(incident, events=events)

        # E_MISSING_999 is unresolvable
        assert "E_MISSING_999" in report.evidence_inventory.missing_event_ids
        assert report.evidence_inventory.resolved_event_count == 1
        assert len(report.timeline) == 1
        assert report.timeline[0].event_id == "E001"

    def test_missing_detections_are_tracked_explicitly(self):
        incident = _create_sample_incident(detection_ids=["D001", "D_GHOST"])
        detections = [_create_sample_detection("D001")]

        report = build_incident_report(incident, detections=detections)

        assert "D_GHOST" in report.evidence_inventory.missing_detection_ids
        assert report.evidence_inventory.resolved_detection_count == 1
        assert len(report.detection_findings) == 1

    def test_report_without_ai_analysis_handles_gracefully(self):
        incident = _create_sample_incident(ai_analysis=None, ai_status=None)
        report = build_incident_report(incident)

        assert report.ai_investigation.has_ai_analysis is False
        assert report.ai_investigation.status is None
        assert report.ai_investigation.summary is None
        assert "not executed" in report.ai_investigation.notes
        # Baseline recommendations generated from deterministic patterns
        assert len(report.recommendations.investigation_steps) > 0 or len(report.recommendations.immediate_containment) > 0

    def test_report_with_ai_analysis_success(self):
        ai_data = {
            "summary": "AI executive summary of attack.",
            "attack_interpretation": "Observed multi-stage credential theft.",
            "potential_impact": "Host administrative compromise.",
            "recommended_actions": [
                "Isolate host WS-001 from enterprise network",
                "Investigate process lineage and command line",
                "Reset user credentials with MFA enforcement",
            ],
            "cited_event_ids": ["E001"],
        }
        incident = _create_sample_incident(
            evidence_ids=["E001", "E002"],
            ai_analysis=ai_data,
            ai_status="SUCCESS",
        )
        report = build_incident_report(incident)

        assert report.ai_investigation.has_ai_analysis is True
        assert report.ai_investigation.status == "SUCCESS"
        assert report.ai_investigation.is_fallback is False
        assert report.ai_investigation.summary == ai_data["summary"]
        assert report.ai_investigation.cited_event_ids == ["E001"]
        assert report.ai_investigation.uncited_evidence_ids == ["E002"]

        # Recommendations categorized
        assert any("Isolate" in act for act in report.recommendations.immediate_containment)
        assert any("Investigate" in act for act in report.recommendations.investigation_steps)
        assert any("Reset" in act for act in report.recommendations.remediation_and_hardening)

    def test_report_with_ai_analysis_fallback_or_unavailable(self):
        ai_data = {
            "summary": "Deterministic fallback summary.",
            "attack_interpretation": "Fallback technical interpretation.",
            "potential_impact": "Fallback impact.",
            "recommended_actions": ["Review authentication failure logs"],
            "cited_event_ids": ["E001"],
        }
        incident = _create_sample_incident(
            ai_analysis=ai_data,
            ai_status="FALLBACK",
        )
        report = build_incident_report(incident)

        assert report.ai_investigation.has_ai_analysis is True
        assert report.ai_investigation.status == "FALLBACK"
        assert report.ai_investigation.is_fallback is True
        assert "FALLBACK mode" in report.ai_investigation.notes

    def test_evidence_verification_reflects_phase2_checkpoint2_state(self):
        incident = _create_sample_incident(
            evidence_ids=["E001", "E002"],
            ai_analysis={"summary": "...", "cited_event_ids": ["E001"]},
            ai_status="SUCCESS",
        )
        report = build_incident_report(incident)

        assert report.evidence_verification.is_verified is False
        assert report.evidence_verification.status_label == "PENDING_PHASE_2_CHECKPOINT_3"
        assert report.evidence_verification.total_evidence_count == 2
        assert report.evidence_verification.ai_cited_count == 1


# =============================================================================
# 3. DATABASE RETRIEVAL TESTS
# =============================================================================

class TestReportBuilderWithDatabase:
    def test_build_report_from_db_success(self, tmp_path):
        db_file = str(tmp_path / "test_aegis.db")
        db = AegisDatabase(db_file)

        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        t2 = datetime(2024, 11, 20, 10, 15, tzinfo=timezone.utc)
        ev1 = _create_sample_event("E001", t1)
        ev2 = _create_sample_event("E002", t2)
        det1 = _create_sample_detection("D001", event_ids=["E001"])
        inc = _create_sample_incident(
            incident_id="INC999",
            evidence_ids=["E001", "E002"],
            detection_ids=["D001"],
        )

        db.store_events([ev1, ev2])
        db.store_detections([det1])
        db.store_incidents([inc])

        report = build_incident_report_from_db("INC999", db)

        assert report.header.incident_id == "INC999"
        assert len(report.timeline) == 2
        assert len(report.detection_findings) == 1
        assert report.evidence_inventory.resolved_event_count == 2
        assert report.evidence_inventory.missing_event_ids == []

        # Confirm read-only: database row count remains unchanged
        assert db.get_incident_count() == 1
        assert db.get_event_count() == 2
        db.close()

    def test_build_report_from_db_unknown_incident_raises_value_error(self, tmp_path):
        db_file = str(tmp_path / "empty_aegis.db")
        db = AegisDatabase(db_file)

        with pytest.raises(ValueError, match="Incident with ID 'NON_EXISTENT' not found"):
            build_incident_report_from_db("NON_EXISTENT", db)

        db.close()


class TestJsonReportSerialization:
    """Tests for Phase 3 Checkpoint 3 JSON serialization engine."""

    def test_valid_json_serialization_and_roundtrip(self):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        json_str = serialize_report_to_json(report, indent=2)
        assert isinstance(json_str, str)
        assert len(json_str) > 0

        # Roundtrip validation: reconstruct IncidentReport from JSON
        reconstructed = IncidentReport.model_validate_json(json_str)
        assert reconstructed.header.incident_id == report.header.incident_id
        assert reconstructed.executive_summary.severity == report.executive_summary.severity
        assert len(reconstructed.timeline) == len(report.timeline)
        assert reconstructed == report

    def test_complete_preservation_of_report_fields(self):
        incident = _create_sample_incident(
            ai_analysis={
                "summary": "Suspicious brute force sequence.",
                "attack_interpretation": "Credential guessing.",
                "potential_impact": "Account takeover.",
                "recommended_actions": ["Isolate host", "Audit logs"],
                "cited_event_ids": ["E001"],
            },
            ai_status="SUCCESS",
        )
        report = build_incident_report(incident)
        json_str = serialize_report_to_json(report)

        # Confirm all top-level schema blocks exist in serialized string
        for field_name in (
            "header",
            "executive_summary",
            "incident_overview",
            "severity_assessment",
            "detection_findings",
            "timeline",
            "ai_investigation",
            "evidence_verification",
            "recommendations",
            "evidence_inventory",
        ):
            assert f'"{field_name}"' in json_str

    def test_utf8_output_and_special_characters(self):
        t = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
        unicode_process = "C:\\SecOps\\t\u00e9st_\u00f1ame.exe"
        ev = _create_sample_event("E001", t, process=unicode_process, user="us\u00e9r_\u03b1")
        incident = _create_sample_incident(evidence_ids=["E001"])
        report = build_incident_report(incident, events=[ev])

        json_bytes = serialize_report_to_bytes(report)
        decoded = json_bytes.decode("utf-8")
        assert "t\u00e9st_\u00f1ame.exe" in decoded or "\\u00e9" in decoded
        assert "us\u00e9r" in decoded or "\\u00e9" in decoded

    def test_stable_deterministic_output_for_identical_data(self):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        bytes1 = serialize_report_to_bytes(report, indent=2)
        bytes2 = serialize_report_to_bytes(report, indent=2)

        # Byte-for-byte exact equality
        assert bytes1 == bytes2
        assert len(bytes1) == len(bytes2)


class TestReportIntegrityDigest:
    """Tests for SHA-256 integrity calculation and verification."""

    def test_correct_sha256_digest_calculation(self):
        import hashlib
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        json_bytes = serialize_report_to_bytes(report)
        expected_hash = hashlib.sha256(json_bytes).hexdigest().lower()

        computed_digest = compute_report_sha256(json_bytes)
        assert computed_digest == expected_hash
        assert len(computed_digest) == 64

    def test_digest_verification_success(self, tmp_path):
        content = b'{"status": "verified", "incident": "INC001"}'
        digest = compute_report_sha256(content)

        # Verification over raw bytes
        assert verify_report_digest(content, digest) is True

        # Verification over string
        assert verify_report_digest(content.decode("utf-8"), digest) is True

        # Verification over file Path
        test_file = tmp_path / "test_report.json"
        test_file.write_bytes(content)
        assert verify_report_digest(test_file, digest) is True

    def test_failed_verification_after_modifying_one_byte(self, tmp_path):
        original = b'{"status": "verified", "incident": "INC001"}'
        digest = compute_report_sha256(original)

        # Alter one byte: change '1' to '2'
        tampered = b'{"status": "verified", "incident": "INC002"}'
        assert verify_report_digest(tampered, digest) is False

        # Alter file by one byte
        test_file = tmp_path / "tampered.json"
        test_file.write_bytes(tampered)
        assert verify_report_digest(test_file, digest) is False

    def test_invalid_digest_handling(self):
        content = b'{"status": "test"}'

        # Malformed non-hex string
        assert verify_report_digest(content, "not_a_valid_hex_hash_at_all") is False

        # Wrong length (63 characters)
        assert verify_report_digest(content, "a" * 63) is False

        # Wrong length (65 characters)
        assert verify_report_digest(content, "a" * 65) is False

        # Empty string
        assert verify_report_digest(content, "") is False

        # None or non-string
        assert verify_report_digest(content, None) is False
        assert verify_report_digest(content, 12345) is False


class TestJsonReportExport:
    """Tests for file export, overwrite guards, and directory protection."""

    def test_export_json_report_creates_file_and_sidecar(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        out_file = tmp_path / "nested" / "reports" / "INC001.json"
        result = export_json_report(
            report=report,
            output_path=out_file,
            overwrite=False,
            write_sidecar=True,
        )

        assert isinstance(result, JsonReportExportResult)
        assert result.report_path == out_file.resolve()
        assert out_file.is_file()
        assert out_file.stat().st_size == result.byte_count
        assert len(result.sha256_digest) == 64

        # Verify exact bytes on disk match the digest
        disk_bytes = out_file.read_bytes()
        assert compute_report_sha256(disk_bytes) == result.sha256_digest
        assert verify_report_digest(out_file, result.sha256_digest) is True

        # Verify sidecar file
        assert result.sidecar_path is not None
        assert result.sidecar_path.is_file()
        sidecar_text = result.sidecar_path.read_text(encoding="utf-8")
        assert result.sha256_digest in sidecar_text
        assert "INC001.json" in sidecar_text
        assert "source-evidence authenticity" in sidecar_text

    def test_existing_file_protection_raises_file_exists_error(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        out_file = tmp_path / "INC002.json"
        export_json_report(report, out_file)
        assert out_file.is_file()

        # Second export without overwrite=True must raise FileExistsError
        with pytest.raises(FileExistsError, match="Target report file already exists"):
            export_json_report(report, out_file, overwrite=False)

    def test_explicit_overwrite_behavior_succeeds(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        out_file = tmp_path / "INC003.json"
        result1 = export_json_report(report, out_file)
        assert out_file.is_file()

        # Export again with overwrite=True succeeds
        result2 = export_json_report(report, out_file, overwrite=True)
        assert result2.report_path == out_file.resolve()
        assert result2.sha256_digest == result1.sha256_digest

    def test_invalid_output_path_handling(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        # Create a file, then try to use it as a directory
        blocker = tmp_path / "blocker_file"
        blocker.write_text("i am a file", encoding="utf-8")

        invalid_path = blocker / "nested" / "report.json"
        with pytest.raises(OSError):
            export_json_report(report, invalid_path)

    def test_security_guard_prevents_writes_inside_protected_dataset_directories(self):
        from pathlib import Path
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        # Attempt to target data/evaluation
        eval_target = Path("data/evaluation/malicious_report.json")
        with pytest.raises(ValueError, match="Access Denied"):
            export_json_report(report, eval_target)

        # Attempt to target data/development
        dev_target = Path("data/development/malicious_report.json")
        with pytest.raises(ValueError, match="Access Denied"):
            export_json_report(report, dev_target)


class TestHtmlReportGeneration:
    """Tests for Phase 3 Checkpoint 4 HTML report rendering."""

    def test_html_generation_from_valid_incident_report(self):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        html_text = render_incident_report_to_html(report)
        assert isinstance(html_text, str)
        assert "<!DOCTYPE html>" in html_text
        assert "<html" in html_text
        assert "</html>" in html_text

    def test_presence_of_all_available_report_sections(self):
        incident = _create_sample_incident(
            ai_analysis={
                "summary": "Brute force sequence observed.",
                "attack_interpretation": "Credential spray.",
                "potential_impact": "Compromise of user account.",
                "recommended_actions": ["Isolate host", "Audit access logs"],
                "cited_event_ids": ["E001"],
            },
            ai_status="SUCCESS",
        )
        report = build_incident_report(incident)
        digest = "a" * 64
        html_text = render_incident_report_to_html(report, json_digest=digest)

        # 1. Header & ID
        assert report.header.incident_id in html_text
        assert report.header.report_title in html_text
        # 2. Executive summary
        assert "Executive Summary" in html_text
        # 3. Incident overview
        assert "Incident Telemetry Overview" in html_text
        # 4. Severity & rationale
        assert "Deterministic Severity Evaluation" in html_text
        assert report.severity_assessment.severity_rationale in html_text
        # 5. Detection details
        assert "Deterministic Detection Findings" in html_text
        # 6. Chronological timeline
        assert "Chronological Telemetry Timeline" in html_text
        # 7. AI investigation findings
        assert "AI-Assisted Investigation Analysis" in html_text
        # 8. Evidence verification status
        assert "Evidence Verification Status" in html_text
        assert "PENDING_PHASE_2_CHECKPOINT_3" in html_text
        # 9. Recommended actions
        assert "Recommended SOC Action Plan" in html_text
        assert "Immediate Containment" in html_text
        assert "Investigation Steps" in html_text
        assert "Remediation &amp; Hardening" in html_text
        # 10. Evidence inventory
        assert "Evidence &amp; Reconciliation Inventory" in html_text
        # 12. Integrity section
        assert digest in html_text
        assert "report-file integrity" in html_text
        assert "source-evidence authenticity" in html_text

    def test_correct_incident_id_and_severity_rendering(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            incident = _create_sample_incident(
                incident_id=f"INC_{sev}",
                severity=Severity(sev),
            )
            report = build_incident_report(incident)
            html_text = render_incident_report_to_html(report)

            assert f"INC_{sev}" in html_text
            assert f"badge-{sev.lower()}" in html_text

    def test_chronological_timeline_rendering(self):
        t1 = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 11, 20, 10, 10, tzinfo=timezone.utc)
        ev1 = _create_sample_event("E001", t1, event_type="auth_failed")
        ev2 = _create_sample_event("E002", t2, event_type="auth_success")

        incident = _create_sample_incident(evidence_ids=["E001", "E002"])
        report = build_incident_report(incident, events=[ev2, ev1])  # Pass reversed

        html_text = render_incident_report_to_html(report)
        idx_e1 = html_text.find("E001")
        idx_e2 = html_text.find("E002")

        assert idx_e1 != -1 and idx_e2 != -1
        assert idx_e1 < idx_e2  # E001 must appear before E002 in rendered HTML
        assert "auth_failed" in html_text
        assert "auth_success" in html_text

    def test_ai_success_rendering(self):
        incident = _create_sample_incident(
            ai_analysis={
                "summary": "Coordinated attack chain.",
                "attack_interpretation": "Lateral movement.",
                "potential_impact": "Host compromise.",
                "recommended_actions": ["Quarantine host"],
                "cited_event_ids": ["E001"],
            },
            ai_status="SUCCESS",
        )
        report = build_incident_report(incident)
        html_text = render_incident_report_to_html(report)

        assert "AI Investigation Analysis &bull; SLM Analysis Completed Successfully" in html_text
        assert "Coordinated attack chain." in html_text
        assert "Lateral movement." in html_text
        assert "Host compromise." in html_text
        assert "Citation References Validated" in html_text

    def test_ai_unavailable_and_fallback_rendering(self):
        # 1. No AI analysis at all
        incident_no_ai = _create_sample_incident(ai_analysis=None, ai_status=None)
        report_no_ai = build_incident_report(incident_no_ai)
        html_no_ai = render_incident_report_to_html(report_no_ai)
        assert "Deterministic Triage Only (No AI Analysis Executed)" in html_no_ai
        assert "Deterministic Only" in html_no_ai

        # 2. Fallback AI analysis
        incident_fallback = _create_sample_incident(
            ai_analysis={
                "summary": "Deterministic rule-based fallback summary.",
                "attack_interpretation": "Interpretation based on deterministic rules.",
                "potential_impact": "Calculated based on detected attack patterns.",
                "recommended_actions": ["Review logs"],
                "cited_event_ids": ["E001"],
            },
            ai_status="FALLBACK",
        )
        report_fallback = build_incident_report(incident_fallback)
        html_fallback = render_incident_report_to_html(report_fallback)
        assert "Deterministic Fallback Triage" in html_fallback
        assert "Fallback Mode" in html_fallback

    def test_missing_evidence_visibility_banner(self):
        # Missing evidence: incident lists E999 which is not provided in events list
        incident = _create_sample_incident(evidence_ids=["E999"])
        report = build_incident_report(incident, events=[])
        html_text = render_incident_report_to_html(report)

        assert "AUDIT WARNING: Unresolved Telemetry References Detected" in html_text
        assert "Missing Event IDs: E999" in html_text
        assert "AEGIS-X never fabricates synthetic data" in html_text

    def test_html_escaping_of_malicious_input(self):
        xss_user = "<script>alert('pwned_user')</script>"
        xss_process = 'malicious.exe" onmouseover="alert(\'xss\')'
        xss_raw = {"payload": '<img src=x onerror=alert(1)>', "test": '"><svg/onload=alert(1)>'}

        t = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
        ev = _create_sample_event(
            "E001",
            t,
            user=xss_user,
            process=xss_process,
            raw_data=xss_raw,
        )
        incident = _create_sample_incident(
            user=xss_user,
            evidence_ids=["E001"],
            ai_analysis={
                "summary": "Injected <script>document.cookie</script>",
                "attack_interpretation": "Attack with <b>markup</b>",
                "potential_impact": "<iframe src='evil.com'></iframe>",
                "recommended_actions": ["<script>eval()</script>"],
                "cited_event_ids": ["E001"],
            },
            ai_status="SUCCESS",
        )
        report = build_incident_report(incident, events=[ev])
        html_text = render_incident_report_to_html(report)

        # Raw executable tags must NEVER appear unescaped in HTML
        assert "<script>alert('pwned_user')</script>" not in html_text
        assert '<img src=x onerror=alert(1)>' not in html_text
        assert '<iframe src=' not in html_text
        assert '<script>document.cookie</script>' not in html_text
        assert '<script>eval()</script>' not in html_text

        # Properly escaped entities must be present
        assert "&lt;script&gt;alert(&#x27;pwned_user&#x27;)&lt;/script&gt;" in html_text
        assert "&lt;img src=x onerror=alert(1)&gt;" in html_text
        assert "&lt;iframe src=&#x27;evil.com&#x27;&gt;&lt;/iframe&gt;" in html_text

    def test_no_remote_assets_or_external_dependencies(self):
        incident = _create_sample_incident()
        report = build_incident_report(incident)
        html_text = render_incident_report_to_html(report)

        # Zero remote CDNs, scripts, or fonts
        assert "http://" not in html_text
        assert "https://" not in html_text
        assert "<script" not in html_text
        assert "fonts.googleapis.com" not in html_text
        assert "cdn." not in html_text

    def test_print_css_presence(self):
        incident = _create_sample_incident()
        report = build_incident_report(incident)
        html_text = render_incident_report_to_html(report)

        assert "@media print" in html_text
        assert "page-break-inside: avoid" in html_text
        assert "break-inside: avoid" in html_text


class TestHtmlReportExport:
    """Tests for HTML report file export, filesystem safety, and overwrite controls."""

    def test_export_html_report_creates_file(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        out_file = tmp_path / "exports" / "html" / "INC001.html"
        digest = "b" * 64
        result_path = export_html_report(
            report=report,
            output_path=out_file,
            overwrite=False,
            json_digest=digest,
        )

        assert result_path == out_file.resolve()
        assert out_file.is_file()
        content = out_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert report.header.incident_id in content
        assert digest in content

    def test_existing_html_file_protection_raises_file_exists_error(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        out_file = tmp_path / "INC002.html"
        export_html_report(report, out_file)
        assert out_file.is_file()

        # Second export with overwrite=False must fail
        with pytest.raises(FileExistsError, match="Target HTML report already exists"):
            export_html_report(report, out_file, overwrite=False)

    def test_explicit_overwrite_behavior_succeeds(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        out_file = tmp_path / "INC003.html"
        export_html_report(report, out_file)

        # Export again with overwrite=True
        path2 = export_html_report(report, out_file, overwrite=True)
        assert path2 == out_file.resolve()
        assert out_file.is_file()

    def test_invalid_output_path_handling(self, tmp_path):
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        blocker = tmp_path / "blocker_file"
        blocker.write_text("file content", encoding="utf-8")

        invalid_path = blocker / "nested" / "report.html"
        with pytest.raises(OSError):
            export_html_report(report, invalid_path)

    def test_security_guard_prevents_writes_inside_protected_dataset_directories(self):
        from pathlib import Path
        incident = _create_sample_incident()
        report = build_incident_report(incident)

        # Attempt to target data/evaluation
        eval_target = Path("data/evaluation/malicious_report.html")
        with pytest.raises(ValueError, match="Access Denied"):
            export_html_report(report, eval_target)

        # Attempt to target data/development
        dev_target = Path("data/development/malicious_report.html")
        with pytest.raises(ValueError, match="Access Denied"):
            export_html_report(report, dev_target)


class TestReportCLI:
    """End-to-end integration tests for backend/generate_report.py CLI."""

    @pytest.fixture
    def test_db_setup(self, tmp_path):
        """Builds a temporary, controlled SQLite database with sample events and incident."""
        db_file = tmp_path / "cli_test_aegis.db"
        db = AegisDatabase(str(db_file))
        t1 = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
        ev1 = _create_sample_event("E001", t1)
        det1 = _create_sample_detection("D001", event_ids=["E001"])
        inc = _create_sample_incident("INC_CLI_001", evidence_ids=["E001"], detection_ids=["D001"])
        db.store_events([ev1])
        db.store_detections([det1])
        db.store_incidents([inc])
        db.close()
        return str(db_file), "INC_CLI_001"

    def test_cli_help(self):
        with pytest.raises(SystemExit) as exc:
            cli_main(["--help"])
        assert exc.value.code == 0

    def test_cli_json_generation(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_json"

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "json",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert exit_code == 0
        json_file = out_dir / f"{inc_id}_report.json"
        assert json_file.is_file()
        assert not (out_dir / f"{inc_id}_report.html").exists()

        # Validate JSON content
        parsed = IncidentReport.model_validate_json(json_file.read_text(encoding="utf-8"))
        assert parsed.header.incident_id == inc_id

    def test_cli_html_generation(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_html"

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "html",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert exit_code == 0
        html_file = out_dir / f"{inc_id}_report.html"
        assert html_file.is_file()
        assert not (out_dir / f"{inc_id}_report.json").exists()

        content = html_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert inc_id in content

    def test_cli_both_formats_generation(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_both"

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert exit_code == 0
        json_file = out_dir / f"{inc_id}_report.json"
        html_file = out_dir / f"{inc_id}_report.html"
        assert json_file.is_file()
        assert html_file.is_file()

    def test_cli_json_sidecar_generation(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_sidecar"

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "json",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
            "--sidecar",
        ])
        assert exit_code == 0
        json_file = out_dir / f"{inc_id}_report.json"
        sidecar_file = out_dir / f"{inc_id}_report.json.sha256"
        assert json_file.is_file()
        assert sidecar_file.is_file()

        sidecar_text = sidecar_file.read_text(encoding="utf-8")
        json_bytes = json_file.read_bytes()
        expected_digest = compute_report_sha256(json_bytes)
        assert expected_digest in sidecar_text
        assert json_file.name in sidecar_text

    def test_cli_correct_digest_passed_to_html(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_digest_link"

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert exit_code == 0
        json_file = out_dir / f"{inc_id}_report.json"
        html_file = out_dir / f"{inc_id}_report.html"

        json_digest = compute_report_sha256(json_file.read_bytes())
        html_content = html_file.read_text(encoding="utf-8")
        assert json_digest in html_content
        assert "Companion Machine-Readable JSON SHA-256 Digest" in html_content
        assert "report-file integrity" in html_content

    def test_cli_unknown_incident_id(self, tmp_path, test_db_setup, capsys):
        db_path, _ = test_db_setup
        out_dir = tmp_path / "reports_unknown"

        exit_code = cli_main([
            "--incident-id", "INC_DOES_NOT_EXIST",
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower() or "not found" in captured.out.lower()

    def test_cli_existing_file_protection(self, tmp_path, test_db_setup, capsys):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_conflict"

        # First run succeeds
        code1 = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert code1 == 0

        # Second run without --overwrite fails with exit code 1
        code2 = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert code2 == 1
        captured = capsys.readouterr()
        assert "already exists" in captured.err.lower()

    def test_cli_explicit_overwrite_succeeds(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_overwrite"

        code1 = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert code1 == 0

        # Run with --overwrite succeeds
        code2 = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
            "--overwrite",
        ])
        assert code2 == 0

    def test_cli_protected_dataset_path_rejection(self, test_db_setup, capsys):
        db_path, inc_id = test_db_setup

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "json",
            "--output-dir", "data/evaluation",
            "--db-path", db_path,
        ])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "protected" in captured.err.lower() or "denied" in captured.err.lower()

    def test_cli_database_connection_closed_on_success_and_failure(self, tmp_path, test_db_setup, monkeypatch):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_db_close"

        close_calls = []
        original_close = AegisDatabase.close

        def spy_close(self):
            close_calls.append(True)
            return original_close(self)

        monkeypatch.setattr(AegisDatabase, "close", spy_close)

        # 1. Success case: verify close() was invoked
        code_success = cli_main([
            "--incident-id", inc_id,
            "--format", "json",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert code_success == 0
        assert len(close_calls) >= 1

        # 2. Failure case: unknown incident ID must still close DB
        close_calls.clear()
        code_fail = cli_main([
            "--incident-id", "INC_NON_EXISTENT",
            "--format", "json",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
        ])
        assert code_fail == 1
        assert len(close_calls) >= 1

    def test_cli_output_file_contents_valid_and_complete(self, tmp_path, test_db_setup):
        db_path, inc_id = test_db_setup
        out_dir = tmp_path / "reports_validation"

        exit_code = cli_main([
            "--incident-id", inc_id,
            "--format", "both",
            "--output-dir", str(out_dir),
            "--db-path", db_path,
            "--sidecar",
        ])
        assert exit_code == 0

        json_file = out_dir / f"{inc_id}_report.json"
        html_file = out_dir / f"{inc_id}_report.html"
        sidecar_file = out_dir / f"{inc_id}_report.json.sha256"

        assert json_file.is_file()
        assert html_file.is_file()
        assert sidecar_file.is_file()

        # Verify parsed report matches all core fields
        rep = IncidentReport.model_validate_json(json_file.read_text(encoding="utf-8"))
        assert rep.header.incident_id == inc_id
        assert len(rep.timeline) == 1
        assert rep.timeline[0].event_id == "E001"
        assert rep.detection_findings[0].detection_id == "D001"
        assert rep.severity_assessment.severity == "HIGH"

        # Verify HTML contains all critical markers
        html_text = html_file.read_text(encoding="utf-8")
        assert inc_id in html_text
        assert "E001" in html_text
        assert "D001" in html_text
        assert "HIGH" in html_text


# =============================================================================
# 4. PHASE 2 CHECKPOINT 3C: EVIDENCE VERIFICATION REPORTING INTEGRATION TESTS
# =============================================================================

class TestEvidenceVerificationReporting:
    """Comprehensive tests for evidence verification integration in JSON and HTML reports."""

    def test_1_verified_json_and_html_report(self):
        ver_data = {
            "status": "VERIFIED",
            "total_evidence_count": 2,
            "resolved_evidence_count": 2,
            "missing_evidence_count": 0,
            "cited_evidence_count": 2,
            "valid_citation_count": 2,
            "verified_evidence_ids": ["E001", "E002"],
            "uncited_evidence_ids": [],
            "missing_evidence_ids": [],
            "invalid_citation_ids": [],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["All incident evidence events resolved from database and verified free of discrepancies."],
            "database_error": None,
        }
        incident = _create_sample_incident(
            evidence_ids=["E001", "E002"],
            ai_analysis={"summary": "Attack narrative.", "cited_event_ids": ["E001", "E002"]},
            ai_status="SUCCESS",
            ai_verification=ver_data,
        )
        report = build_incident_report(incident)

        # 1. Inspect model
        assert report.evidence_verification.verification_performed is True
        assert report.evidence_verification.status == "VERIFIED"
        assert report.evidence_verification.is_verified is True
        assert report.evidence_verification.valid_citation_count == 2
        assert report.evidence_verification.verified_evidence_ids == ["E001", "E002"]

        # 2. Inspect JSON serialization
        json_str = serialize_report_to_json(report)
        assert '"status": "VERIFIED"' in json_str
        assert '"verification_performed": true' in json_str
        assert '"valid_citation_count": 2' in json_str
        assert '"verified_evidence_ids"' in json_str
        reconstructed = IncidentReport.model_validate_json(json_str)
        assert reconstructed.evidence_verification.status == "VERIFIED"

        # 3. Inspect HTML rendering
        html_text = render_incident_report_to_html(report)
        assert "badge-verification-verified" in html_text
        assert "VERIFIED" in html_text
        assert "&check; Evidence Verification: All evidence resolved and validated against ground-truth database records." in html_text
        assert "Verified Evidence IDs:" in html_text
        assert "E001" in html_text
        assert "E002" in html_text

    def test_2_partial_json_and_html_report(self):
        ver_data = {
            "status": "PARTIAL",
            "total_evidence_count": 2,
            "resolved_evidence_count": 2,
            "missing_evidence_count": 0,
            "cited_evidence_count": 1,
            "valid_citation_count": 1,
            "verified_evidence_ids": ["E001"],
            "uncited_evidence_ids": ["E002"],
            "missing_evidence_ids": [],
            "invalid_citation_ids": [],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["All cited events verified, but citations cover 1 of 2 evidence events."],
            "database_error": None,
        }
        incident = _create_sample_incident(
            evidence_ids=["E001", "E002"],
            ai_analysis={"summary": "Partial narrative.", "cited_event_ids": ["E001"]},
            ai_status="SUCCESS",
            ai_verification=ver_data,
        )
        report = build_incident_report(incident)

        assert report.evidence_verification.status == "PARTIAL"
        assert report.evidence_verification.is_verified is False
        assert report.evidence_verification.uncited_evidence_ids == ["E002"]

        # JSON
        json_str = serialize_report_to_json(report)
        assert '"status": "PARTIAL"' in json_str
        assert '"uncited_evidence_ids": [\n      "E002"\n    ]' in json_str or '"uncited_evidence_ids": ["E002"]' in json_str or '"E002"' in json_str

        # HTML
        html_text = render_incident_report_to_html(report)
        assert "badge-verification-partial" in html_text
        assert "PARTIAL" in html_text
        assert "&#9888; Evidence Verification: Evidence resolved with partial coverage." in html_text
        assert "All cited events verified, but citations cover 1 of 2 evidence events." in html_text

    def test_3_unverified_json_and_html_report(self):
        ver_data = {
            "status": "UNVERIFIED",
            "total_evidence_count": 2,
            "resolved_evidence_count": 1,
            "missing_evidence_count": 1,
            "cited_evidence_count": 1,
            "valid_citation_count": 0,
            "verified_evidence_ids": [],
            "uncited_evidence_ids": ["E001"],
            "missing_evidence_ids": ["E002"],
            "invalid_citation_ids": ["E_HALLUCINATED"],
            "duplicate_citation_ids": [],
            "discrepancies": [
                {
                    "event_id": "E_HALLUCINATED",
                    "mismatch_type": "FABRICATED_CITATION",
                    "expected_value": "Member of INC000001.evidence_event_ids",
                    "actual_value": "E_HALLUCINATED",
                    "explanation": "Citation does not exist in incident evidence.",
                }
            ],
            "verification_rationale": ["1 declared evidence event(s) not found in SQLite store."],
            "database_error": None,
        }
        incident = _create_sample_incident(
            evidence_ids=["E001", "E002"],
            ai_analysis={"summary": "Narrative with fake citation.", "cited_event_ids": ["E_HALLUCINATED"]},
            ai_status="FALLBACK",
            ai_verification=ver_data,
        )
        report = build_incident_report(incident)

        assert report.evidence_verification.status == "UNVERIFIED"
        assert report.evidence_verification.missing_evidence_ids == ["E002"]
        assert report.evidence_verification.invalid_citation_ids == ["E_HALLUCINATED"]
        assert len(report.evidence_verification.discrepancies) == 1

        # JSON
        json_str = serialize_report_to_json(report)
        assert '"status": "UNVERIFIED"' in json_str
        assert '"FABRICATED_CITATION"' in json_str
        assert '"E_HALLUCINATED"' in json_str

        # HTML
        html_text = render_incident_report_to_html(report)
        assert "badge-verification-unverified" in html_text
        assert "UNVERIFIED" in html_text
        assert "&#10006; Evidence Verification: Unable to fully verify incident evidence." in html_text
        assert "Invalid Citation IDs:" in html_text
        assert "E_HALLUCINATED" in html_text
        assert "Missing Evidence IDs:" in html_text
        assert "E002" in html_text
        assert "Structured Claims &amp; Discrepancies (1)" in html_text

    def test_4_missing_verification_result(self):
        # Incident without ai_verification
        incident = _create_sample_incident(
            evidence_ids=["E001", "E002"],
            ai_verification=None,
        )
        report = build_incident_report(incident)

        assert report.evidence_verification.verification_performed is False
        assert report.evidence_verification.status == "NOT_AVAILABLE"
        assert report.evidence_verification.is_verified is False
        assert "not been performed" in report.evidence_verification.details

        # HTML
        html_text = render_incident_report_to_html(report)
        assert "Evidence verification has not been performed for this incident." in html_text
        assert "NOT AVAILABLE" in html_text or "PENDING_PHASE_2_CHECKPOINT_3" in html_text
        # Must NEVER show VERIFIED badge
        assert '<span class="badge badge-verification-verified' not in html_text
        assert ">VERIFIED</span>" not in html_text

    def test_5_invalid_and_missing_evidence_references(self):
        ver_data = {
            "status": "UNVERIFIED",
            "total_evidence_count": 3,
            "resolved_evidence_count": 1,
            "missing_evidence_count": 2,
            "cited_evidence_count": 2,
            "valid_citation_count": 0,
            "verified_evidence_ids": ["E001"],
            "uncited_evidence_ids": [],
            "missing_evidence_ids": ["E002", "E003"],
            "invalid_citation_ids": ["E_FAKE_1", "E_FAKE_2"],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["2 missing evidence events, 2 invalid citations."],
            "database_error": None,
        }
        incident = _create_sample_incident(evidence_ids=["E001", "E002", "E003"], ai_verification=ver_data)
        report = build_incident_report(incident)

        # JSON
        json_str = serialize_report_to_json(report)
        assert '"E_FAKE_1"' in json_str
        assert '"E_FAKE_2"' in json_str
        assert '"E002"' in json_str
        assert '"E003"' in json_str

        # HTML
        html_text = render_incident_report_to_html(report)
        assert "E_FAKE_1" in html_text
        assert "E_FAKE_2" in html_text
        assert "E002" in html_text
        assert "E003" in html_text

    def test_6_structured_claim_discrepancies(self):
        discrepancies = [
            {
                "event_id": "E001",
                "mismatch_type": "USER_MISMATCH",
                "expected_value": "admin",
                "actual_value": "charlie",
                "explanation": "Event user 'charlie' does not match claimed user 'admin'.",
            },
            {
                "event_id": "E002",
                "mismatch_type": "DEVICE_MISMATCH",
                "expected_value": "SRV-DC01",
                "actual_value": "WS-099",
                "explanation": "Event device 'WS-099' does not match claimed device 'SRV-DC01'.",
            },
            {
                "event_id": None,
                "mismatch_type": "TIMESTAMP_OUT_OF_BOUNDS",
                "expected_value": "2024-11-20T10:00:00Z .. 2024-11-20T10:30:00Z",
                "actual_value": "2024-11-20T12:00:00Z",
                "explanation": "Event timestamp falls outside declared incident window.",
            },
        ]
        ver_data = {
            "status": "UNVERIFIED",
            "total_evidence_count": 2,
            "resolved_evidence_count": 2,
            "missing_evidence_count": 0,
            "cited_evidence_count": 2,
            "valid_citation_count": 2,
            "verified_evidence_ids": [],
            "uncited_evidence_ids": [],
            "missing_evidence_ids": [],
            "invalid_citation_ids": [],
            "duplicate_citation_ids": [],
            "discrepancies": discrepancies,
            "verification_rationale": ["3 critical factual discrepancies detected."],
            "database_error": None,
        }
        incident = _create_sample_incident(ai_verification=ver_data)
        report = build_incident_report(incident)

        # JSON check
        json_str = serialize_report_to_json(report)
        assert '"USER_MISMATCH"' in json_str
        assert '"DEVICE_MISMATCH"' in json_str
        assert '"TIMESTAMP_OUT_OF_BOUNDS"' in json_str
        assert '"admin"' in json_str
        assert '"charlie"' in json_str

        # HTML check
        html_text = render_incident_report_to_html(report)
        assert "Structured Claims &amp; Discrepancies (3)" in html_text
        assert "USER_MISMATCH" in html_text
        assert "DEVICE_MISMATCH" in html_text
        assert "TIMESTAMP_OUT_OF_BOUNDS" in html_text
        assert "admin" in html_text
        assert "charlie" in html_text
        assert "SRV-DC01" in html_text
        assert "WS-099" in html_text

    def test_7_ai_success_with_verification_unverified(self):
        # AI generated a response (SUCCESS), but verification found missing records (UNVERIFIED)
        ver_data = {
            "status": "UNVERIFIED",
            "total_evidence_count": 2,
            "resolved_evidence_count": 0,
            "missing_evidence_count": 2,
            "cited_evidence_count": 1,
            "valid_citation_count": 0,
            "verified_evidence_ids": [],
            "uncited_evidence_ids": ["E001", "E002"],
            "missing_evidence_ids": ["E001", "E002"],
            "invalid_citation_ids": ["E001"],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["Database lookup failed: SQLite store missing."],
            "database_error": "Table 'events' corrupted",
        }
        incident = _create_sample_incident(
            ai_analysis={"summary": "Valid AI analysis.", "cited_event_ids": ["E001"]},
            ai_status="SUCCESS",
            ai_verification=ver_data,
        )
        report = build_incident_report(incident)

        # Statuses are independent:
        assert report.ai_investigation.status == "SUCCESS"
        assert report.evidence_verification.status == "UNVERIFIED"

        html_text = render_incident_report_to_html(report)
        # AI shows success
        assert "AI Investigation Analysis &bull; SLM Analysis Completed Successfully" in html_text
        # Verification shows unverified with danger banner
        assert "badge-verification-unverified" in html_text
        assert "Database Error:" in html_text
        assert "Table &#x27;events&#x27; corrupted" in html_text or "Table 'events' corrupted" in html_text

    def test_8_ai_fallback_with_verification_partial(self):
        ver_data = {
            "status": "PARTIAL",
            "total_evidence_count": 3,
            "resolved_evidence_count": 3,
            "missing_evidence_count": 0,
            "cited_evidence_count": 1,
            "valid_citation_count": 1,
            "verified_evidence_ids": ["E001"],
            "uncited_evidence_ids": ["E002", "E003"],
            "missing_evidence_ids": [],
            "invalid_citation_ids": [],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["Citations cover 1 of 3 events."],
            "database_error": None,
        }
        incident = _create_sample_incident(
            ai_analysis={"summary": "Deterministic fallback summary.", "cited_event_ids": ["E001"]},
            ai_status="FALLBACK",
            ai_verification=ver_data,
        )
        report = build_incident_report(incident)

        assert report.ai_investigation.status == "FALLBACK"
        assert report.evidence_verification.status == "PARTIAL"

        html_text = render_incident_report_to_html(report)
        assert "Deterministic Fallback Triage" in html_text
        assert "badge-verification-partial" in html_text

    def test_9_ai_unavailable_with_verification_verified(self):
        ver_data = {
            "status": "VERIFIED",
            "total_evidence_count": 2,
            "resolved_evidence_count": 2,
            "missing_evidence_count": 0,
            "cited_evidence_count": 2,
            "valid_citation_count": 2,
            "verified_evidence_ids": ["E001", "E002"],
            "uncited_evidence_ids": [],
            "missing_evidence_ids": [],
            "invalid_citation_ids": [],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["All evidence verified from database."],
            "database_error": None,
        }
        incident = _create_sample_incident(
            ai_analysis={"summary": "Deterministic offline fallback.", "cited_event_ids": ["E001", "E002"]},
            ai_status="UNAVAILABLE",
            ai_verification=ver_data,
        )
        report = build_incident_report(incident)

        # AI is UNAVAILABLE, but verification is VERIFIED
        assert report.ai_investigation.status == "UNAVAILABLE"
        assert report.evidence_verification.status == "VERIFIED"

        html_text = render_incident_report_to_html(report)
        assert "Deterministic Fallback Triage" in html_text
        assert "badge-verification-verified" in html_text

    def test_10_html_escaping_of_verification_rationale_and_discrepancies(self):
        malicious_disc = {
            "event_id": "<script>alert('eid')</script>",
            "mismatch_type": "USER_MISMATCH",
            "expected_value": "<img src=x onerror=alert('exp')>",
            "actual_value": "actual<svg/onload=alert('act')>",
            "explanation": "Dangerous <b>markup</b> & payload <script>steal()</script>",
        }
        malicious_rationale = [
            "Rationale with <script>alert('rat')</script>",
            "Error with <iframe src='bad.com'></iframe>",
        ]
        ver_data = {
            "status": "UNVERIFIED",
            "total_evidence_count": 1,
            "resolved_evidence_count": 1,
            "missing_evidence_count": 0,
            "cited_evidence_count": 1,
            "valid_citation_count": 0,
            "verified_evidence_ids": [],
            "uncited_evidence_ids": [],
            "missing_evidence_ids": [],
            "invalid_citation_ids": ["<script>bad_id</script>"],
            "duplicate_citation_ids": [],
            "discrepancies": [malicious_disc],
            "verification_rationale": malicious_rationale,
            "database_error": "<script>alert('db_err')</script>",
        }
        incident = _create_sample_incident(ai_verification=ver_data)
        report = build_incident_report(incident)

        html_text = render_incident_report_to_html(report)

        # Raw tags MUST NOT be present
        assert "<script>alert('eid')</script>" not in html_text
        assert "<img src=x onerror=alert('exp')>" not in html_text
        assert "<svg/onload=alert('act')>" not in html_text
        assert "<script>steal()</script>" not in html_text
        assert "<script>alert('rat')</script>" not in html_text
        assert "<iframe src='bad.com'></iframe>" not in html_text
        assert "<script>bad_id</script>" not in html_text
        assert "<script>alert('db_err')</script>" not in html_text

        # Escaped entities MUST be present
        assert "&lt;script&gt;alert(&#x27;eid&#x27;)&lt;/script&gt;" in html_text
        assert "&lt;img src=x onerror=alert(&#x27;exp&#x27;)&gt;" in html_text
        assert "&lt;iframe src=&#x27;bad.com&#x27;&gt;&lt;/iframe&gt;" in html_text

    def test_11_deterministic_json_output_with_verification(self):
        ver_data = {
            "status": "VERIFIED",
            "total_evidence_count": 2,
            "resolved_evidence_count": 2,
            "missing_evidence_count": 0,
            "cited_evidence_count": 2,
            "valid_citation_count": 2,
            "verified_evidence_ids": ["E001", "E002"],
            "uncited_evidence_ids": [],
            "missing_evidence_ids": [],
            "invalid_citation_ids": [],
            "duplicate_citation_ids": [],
            "discrepancies": [],
            "verification_rationale": ["Consistent deterministic audit trail."],
            "database_error": None,
        }
        incident = _create_sample_incident(ai_verification=ver_data)
        report = build_incident_report(incident)

        bytes1 = serialize_report_to_bytes(report)
        bytes2 = serialize_report_to_bytes(report)
        assert bytes1 == bytes2
        assert compute_report_sha256(bytes1) == compute_report_sha256(bytes2)

    def test_12_backward_compatibility_with_existing_report_generation(self, tmp_path):
        # Incident created with no ai_verification (backward compatibility)
        incident = _create_sample_incident(ai_verification=None)
        report = build_incident_report(incident)

        out_json = tmp_path / "legacy.json"
        out_html = tmp_path / "legacy.html"

        res_json = export_json_report(report, out_json, write_sidecar=True)
        res_html = export_html_report(report, out_html, json_digest=res_json.sha256_digest)

        assert out_json.is_file()
        assert out_html.is_file()
        assert verify_report_digest(out_json, res_json.sha256_digest) is True
