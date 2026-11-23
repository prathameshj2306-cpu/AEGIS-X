"""
Unit tests for the correlation engine and severity classifier.

Tests cover:
- Same-user detections within time window → merged into one incident.
- Different-user detections → separate incidents.
- Time window boundary behavior.
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW.
- Severity rationale generation.
- Incident title generation.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import AegisConfig
from app.schemas.events import NormalizedEvent, EventSource
from app.schemas.incidents import Detection, Severity
from app.correlation.correlator import correlate_detections, build_incidents
from app.severity.classifier import classify_severity, classify_all


def _make_event(event_id: str, user: str, device: str,
                timestamp: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user=user,
        device=device,
        ip="192.168.1.10",
        event_type="login_failure",
        source=EventSource.AUTHENTICATION,
        raw_data={"test": True},
    )


def _make_detection(detection_id: str, rule_name: str, user: str,
                    device: str, event_ids: list[str],
                    timestamp: datetime | None = None) -> Detection:
    return Detection(
        detection_id=detection_id,
        rule_name=rule_name,
        explanation=f"Test detection: {rule_name}",
        event_ids=event_ids,
        timestamp=timestamp or datetime.now(timezone.utc),
        user=user,
        device=device,
        confidence="high",
    )


class TestCorrelation:
    def test_same_user_within_window_merged(self):
        """Two detections for same user within 30 min → one group."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event("E001", "alice", "WS-001", base),
            _make_event("E002", "alice", "WS-001", base + timedelta(minutes=5)),
            _make_event("E003", "alice", "WS-001", base + timedelta(minutes=10)),
        ]
        detections = [
            _make_detection("D001", "brute_force_login", "alice", "WS-001", ["E001", "E002"]),
            _make_detection("D002", "privilege_escalation", "alice", "WS-001", ["E003"]),
        ]

        config = AegisConfig()
        groups = correlate_detections(detections, events, config)
        assert len(groups) == 1
        assert len(groups[0].detections) == 2

    def test_different_users_separate_incidents(self):
        """Detections for different users → separate groups."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event("E001", "alice", "WS-001", base),
            _make_event("E002", "bob", "WS-002", base + timedelta(minutes=5)),
        ]
        detections = [
            _make_detection("D001", "brute_force_login", "alice", "WS-001", ["E001"]),
            _make_detection("D002", "brute_force_login", "bob", "WS-002", ["E002"]),
        ]

        groups = correlate_detections(detections, events)
        assert len(groups) == 2

    def test_same_user_outside_window_separate(self):
        """Same user but detections >30 min apart → separate groups."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event("E001", "alice", "WS-001", base),
            _make_event("E002", "alice", "WS-001", base + timedelta(hours=2)),
        ]
        detections = [
            _make_detection("D001", "brute_force_login", "alice", "WS-001", ["E001"]),
            _make_detection("D002", "suspicious_process", "alice", "WS-001", ["E002"]),
        ]

        groups = correlate_detections(detections, events)
        assert len(groups) == 2

    def test_build_incidents_from_groups(self):
        """Build Incident objects from correlation groups."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event("E001", "alice", "WS-001", base),
            _make_event("E002", "alice", "WS-001", base + timedelta(minutes=5)),
        ]
        detections = [
            _make_detection("D001", "brute_force_login", "alice", "WS-001", ["E001"]),
            _make_detection("D002", "privilege_escalation", "alice", "WS-001", ["E002"]),
        ]

        groups = correlate_detections(detections, events)
        incidents = build_incidents(groups)

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.incident_id == "INC000001"
        assert "alice" in (inc.user or "")
        assert "brute_force_login" in inc.detected_patterns
        assert "privilege_escalation" in inc.detected_patterns
        assert "E001" in inc.evidence_event_ids
        assert "E002" in inc.evidence_event_ids


class TestSeverityClassification:
    def setup_method(self):
        self.config = AegisConfig()

    def _make_incident(self, patterns: list[str]):
        """Helper to build an incident with given detection patterns."""
        from app.schemas.incidents import Incident, IncidentStatus
        return Incident(
            incident_id="INC000001",
            title="Test Incident",
            severity=Severity.LOW,
            status=IncidentStatus.OPEN,
            detected_patterns=patterns,
            user="alice",
            device="WS-001",
            start_time=datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2024, 11, 18, 10, 30, 0, tzinfo=timezone.utc),
            evidence_event_ids=["E001"],
            detection_ids=["D001"],
            severity_rationale="Pending",
            created_at=datetime.now(timezone.utc),
        )

    def test_critical_three_serious_patterns(self):
        """3 serious patterns → CRITICAL."""
        inc = self._make_incident([
            "brute_force_login", "privilege_escalation", "suspicious_process"
        ])
        classify_severity(inc, self.config)
        assert inc.severity == Severity.CRITICAL
        assert "CRITICAL" in inc.severity_rationale
        assert inc.risk_score is not None and inc.risk_score >= 90

    def test_high_two_serious_patterns(self):
        """2 serious patterns → HIGH."""
        inc = self._make_incident(["brute_force_login", "privilege_escalation"])
        classify_severity(inc, self.config)
        assert inc.severity == Severity.HIGH
        assert "HIGH" in inc.severity_rationale

    def test_medium_single_brute_force(self):
        """Single brute-force → MEDIUM."""
        inc = self._make_incident(["brute_force_login"])
        classify_severity(inc, self.config)
        assert inc.severity == Severity.MEDIUM
        assert "MEDIUM" in inc.severity_rationale

    def test_medium_single_suspicious_process(self):
        """Single suspicious process → MEDIUM."""
        inc = self._make_incident(["suspicious_process"])
        classify_severity(inc, self.config)
        assert inc.severity == Severity.MEDIUM

    def test_low_unusual_login_only(self):
        """Only unusual login time → LOW."""
        inc = self._make_incident(["unusual_login_time"])
        classify_severity(inc, self.config)
        assert inc.severity == Severity.LOW
        assert "LOW" in inc.severity_rationale

    def test_severity_rationale_is_human_readable(self):
        """Severity rationale should be a readable explanation."""
        inc = self._make_incident(["brute_force_login", "suspicious_process"])
        classify_severity(inc, self.config)
        assert len(inc.severity_rationale) > 20
        # Should mention the patterns
        assert "brute_force" in inc.severity_rationale.lower() or \
               "suspicious_process" in inc.severity_rationale.lower()

    def test_classify_all(self):
        """classify_all should process a list of incidents."""
        incidents = [
            self._make_incident(["brute_force_login"]),
            self._make_incident(["unusual_login_time"]),
        ]
        classify_all(incidents, self.config)
        assert incidents[0].severity == Severity.MEDIUM
        assert incidents[1].severity == Severity.LOW
