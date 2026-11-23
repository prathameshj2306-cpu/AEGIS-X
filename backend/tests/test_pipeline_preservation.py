"""
Regression tests for pipeline execution, incident identity stability,
and AI analysis / evidence verification preservation across runs.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import AegisConfig
from app.correlation.correlator import build_incidents, correlate_detections
from app.database.store import AegisDatabase
from app.detection.engine import run_detection
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Incident, IncidentStatus, Severity
from app.severity.classifier import classify_all


def _make_event(event_id: str, user: str, device: str, timestamp: datetime,
                event_type: str = "login_failure", process: str | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user=user,
        device=device,
        ip="192.168.1.50",
        event_type=event_type,
        source=EventSource.AUTHENTICATION if "login" in event_type else EventSource.ENDPOINT,
        process=process,
        raw_data={"test": True},
    )


class TestPipelinePreservation:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_preservation.db")
        self.db = AegisDatabase(self.db_path)
        self.config = AegisConfig()

    def teardown_method(self):
        self.db.close()

    def _run_pipeline(self):
        """Helper to run the full pipeline against the test database."""
        all_events = self.db.get_all_events()
        detections = run_detection(all_events, self.config)
        existing_incidents = self.db.get_all_incidents()
        groups = correlate_detections(detections, all_events, self.config)
        incidents = build_incidents(groups, existing_incidents=existing_incidents)
        incidents = classify_all(incidents, self.config)
        if detections:
            self.db.store_detections(detections)
        if incidents:
            self.db.store_incidents(incidents)
        return incidents

    def test_first_pipeline_run(self):
        """First pipeline run should create incidents with clean sequential IDs and empty AI fields."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        # 5 login failures for alice -> brute_force_login
        events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(events)

        incidents = self._run_pipeline()
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.incident_id == "INC000001"
        assert inc.user == "alice"
        assert inc.ai_status is None
        assert inc.ai_analysis is None
        assert inc.ai_verification is None

    def test_ai_analysis_followed_by_another_pipeline_run(self):
        """Completed AI analysis must be preserved when the pipeline runs again over unchanged evidence."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(events)
        self._run_pipeline()

        # Simulate analyst running local SLM investigation
        inc = self.db.get_incident("INC000001")
        assert inc is not None
        inc.ai_status = "SUCCESS"
        inc.ai_analysis = {"narrative": "Brute-force attack detected against alice", "confidence": 0.95}
        self.db.store_incidents([inc])

        # Run pipeline again
        rerun_incidents = self._run_pipeline()
        assert len(rerun_incidents) == 1
        rerun_inc = self.db.get_incident("INC000001")
        assert rerun_inc.ai_status == "SUCCESS"
        assert rerun_inc.ai_analysis == {"narrative": "Brute-force attack detected against alice", "confidence": 0.95}

    def test_verification_followed_by_another_pipeline_run(self):
        """Completed evidence verification must be preserved on subsequent pipeline runs."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(events)
        self._run_pipeline()

        # Simulate analyst running verification
        inc = self.db.get_incident("INC000001")
        inc.ai_status = "SUCCESS"
        inc.ai_analysis = {"narrative": "Analysis"}
        inc.ai_verification = {
            "status": "VERIFIED",
            "cited_evidence_count": 5,
            "valid_citation_count": 5,
            "rationale": "All 5 cited events verified in SQLite",
        }
        self.db.store_incidents([inc])

        # Re-run pipeline
        self._run_pipeline()
        refreshed = self.db.get_incident("INC000001")
        assert refreshed.ai_verification is not None
        assert refreshed.ai_verification["status"] == "VERIFIED"
        assert refreshed.ai_verification["cited_evidence_count"] == 5

    def test_new_upload_followed_by_pipeline_run(self):
        """New uploads must create new incidents without wiping historical incidents' investigation state."""
        base1 = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        alice_events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base1 + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(alice_events)
        self._run_pipeline()

        # Attach AI analysis to alice's incident
        inc_alice = self.db.get_incident("INC000001")
        inc_alice.ai_status = "SUCCESS"
        inc_alice.ai_analysis = {"summary": "Alice investigation completed"}
        self.db.store_incidents([inc_alice])

        # New upload arrives for bob
        base2 = datetime(2024, 11, 21, 14, 0, 0, tzinfo=timezone.utc)
        bob_events = [
            _make_event(f"E{i:03d}", "bob", "WS-002", base2 + timedelta(minutes=i))
            for i in range(10, 15)
        ]
        self.db.store_events(bob_events)

        # Run pipeline
        incidents = self._run_pipeline()
        assert len(incidents) == 2

        # Alice incident should be preserved intact
        refreshed_alice = self.db.get_incident("INC000001")
        assert refreshed_alice.user == "alice"
        assert refreshed_alice.ai_status == "SUCCESS"
        assert refreshed_alice.ai_analysis == {"summary": "Alice investigation completed"}

        # Bob incident should be created with clean sequential ID and empty AI fields
        bob_inc = next(i for i in incidents if i.user == "bob")
        assert bob_inc.incident_id == "INC000002"
        assert bob_inc.ai_status is None

    def test_changed_evidence_invalidates_old_analysis(self):
        """When an incident's underlying evidence changes, stale AI analysis must be invalidated."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(events)
        self._run_pipeline()

        # Add AI analysis
        inc = self.db.get_incident("INC000001")
        inc.ai_status = "SUCCESS"
        inc.ai_analysis = {"summary": "Old analysis based on 5 events"}
        inc.ai_verification = {"status": "VERIFIED"}
        self.db.store_incidents([inc])

        # New evidence arrives for alice within the correlation window (e.g. privilege escalation)
        new_event = _make_event("E099", "alice", "WS-001", base + timedelta(minutes=6),
                                event_type="privilege_escalation", process="sudo")
        self.db.store_events([new_event])

        # Re-run pipeline
        self._run_pipeline()
        updated_inc = self.db.get_incident("INC000001")
        assert updated_inc is not None
        # Evidence changed: E099 was added
        assert "E099" in updated_inc.evidence_event_ids
        # Stale analysis & verification must be invalidated
        assert updated_inc.ai_status is None
        assert updated_inc.ai_analysis is None
        assert updated_inc.ai_verification is None

    def test_repeated_pipeline_execution_no_duplicates(self):
        """Repeated pipeline execution over the same data must not create duplicate incidents."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(events)

        # Run pipeline 4 times
        for _ in range(4):
            self._run_pipeline()

        all_incs = self.db.get_all_incidents()
        assert len(all_incs) == 1
        assert all_incs[0].incident_id == "INC000001"

    def test_store_incidents_rollback_on_error(self):
        """store_incidents must roll back on database write failure, preserving previous state."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:03d}", "alice", "WS-001", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.store_events(events)
        self._run_pipeline()

        initial_count = self.db.get_incident_count()
        assert initial_count == 1

        # Intentionally cause an error during executemany by passing a malformed incident list
        class BrokenIncident:
            incident_id = "BROKEN"
            title = "Broken"
            severity = MagicMock()
            severity.value = "HIGH"
            status = MagicMock()
            status.value = "OPEN"
            detected_patterns = []
            user = "broken"
            device = "broken"
            start_time = datetime.now(timezone.utc)
            end_time = datetime.now(timezone.utc)
            evidence_event_ids = []
            detection_ids = []
            risk_score = 50.0
            severity_rationale = "test"
            def model_dump_json(self):
                raise RuntimeError("Simulated serialization crash")

        with pytest.raises(RuntimeError):
            self.db.store_incidents([BrokenIncident()])

        # Verify the database rolled back cleanly and still has initial incident
        assert self.db.get_incident_count() == initial_count
        assert self.db.get_incident("INC000001") is not None
