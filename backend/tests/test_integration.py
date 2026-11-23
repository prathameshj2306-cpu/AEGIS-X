"""
Integration test: full pipeline from synthetic data → incidents.

This test runs the complete Phase 1 pipeline and validates:
1. Data generation works.
2. Ingestion produces valid events.
3. Detection fires expected rules.
4. Correlation groups detections correctly.
5. Severity is assigned deterministically.
6. SQLite persistence stores and retrieves data.
7. Benign scenarios don't trigger false positives.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import AegisConfig, AuthorizedSchedule
from app.ingestion.ingestor import ingest_csv
from app.detection.engine import run_detection
from app.correlation.correlator import correlate_detections, build_incidents
from app.severity.classifier import classify_all
from app.simulator.generator import generate_dataset
from app.database.store import AegisDatabase
from app.schemas.events import EventSource
from app.schemas.incidents import Severity


class TestFullPipeline:
    def setup_method(self):
        """Generate a dataset and run the full pipeline."""
        self.tmpdir = tempfile.mkdtemp()
        self.data_dir = os.path.join(self.tmpdir, "test_data")
        self.db_path = os.path.join(self.tmpdir, "test.db")

        # Generate data with known seed
        self.summary = generate_dataset(
            seed=42, output_dir=self.data_dir, dataset_name="test"
        )

        # Config with authorized admin schedule
        self.config = AegisConfig()
        self.config.authorized_schedules.append(AuthorizedSchedule(
            user="admin",
            days=["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
            start="00:00",
            end="23:59",
            timezone="UTC",
        ))

    def test_data_generation(self):
        """Verify that the generator creates the expected files."""
        assert os.path.exists(os.path.join(self.data_dir, "auth_events.csv"))
        assert os.path.exists(os.path.join(self.data_dir, "endpoint_events.csv"))
        assert os.path.exists(os.path.join(self.data_dir, "scenarios.json"))
        assert self.summary["total_events"] > 0
        assert self.summary["malicious_scenarios"] == 5
        assert self.summary["benign_scenarios"] == 5

    def test_ingestion_succeeds(self):
        """Verify that generated data can be ingested without errors."""
        auth_result = ingest_csv(
            os.path.join(self.data_dir, "auth_events.csv"),
            default_source=EventSource.AUTHENTICATION,
        )
        assert auth_result.success_count > 0
        assert auth_result.error_count == 0

        ep_result = ingest_csv(
            os.path.join(self.data_dir, "endpoint_events.csv"),
            default_source=EventSource.ENDPOINT,
            id_offset=auth_result.success_count + 1,
        )
        assert ep_result.success_count > 0
        assert ep_result.error_count == 0

    def test_detection_finds_expected_patterns(self):
        """Detection engine should find brute-force, priv esc, and suspicious processes."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)

        rule_names = {d.rule_name for d in detections}
        # We expect at least these rules to fire (from malicious scenarios)
        assert "brute_force_login" in rule_names, "Should detect brute force"
        assert "privilege_escalation" in rule_names, "Should detect priv esc"
        assert "suspicious_process" in rule_names, "Should detect suspicious process"

    def test_brute_force_threshold_respected(self):
        """Brute-force should NOT fire for the benign 2-failure scenario."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)

        bf_detections = [d for d in detections if d.rule_name == "brute_force_login"]
        # Check that no brute-force detection has fewer than 5 event IDs
        for d in bf_detections:
            assert len(d.event_ids) >= 5, (
                f"Brute-force detection {d.detection_id} has only "
                f"{len(d.event_ids)} events (threshold is 5)"
            )

    def test_authorized_admin_not_flagged(self):
        """Admin with authorized schedule logging at 02:00 should NOT be flagged."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)

        # Check that no unusual_login_time detection targets "admin"
        for d in detections:
            if d.rule_name == "unusual_login_time" and d.user == "admin":
                pytest.fail(
                    f"Admin was flagged for unusual login time despite having "
                    f"an authorized schedule: {d.explanation}"
                )

    def test_correlation_produces_incidents(self):
        """Correlation should produce at least one incident."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)
        groups = correlate_detections(detections, all_events, self.config)
        incidents = build_incidents(groups)

        assert len(incidents) > 0

    def test_severity_classification(self):
        """At least one HIGH or CRITICAL incident expected from multi-stage attack."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)
        groups = correlate_detections(detections, all_events, self.config)
        incidents = build_incidents(groups)
        incidents = classify_all(incidents, self.config)

        severities = {inc.severity for inc in incidents}
        # Multi-stage attack should produce CRITICAL or at least HIGH
        assert Severity.HIGH in severities or Severity.CRITICAL in severities, (
            f"Expected at least HIGH severity from multi-stage attack. Got: {severities}"
        )

        # Every incident should have a rationale
        for inc in incidents:
            assert len(inc.severity_rationale) > 10

    def test_sqlite_persistence(self):
        """Verify that data can be stored and retrieved from SQLite."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)
        groups = correlate_detections(detections, all_events, self.config)
        incidents = build_incidents(groups)
        incidents = classify_all(incidents, self.config)

        db = AegisDatabase(self.db_path)
        try:
            db.store_events(all_events)
            db.store_detections(detections)
            db.store_incidents(incidents)

            assert db.get_event_count() == len(all_events)
            assert db.get_incident_count() == len(incidents)

            # Retrieve and verify
            stored_incidents = db.get_all_incidents()
            assert len(stored_incidents) == len(incidents)

            # Check a specific event can be retrieved
            event = db.get_event(all_events[0].event_id)
            assert event is not None
            assert event.event_id == all_events[0].event_id
        finally:
            db.close()

    def test_normal_powershell_not_flagged(self):
        """Benign PowerShell (Get-Process) should NOT be flagged as suspicious."""
        all_events = self._ingest_all()
        detections = run_detection(all_events, self.config)

        for d in detections:
            if d.rule_name == "suspicious_process":
                process = d.metadata.get("process", "")
                assert "Get-Process" not in process, (
                    f"Normal PowerShell was flagged as suspicious: {process}"
                )
                assert "Get-Service" not in process, (
                    f"Normal PowerShell was flagged as suspicious: {process}"
                )

    def _ingest_all(self):
        """Helper: ingest both auth and endpoint CSV files."""
        auth_result = ingest_csv(
            os.path.join(self.data_dir, "auth_events.csv"),
            default_source=EventSource.AUTHENTICATION,
        )
        ep_result = ingest_csv(
            os.path.join(self.data_dir, "endpoint_events.csv"),
            default_source=EventSource.ENDPOINT,
            id_offset=auth_result.success_count + 1,
        )
        return auth_result.events + ep_result.events


class TestDatasetSeparation:
    """Verify that development and evaluation datasets are independent."""

    def test_different_seeds_produce_different_data(self):
        tmpdir = tempfile.mkdtemp()
        dev_dir = os.path.join(tmpdir, "dev")
        eval_dir = os.path.join(tmpdir, "eval")

        generate_dataset(seed=42, output_dir=dev_dir, dataset_name="dev")
        generate_dataset(seed=7777, output_dir=eval_dir, dataset_name="eval")

        # Both should produce data
        dev_auth = os.path.join(dev_dir, "auth_events.csv")
        eval_auth = os.path.join(eval_dir, "auth_events.csv")

        assert os.path.exists(dev_auth)
        assert os.path.exists(eval_auth)

        # They should differ (different seeds → different events)
        with open(dev_auth, "r") as f:
            dev_content = f.read()
        with open(eval_auth, "r") as f:
            eval_content = f.read()

        # At minimum, the data should not be byte-identical
        assert dev_content != eval_content, (
            "Development and evaluation datasets should differ (different seeds)"
        )
