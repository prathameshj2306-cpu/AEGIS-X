"""
Automated test suite for Ingestion Batch Management and Data Isolation in AEGIS-X.

Verifies:
1. Two different uploads create two distinct batch IDs.
2. Ingestion of Batch 2 does not alter or reprocess Batch 1 events.
3. Running pipeline on Batch 2 generates incidents only from Batch 2 events.
4. Historical incidents from Batch 1 remain untouched, with their AI analysis and verification intact.
5. Re-running the pipeline on Batch 2 is idempotent (no duplicates, preserves AI status).
6. Pipeline with batch_id='all' processes all events and retains all incidents correctly.
7. Existing events and incidents before migration are accessible under BATCH-LEGACY.
8. API endpoints GET /api/batches, GET /api/batches/{id}, and GET /api/incidents?batch_id={id} return correct data.
9. Incident models and responses include the correct batch_id.
10. Correlation window (15 minutes) only groups events within the same batch.
11. Reports generated for an incident include the batch_id and source filename.
12. Batch status transitions properly from UPLOADED to INVESTIGATED.
"""

import io
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import AegisConfig
from app.correlation.correlator import build_incidents, correlate_detections
from app.database.store import AegisDatabase
from app.detection.engine import run_detection
from app.main import create_app
from app.reporting.report_builder import build_incident_report
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Incident, IncidentStatus, Severity
from app.severity.classifier import classify_all


def _make_event(
    event_id: str,
    user: str,
    device: str,
    timestamp: datetime,
    event_type: str = "login_failure",
    batch_id: str | None = None,
    process: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user=user,
        device=device,
        ip="192.168.1.50",
        event_type=event_type,
        source=EventSource.AUTHENTICATION if "login" in event_type else EventSource.ENDPOINT,
        process=process,
        batch_id=batch_id,
        raw_data={"test": True},
    )


class TestBatchManagement:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_batches.db")
        self.config = AegisConfig()
        self.db = AegisDatabase(self.db_path)
        self.app = create_app(config=self.config, db_path=self.db_path)
        self.client = TestClient(self.app)

    def teardown_method(self):
        self.db.close()

    def test_two_uploads_create_two_distinct_batches(self):
        """1. Two different uploads create two distinct batch IDs."""
        csv1 = "timestamp,user,device,event_type\n2024-11-20T10:00:00Z,alice,WS-01,login_failure\n"
        csv2 = "timestamp,user,device,event_type\n2024-11-20T10:05:00Z,bob,WS-02,login_failure\n"

        res1 = self.client.post(
            "/api/upload",
            files={"file": ("auth_batch1.csv", io.BytesIO(csv1.encode()), "text/csv")},
            data={"source": "authentication"},
        )
        assert res1.status_code == 200
        batch1_id = res1.json()["batch_id"]
        assert batch1_id.startswith("BATCH-")

        res2 = self.client.post(
            "/api/upload",
            files={"file": ("auth_batch2.csv", io.BytesIO(csv2.encode()), "text/csv")},
            data={"source": "authentication"},
        )
        assert res2.status_code == 200
        batch2_id = res2.json()["batch_id"]
        assert batch2_id.startswith("BATCH-")

        assert batch1_id != batch2_id

    def test_batch_isolation_events_and_no_mixing(self):
        """2. Ingestion of Batch 2 does not alter or reprocess Batch 1 events."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events_b1 = [
            _make_event(f"E00000{i}", "alice", "WS-01", base + timedelta(minutes=i))
            for i in range(1, 4)
        ]
        stored_b1 = self.db.allocate_and_store_events(events_b1, batch_id="BATCH-000001")
        self.db.create_batch("BATCH-000001", "upload_b1.csv", "authentication", len(stored_b1))

        events_b2 = [
            _make_event(f"E00000{i}", "bob", "WS-02", base + timedelta(minutes=i))
            for i in range(4, 7)
        ]
        stored_b2 = self.db.allocate_and_store_events(events_b2, batch_id="BATCH-000002")
        self.db.create_batch("BATCH-000002", "upload_b2.csv", "authentication", len(stored_b2))

        b1_events = self.db.get_events_by_batch("BATCH-000001")
        assert len(b1_events) == 3
        assert all(e.batch_id == "BATCH-000001" for e in b1_events)
        assert all(e.user == "alice" for e in b1_events)

        b2_events = self.db.get_events_by_batch("BATCH-000002")
        assert len(b2_events) == 3
        assert all(e.batch_id == "BATCH-000002" for e in b2_events)
        assert all(e.user == "bob" for e in b2_events)

    def test_pipeline_scoped_to_batch_generates_isolated_incidents(self):
        """3. Running pipeline on Batch 2 generates incidents only from Batch 2 events."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        # Alice 5 login failures -> brute force in Batch 1
        events_b1 = [
            _make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.allocate_and_store_events(events_b1, batch_id="BATCH-000001")
        self.db.create_batch("BATCH-000001", "alice.csv", "authentication", 5)

        # Bob 5 login failures -> brute force in Batch 2
        events_b2 = [
            _make_event(f"E{i:03d}", "bob", "WS-02", base + timedelta(minutes=i))
            for i in range(6, 11)
        ]
        self.db.allocate_and_store_events(events_b2, batch_id="BATCH-000002")
        self.db.create_batch("BATCH-000002", "bob.csv", "authentication", 5)

        # Run pipeline specifically on BATCH-000002
        res = self.client.post("/api/pipeline/run?batch_id=BATCH-000002")
        assert res.status_code == 200
        data = res.json()
        assert data["batch_id"] == "BATCH-000002"
        assert data["incidents_created"] == 1

        # Check incidents in DB for Batch 2
        b2_incidents = self.db.get_incidents_by_batch("BATCH-000002")
        assert len(b2_incidents) == 1
        assert b2_incidents[0].user == "bob"
        assert b2_incidents[0].batch_id == "BATCH-000002"

        # Check that no incidents exist yet for Batch 1
        b1_incidents = self.db.get_incidents_by_batch("BATCH-000001")
        assert len(b1_incidents) == 0

    def test_historical_batch_incidents_remain_untouched(self):
        """4. Historical incidents from Batch 1 remain untouched, with their AI analysis and verification intact."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        # Create and run Batch 1
        events_b1 = [
            _make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.allocate_and_store_events(events_b1, batch_id="BATCH-000001")
        self.db.create_batch("BATCH-000001", "b1.csv", "authentication", 5)
        self.client.post("/api/pipeline/run?batch_id=BATCH-000001")

        # Simulate completed AI analysis & verification on Batch 1 incident
        b1_inc = self.db.get_incidents_by_batch("BATCH-000001")[0]
        b1_inc.ai_status = "SUCCESS"
        b1_inc.ai_analysis = {"summary": "Critical attack on alice", "confidence": 0.98}
        b1_inc.ai_verification = {"status": "VERIFIED", "rationale": "All citations match"}
        self.db.store_incidents([b1_inc], batch_id="BATCH-000001")

        # Upload and run Batch 2
        events_b2 = [
            _make_event(f"E{i:03d}", "bob", "WS-02", base + timedelta(minutes=i))
            for i in range(6, 11)
        ]
        self.db.allocate_and_store_events(events_b2, batch_id="BATCH-000002")
        self.db.create_batch("BATCH-000002", "b2.csv", "authentication", 5)
        self.client.post("/api/pipeline/run?batch_id=BATCH-000002")

        # Verify Batch 1 incident was NOT modified or reset
        reloaded_b1 = self.db.get_incident(b1_inc.incident_id)
        assert reloaded_b1 is not None
        assert reloaded_b1.batch_id == "BATCH-000001"
        assert reloaded_b1.ai_status == "SUCCESS"
        assert reloaded_b1.ai_analysis["summary"] == "Critical attack on alice"
        assert reloaded_b1.ai_verification["status"] == "VERIFIED"

    def test_batch_pipeline_idempotence(self):
        """5. Re-running the pipeline on Batch 2 is idempotent (no duplicates, preserves AI status)."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:03d}", "bob", "WS-02", base + timedelta(minutes=i))
            for i in range(1, 6)
        ]
        self.db.allocate_and_store_events(events, batch_id="BATCH-000002")
        self.db.create_batch("BATCH-000002", "b2.csv", "authentication", 5)

        # First run
        self.client.post("/api/pipeline/run?batch_id=BATCH-000002")
        incidents_run1 = self.db.get_incidents_by_batch("BATCH-000002")
        assert len(incidents_run1) == 1
        inc_id = incidents_run1[0].incident_id

        # Attach AI analysis
        incidents_run1[0].ai_status = "SUCCESS"
        incidents_run1[0].ai_analysis = {"summary": "Analysis on bob"}
        self.db.store_incidents(incidents_run1, batch_id="BATCH-000002")

        # Second run
        self.client.post("/api/pipeline/run?batch_id=BATCH-000002")
        incidents_run2 = self.db.get_incidents_by_batch("BATCH-000002")
        assert len(incidents_run2) == 1
        assert incidents_run2[0].incident_id == inc_id
        assert incidents_run2[0].ai_status == "SUCCESS"
        assert incidents_run2[0].ai_analysis["summary"] == "Analysis on bob"

    def test_pipeline_with_batch_id_all(self):
        """6. Pipeline with batch_id='all' processes all events and retains all incidents correctly."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        ev1 = [_make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i)) for i in range(1, 6)]
        ev2 = [_make_event(f"E{i:03d}", "bob", "WS-02", base + timedelta(minutes=i)) for i in range(6, 11)]

        self.db.allocate_and_store_events(ev1, batch_id="BATCH-000001")
        self.db.create_batch("BATCH-000001", "b1.csv", "authentication", 5)
        self.db.allocate_and_store_events(ev2, batch_id="BATCH-000002")
        self.db.create_batch("BATCH-000002", "b2.csv", "authentication", 5)

        res = self.client.post("/api/pipeline/run?batch_id=all")
        assert res.status_code == 200
        assert res.json()["batch_id"] == "all"
        assert res.json()["events_processed"] == 10
        assert res.json()["incidents_created"] == 2

    def test_legacy_backfill_migration(self):
        """7. Existing events and incidents before migration are accessible under BATCH-LEGACY."""
        legacy_db_path = os.path.join(self.tmpdir, "legacy_schema.db")
        conn = sqlite3.connect(legacy_db_path)
        # Create table WITHOUT batch_id column
        conn.executescript("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user TEXT,
                device TEXT,
                ip TEXT,
                event_type TEXT NOT NULL,
                process TEXT,
                source TEXT NOT NULL,
                raw_data TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                detected_patterns TEXT NOT NULL,
                user TEXT,
                device TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                evidence_event_ids TEXT NOT NULL,
                detection_ids TEXT NOT NULL,
                risk_score REAL,
                severity_rationale TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        ev = _make_event("E000001", "charlie", "WS-03", base)
        conn.execute(
            "INSERT INTO events (event_id, timestamp, user, device, ip, event_type, process, source, raw_data, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("E000001", base.isoformat(), "charlie", "WS-03", "10.0.0.1", "login_failure", None, "authentication", "{}", ev.model_dump_json())
        )
        conn.commit()
        conn.close()

        # Open with AegisDatabase (triggers _apply_migrations)
        migrated_db = AegisDatabase(legacy_db_path)
        batches = migrated_db.get_all_batches()
        assert any(b["batch_id"] == "BATCH-LEGACY" for b in batches)

        event = migrated_db.get_event("E000001")
        assert event is not None
        assert event.batch_id == "BATCH-LEGACY"
        migrated_db.close()

    def test_batch_api_endpoints(self):
        """8. API endpoints GET /api/batches, GET /api/batches/{id}, and GET /api/incidents?batch_id={id} return correct data."""
        self.db.create_batch("BATCH-000001", "test.csv", "authentication", 10, "INVESTIGATED")

        # GET /api/batches
        res_list = self.client.get("/api/batches")
        assert res_list.status_code == 200
        batch_ids = [b["batch_id"] for b in res_list.json()]
        assert "BATCH-000001" in batch_ids

        # GET /api/batches/{id}
        res_single = self.client.get("/api/batches/BATCH-000001")
        assert res_single.status_code == 200
        assert res_single.json()["filename"] == "test.csv"
        assert res_single.json()["event_count"] == 10

        # GET /api/incidents?batch_id=BATCH-000001
        res_inc = self.client.get("/api/incidents?batch_id=BATCH-000001")
        assert res_inc.status_code == 200
        assert isinstance(res_inc.json(), list)

    def test_incident_models_include_batch_id(self):
        """9. Incident models and responses include the correct batch_id."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i)) for i in range(1, 6)]
        self.db.allocate_and_store_events(events, batch_id="BATCH-000005")
        self.db.create_batch("BATCH-000005", "test5.csv", "authentication", 5)

        self.client.post("/api/pipeline/run?batch_id=BATCH-000005")
        res = self.client.get("/api/incidents?batch_id=BATCH-000005")
        assert res.status_code == 200
        incidents = res.json()
        assert len(incidents) == 1
        assert incidents[0]["batch_id"] == "BATCH-000005"

    def test_correlation_window_groups_only_within_batch(self):
        """10. Correlation window (15 minutes) only groups events within the same batch."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        # Same user and device, timestamps 1 minute apart, but different batches
        ev_b1 = [_make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i)) for i in range(1, 6)]
        ev_b2 = [_make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i + 5)) for i in range(6, 11)]

        self.db.allocate_and_store_events(ev_b1, batch_id="BATCH-000001")
        self.db.create_batch("BATCH-000001", "file1.csv", "authentication", 5)
        self.db.allocate_and_store_events(ev_b2, batch_id="BATCH-000002")
        self.db.create_batch("BATCH-000002", "file2.csv", "authentication", 5)

        # Run on BATCH-000001
        self.client.post("/api/pipeline/run?batch_id=BATCH-000001")
        b1_incs = self.db.get_incidents_by_batch("BATCH-000001")
        assert len(b1_incs) == 1
        # Evidence only from B1
        for eid in b1_incs[0].evidence_event_ids:
            ev = self.db.get_event(eid)
            assert ev.batch_id == "BATCH-000001"

    def test_report_includes_batch_metadata(self):
        """11. Reports generated for an incident include the batch_id and source filename."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i)) for i in range(1, 6)]
        self.db.allocate_and_store_events(events, batch_id="BATCH-000009")
        self.db.create_batch("BATCH-000009", "auth_sensitive.csv", "authentication", 5)

        self.client.post("/api/pipeline/run?batch_id=BATCH-000009")
        inc = self.db.get_incidents_by_batch("BATCH-000009")[0]

        report = build_incident_report(inc, db=self.db)
        assert report.header.batch_id == "BATCH-000009"
        assert report.header.source_filename == "auth_sensitive.csv"
        assert report.executive_summary.batch_id == "BATCH-000009"
        assert report.executive_summary.source_filename == "auth_sensitive.csv"

    def test_batch_status_transitions(self):
        """12. Batch status transitions properly from UPLOADED to INVESTIGATED."""
        base = datetime(2024, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(f"E{i:03d}", "alice", "WS-01", base + timedelta(minutes=i)) for i in range(1, 6)]
        self.db.allocate_and_store_events(events, batch_id="BATCH-000010")
        batch = self.db.create_batch("BATCH-000010", "auth.csv", "authentication", 5)
        assert batch["status"] == "UPLOADED"
        assert batch["incident_count"] == 0

        self.client.post("/api/pipeline/run?batch_id=BATCH-000010")
        updated_batch = self.db.get_batch("BATCH-000010")
        assert updated_batch["status"] == "INVESTIGATED"
        assert updated_batch["incident_count"] == 1
