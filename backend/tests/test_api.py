"""
Tests for Phase 4 Checkpoint 1: FastAPI Application Core, CORS, and Health Route.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.config import AegisConfig
from app.database.store import AegisDatabase
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Incident, IncidentStatus, Severity
from app.api.dependencies import get_db, get_ollama_client


@pytest.fixture
def test_db(tmp_path):
    """Provides a fresh SQLite test database with sample records."""
    db_file = str(tmp_path / "api_test.db")
    db = AegisDatabase(db_file)
    ev = NormalizedEvent(
        event_id="EV_API_001",
        timestamp=datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc),
        user="test_analyst",
        device="WS-SOC01",
        event_type="login_success",
        source=EventSource.AUTHENTICATION,
        raw_data={"detail": "API test"},
    )
    inc = Incident(
        incident_id="INC_API_001",
        title="API Test Incident",
        severity=Severity.MEDIUM,
        status=IncidentStatus.OPEN,
        detected_patterns=["brute_force_login"],
        user="test_analyst",
        device="WS-SOC01",
        start_time=datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc),
        end_time=datetime(2024, 11, 20, 10, 15, tzinfo=timezone.utc),
        evidence_event_ids=["EV_API_001"],
        detection_ids=["D001"],
        severity_rationale="Medium severity test rationale",
    )
    db.store_events([ev])
    db.store_incidents([inc])
    db.close()
    return db_file


@pytest.fixture
def app_instance(test_db):
    """Creates a configured FastAPI test app instance."""
    config = AegisConfig()
    app = create_app(config=config, db_path=test_db)
    return app


@pytest.fixture
def client(app_instance):
    """Provides a TestClient for synchronous API requests."""
    with TestClient(app_instance) as c:
        yield c


class TestApiCoreAndHealth:
    """Tests for Core API setup, Health Check endpoint, and CORS policies."""

    def test_health_check_healthy_when_ollama_online(self, app_instance, client, monkeypatch):
        # Mock Ollama health check to True
        class MockOllamaClient:
            async def check_health(self):
                return True

        app_instance.dependency_overrides[get_ollama_client] = lambda: MockOllamaClient()

        response = client.get("/api/health")
        assert response.status_code == 200

        data = response.json()
        assert data["platform"] == "AEGIS-X"
        assert data["status"] == "healthy"
        assert data["database_connected"] is True
        assert data["event_count"] >= 1
        assert data["incident_count"] >= 1
        assert data["ollama_online"] is True
        assert "checked_at" in data

    def test_health_check_degraded_when_ollama_offline(self, app_instance, client, monkeypatch):
        # Mock Ollama health check to False
        class MockOllamaClientOffline:
            async def check_health(self):
                return False

        app_instance.dependency_overrides[get_ollama_client] = lambda: MockOllamaClientOffline()

        response = client.get("/api/health")
        assert response.status_code == 200

        data = response.json()
        assert data["platform"] == "AEGIS-X"
        assert data["status"] == "degraded"
        assert data["database_connected"] is True
        assert data["ollama_online"] is False

    def test_cors_strictly_allows_frontend_origin(self, client):
        # Request with exact authorized frontend origin
        response = client.get(
            "/api/health",
            headers={"Origin": "http://127.0.0.1:5173"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_cors_preflight_options_for_frontend_origin(self, client):
        response = client.options(
            "/api/health",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"

    def test_cors_rejects_unauthorized_origin(self, client):
        # Unauthorized origin must NOT be allowed
        response = client.get(
            "/api/health",
            headers={"Origin": "http://malicious-site.com"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") != "http://malicious-site.com"
        assert "access-control-allow-origin" not in response.headers

    def test_structured_404_error_response(self, client):
        response = client.get("/api/non_existent_endpoint")
        assert response.status_code == 404

        data = response.json()
        assert "error" in data
        assert "detail" in data
        assert data["status_code"] == 404
        assert "timestamp" in data

    def test_openapi_documentation_accessible(self, client):
        response = client.get("/api/openapi.json")
        assert response.status_code == 200
        openapi = response.json()
        assert openapi["info"]["title"].startswith("AEGIS-X")
        assert "/api/health" in openapi["paths"]
        assert "/api/upload" in openapi["paths"]


class TestApiUpload:
    """Tests for Phase 4 Checkpoint 2: Log Ingestion & Upload API."""

    def test_upload_valid_auth_csv(self, client):
        csv_content = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:00:00Z,alice,WS-001,login_success,192.168.1.10\n"
            "2024-11-20T10:05:00Z,bob,WS-002,login_failure,192.168.1.11\n"
        )
        response = client.post(
            "/api/upload",
            files={"file": ("auth_logs.csv", csv_content, "text/csv")},
            data={"source": "authentication"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "auth_logs.csv"
        assert data["source"] == "authentication"
        assert data["event_count"] == 2
        assert data["error_count"] == 0
        assert data["total_events_in_db"] >= 3  # 1 fixture + 2 new

    def test_upload_valid_endpoint_csv_with_explicit_source(self, client):
        csv_content = (
            "timestamp,user,device,event_type,process\n"
            "2024-11-20T10:10:00Z,alice,WS-001,process_start,powershell.exe\n"
        )
        response = client.post(
            "/api/upload",
            files={"file": ("sys_events.csv", csv_content, "text/csv")},
            data={"source": "endpoint"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "sys_events.csv"
        assert data["source"] == "endpoint"
        assert data["event_count"] == 1
        assert data["error_count"] == 0

    def test_upload_valid_json_array(self, client):
        import json
        payload = [
            {
                "timestamp": "2024-11-20T11:00:00Z",
                "user": "charlie",
                "device": "SRV-001",
                "event_type": "login_success",
                "source": "authentication",
            },
            {
                "timestamp": "2024-11-20T11:05:00Z",
                "user": "charlie",
                "device": "SRV-001",
                "event_type": "privilege_escalation",
                "source": "authentication",
            },
        ]
        response = client.post(
            "/api/upload",
            files={"file": ("auth_data.json", json.dumps(payload), "application/json")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "auth_data.json"
        assert data["event_count"] == 2
        assert data["error_count"] == 0

    def test_upload_valid_ndjson(self, client):
        ndjson_content = (
            '{"timestamp": "2024-11-20T12:00:00Z", "user": "dave", "device": "WS-003", "event_type": "process_start", "process": "cmd.exe"}\n'
            '{"timestamp": "2024-11-20T12:01:00Z", "user": "dave", "device": "WS-003", "event_type": "process_stop", "process": "cmd.exe"}\n'
        )
        response = client.post(
            "/api/upload",
            files={"file": ("endpoint_stream.json", ndjson_content, "application/x-ndjson")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source"] == "endpoint"
        assert data["event_count"] == 2

    def test_upload_source_inference_from_filename(self, client):
        # "endpoint" in filename should infer EventSource.ENDPOINT
        csv_content = (
            "timestamp,user,device,event_type\n"
            "2024-11-20T13:00:00Z,eve,WS-009,process_start\n"
        )
        response = client.post(
            "/api/upload",
            files={"file": ("endpoint_telemetry.csv", csv_content, "text/csv")},
        )
        assert response.status_code == 200
        assert response.json()["source"] == "endpoint"

    def test_upload_source_via_query_param(self, client):
        csv_content = (
            "timestamp,user,device,event_type\n"
            "2024-11-20T13:05:00Z,frank,WS-010,login_success\n"
        )
        response = client.post(
            "/api/upload?source=authentication",
            files={"file": ("generic_log.csv", csv_content, "text/csv")},
        )
        assert response.status_code == 200
        assert response.json()["source"] == "authentication"

    def test_upload_rejects_invalid_source_value(self, client):
        csv_content = "timestamp,user,device,event_type\n2024-11-20T13:00:00Z,eve,WS-009,login_success\n"
        response = client.post(
            "/api/upload",
            files={"file": ("auth.csv", csv_content, "text/csv")},
            data={"source": "invalid_source_type"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Invalid log source" in str(data["detail"])

    def test_upload_rejects_unsupported_file_extension(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("malicious.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Unsupported file extension" in str(data["detail"])

    def test_upload_rejects_unsupported_mime_type(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("logs.csv", "timestamp,event_type\n2024-11-20T10:00:00Z,login_success", "image/png")},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Unsupported MIME type" in str(data["detail"])

    def test_upload_rejects_oversized_payload_streaming(self, client):
        # Generate payload larger than 10 MB (e.g. 10.5 MB)
        oversized_data = b"A" * (10 * 1024 * 1024 + 1024)
        response = client.post(
            "/api/upload",
            files={"file": ("huge_log.csv", oversized_data, "text/csv")},
        )
        assert response.status_code == 413
        data = response.json()
        assert data["status_code"] == 413
        assert "exceeded" in str(data["detail"]).lower() or "exceeds" in str(data["detail"]).lower()

    def test_upload_rejects_empty_file(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("empty.csv", b"", "text/csv")},
        )
        assert response.status_code == 400
        data = response.json()
        assert "empty" in str(data["detail"]).lower()

    def test_upload_rejects_whitespace_file(self, client):
        response = client.post(
            "/api/upload",
            files={"file": ("blank.csv", "   \n\n\t  \n", "text/csv")},
        )
        assert response.status_code == 400
        data = response.json()
        assert "whitespace" in str(data["detail"]).lower()

    def test_upload_rejects_non_utf8_binary_content(self, client):
        bad_bytes = b"\xff\xfe\x00\x00\x80\x90"
        response = client.post(
            "/api/upload",
            files={"file": ("corrupt.csv", bad_bytes, "text/csv")},
        )
        assert response.status_code == 400
        data = response.json()
        assert "utf-8" in str(data["detail"]).lower()

    def test_upload_rejects_malformed_csv_no_valid_events(self, client):
        # CSV with columns missing required fields (no timestamp, no event_type)
        bad_csv = "col1,col2,col3\nval1,val2,val3\n"
        response = client.post(
            "/api/upload",
            files={"file": ("auth_unparseable.csv", bad_csv, "text/csv")},
            data={"source": "authentication"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Malformed log file" in str(data["detail"])

    def test_upload_rejects_malformed_json_syntax(self, client):
        bad_json = "{this is not valid json at all!"
        response = client.post(
            "/api/upload",
            files={"file": ("auth_broken.json", bad_json, "application/json")},
            data={"source": "authentication"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Malformed" in str(data["detail"])

    def test_upload_handles_database_failure(self, app_instance, client, monkeypatch):
        class BrokenDb(AegisDatabase):
            def allocate_and_store_events(self, events):
                raise RuntimeError("Simulated SQLite disk write error")

            def store_events(self, events):
                raise RuntimeError("Simulated SQLite disk write error")

        # Override get_db dependency
        def mock_get_db():
            db_path = getattr(app_instance.state, "db_path", ":memory:")
            db = BrokenDb(db_path)
            try:
                yield db
            finally:
                db.close()

        app_instance.dependency_overrides[get_db] = mock_get_db

        csv_content = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:00:00Z,alice,WS-001,login_success,10.0.0.1\n"
        )
        response = client.post(
            "/api/upload",
            files={"file": ("auth_fail.csv", csv_content, "text/csv")},
        )
        assert response.status_code == 500
        data = response.json()
        assert data["status_code"] == 500
        assert "Database failure" in str(data["detail"])

    def test_upload_preserves_monotonic_event_ids(self, test_db, client):
        # Database already has 1 event (EV_API_001)
        csv_batch_1 = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:00:00Z,user1,WS-001,login_success,10.0.0.1\n"
            "2024-11-20T10:01:00Z,user2,WS-002,login_success,10.0.0.2\n"
        )
        r1 = client.post(
            "/api/upload",
            files={"file": ("batch1.csv", csv_batch_1, "text/csv")},
            data={"source": "authentication"},
        )
        assert r1.status_code == 200

        csv_batch_2 = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:02:00Z,user3,WS-003,login_success,10.0.0.3\n"
        )
        r2 = client.post(
            "/api/upload",
            files={"file": ("batch2.csv", csv_batch_2, "text/csv")},
            data={"source": "authentication"},
        )
        assert r2.status_code == 200

        # Verify database contents directly
        db = AegisDatabase(test_db)
        all_events = db.get_all_events()
        event_ids = [e.event_id for e in all_events]
        db.close()

        # Should have fixture event + 2 from batch1 + 1 from batch2 = 4 total
        assert len(all_events) == 4
        # Assert each ID is distinct and sequential
        assert len(set(event_ids)) == 4
        assert "E000001" in event_ids
        assert "E000002" in event_ids
        assert "E000003" in event_ids

    def test_oversized_request_with_content_length(self, client):
        # Early rejection by ASGI middleware via Content-Length header
        headers = {
            "content-length": str(10 * 1024 * 1024 + 500),
            "content-type": "multipart/form-data; boundary=testboundary",
        }
        response = client.post("/api/upload", headers=headers, content=b"fake")
        assert response.status_code == 413
        data = response.json()
        assert data["status_code"] == 413
        assert "Payload Too Large" in data["error"]

    def test_oversized_request_without_content_length(self, client):
        # Streamed chunks exceeding limit dynamically via ASGI middleware wrapped receive
        boundary = "----TestBoundaryStream123"

        def generator():
            # Send multipart preamble
            yield f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"huge.csv\"\r\nContent-Type: text/csv\r\n\r\n".encode("utf-8")
            # Send 11 chunks of 1 MB each = 11 MB > 10 MB limit
            for _ in range(11):
                yield b"X" * (1024 * 1024)
            yield f"\r\n--{boundary}--\r\n".encode("utf-8")

        response = client.post(
            "/api/upload",
            content=generator(),
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
        )
        assert response.status_code == 413
        data = response.json()
        assert data["status_code"] == 413
        assert "Payload Too Large" in data["error"]

    def test_chunked_streamed_request_bodies_within_limit(self, client):
        # Streaming valid chunks within limit
        csv_data = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:00:00Z,stream_user,WS-01,login_success,10.0.0.1\n"
        )
        response = client.post(
            "/api/upload",
            files={"file": ("streamed.csv", csv_data, "text/csv")},
            data={"source": "authentication"},
        )
        assert response.status_code == 200
        assert response.json()["event_count"] == 1

    def test_concurrent_uploads_generate_unique_event_ids(self, test_db, app_instance):
        import concurrent.futures

        def post_upload(worker_id):
            client = TestClient(app_instance)
            csv_content = (
                "timestamp,user,device,event_type,ip\n"
                f"2024-11-20T10:{worker_id:02d}:00Z,worker_{worker_id},WS-01,login_success,10.0.0.{worker_id}\n"
                f"2024-11-20T10:{worker_id:02d}:30Z,worker_{worker_id},WS-01,login_success,10.0.0.{worker_id}\n"
            )
            res = client.post(
                "/api/upload",
                files={"file": (f"worker_{worker_id}.csv", csv_content, "text/csv")},
                data={"source": "authentication"},
            )
            return res.status_code, res.json()

        # Run 8 concurrent uploads in parallel threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(post_upload, i) for i in range(1, 9)]
            results = [f.result() for f in futures]

        for status_code, body in results:
            assert status_code == 200
            assert body["event_count"] == 2

        # Verify database has strictly unique sequential IDs without collisions
        db = AegisDatabase(test_db)
        events = db.get_all_events()
        numeric_ids = [e.event_id for e in events if e.event_id.startswith("E") and e.event_id[1:].isdigit()]
        db.close()

        # 16 events added + any prior E-events
        assert len(numeric_ids) == 16
        assert len(set(numeric_ids)) == 16  # Strictly unique!

    def test_event_id_generation_after_record_deletion_or_gaps(self, test_db, client):
        db = AegisDatabase(test_db)
        # Store events E000010 through E000012 manually to create a gap
        ev1 = NormalizedEvent(
            event_id="E000010",
            timestamp=datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc),
            user="user10",
            device="WS-10",
            event_type="login_success",
            source=EventSource.AUTHENTICATION,
            raw_data={},
        )
        ev2 = NormalizedEvent(
            event_id="E000012",
            timestamp=datetime(2024, 11, 20, 10, 1, tzinfo=timezone.utc),
            user="user12",
            device="WS-12",
            event_type="login_success",
            source=EventSource.AUTHENTICATION,
            raw_data={},
        )
        db.store_events([ev1, ev2])
        db.close()

        # Now upload a new record
        csv_data = "timestamp,user,device,event_type,ip\n2024-11-20T10:02:00Z,new_user,WS-01,login_success,10.0.0.1\n"
        res = client.post(
            "/api/upload",
            files={"file": ("gap_test.csv", csv_data, "text/csv")},
            data={"source": "authentication"},
        )
        assert res.status_code == 200

        db = AegisDatabase(test_db)
        all_eids = [e.event_id for e in db.get_all_events()]
        db.close()

        # The new event must be E000013 (max 12 + 1), not based on row count!
        assert "E000013" in all_eids

    def test_database_insertion_failure_and_rollback(self, test_db, app_instance, client):
        # Test that failed allocate_and_store_events rolls back cleanly
        db = AegisDatabase(test_db)
        initial_count = db.get_event_count()
        db.close()

        class FaultyDb(AegisDatabase):
            def allocate_and_store_events(self, events):
                # Simulate partial insertion failure before commit
                with self._write_lock:
                    self.conn.execute("BEGIN IMMEDIATE")
                    self.conn.execute(
                        "INSERT INTO events (event_id, timestamp, event_type, source, raw_data, data_json, created_at) "
                        "VALUES ('E999999', '2024-11-20', 'login', 'authentication', '{}', '{}', '2024-11-20')"
                    )
                    # Trigger error to force rollback
                    self.conn.rollback()
                    raise RuntimeError("Simulated mid-transaction failure")

        app_instance.dependency_overrides[get_db] = lambda: FaultyDb(test_db)

        csv_data = "timestamp,user,device,event_type,ip\n2024-11-20T10:00:00Z,u,d,login_success,1.1.1.1\n"
        res = client.post(
            "/api/upload",
            files={"file": ("rollback_test.csv", csv_data, "text/csv")},
            data={"source": "authentication"},
        )
        assert res.status_code == 500

        # Ensure E999999 was rolled back and event count is unchanged
        db = AegisDatabase(test_db)
        assert db.get_event_count() == initial_count
        assert db.get_event("E999999") is None
        db.close()

    def test_endpoint_source_inferred_from_content(self, client):
        # File has neutral name 'telemetry_data.csv' but contains process & process_start
        csv_data = (
            "timestamp,user,device,event_type,process\n"
            "2024-11-20T10:00:00Z,analyst,WS-01,process_start,powershell.exe\n"
        )
        res = client.post(
            "/api/upload",
            files={"file": ("telemetry_data.csv", csv_data, "text/csv")},
        )
        assert res.status_code == 200
        assert res.json()["source"] == "endpoint"

    def test_authentication_source_inferred_from_content(self, client):
        # File has neutral name 'activity.csv' but contains ip & login_success
        csv_data = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:00:00Z,analyst,WS-01,login_success,192.168.1.100\n"
        )
        res = client.post(
            "/api/upload",
            files={"file": ("activity.csv", csv_data, "text/csv")},
        )
        assert res.status_code == 200
        assert res.json()["source"] == "authentication"

    def test_ambiguous_source_rejected(self, client):
        # File has neutral name and neutral event type with no source indicators
        csv_data = (
            "timestamp,device,event_type\n"
            "2024-11-20T10:00:00Z,WS-01,other\n"
        )
        res = client.post(
            "/api/upload",
            files={"file": ("unlabeled_generic.csv", csv_data, "text/csv")},
        )
        assert res.status_code == 400
        data = res.json()
        assert "Ambiguous log source" in str(data["detail"])

    def test_explicit_source_overriding_inference(self, client):
        # File content looks like endpoint (has process), but user explicitly forces source=authentication
        csv_data = (
            "timestamp,user,device,event_type,process\n"
            "2024-11-20T10:00:00Z,analyst,WS-01,process_start,powershell.exe\n"
        )
        res = client.post(
            "/api/upload",
            files={"file": ("telemetry.csv", csv_data, "text/csv")},
            data={"source": "authentication"},
        )
        assert res.status_code == 200
        assert res.json()["source"] == "authentication"


class TestApiPipelineAndIncidents:
    """Tests for Pipeline Execution, Incident Listing, Detail, and AI Analysis Routes."""

    def test_pipeline_run_with_stored_events(self, client):
        # Upload multiple failed logins followed by privilege escalation
        csv_auth = (
            "timestamp,user,device,event_type,ip\n"
            "2024-11-20T10:00:00Z,attacker,WS-99,login_failure,192.168.1.50\n"
            "2024-11-20T10:01:00Z,attacker,WS-99,login_failure,192.168.1.50\n"
            "2024-11-20T10:02:00Z,attacker,WS-99,login_failure,192.168.1.50\n"
            "2024-11-20T10:03:00Z,attacker,WS-99,login_failure,192.168.1.50\n"
            "2024-11-20T10:04:00Z,attacker,WS-99,login_failure,192.168.1.50\n"
        )
        u_res = client.post(
            "/api/upload",
            files={"file": ("auth_attack.csv", csv_auth, "text/csv")},
            data={"source": "authentication"},
        )
        assert u_res.status_code == 200

        # Execute pipeline
        p_res = client.post("/api/pipeline/run")
        assert p_res.status_code == 200
        p_data = p_res.json()
        assert p_data["status"] == "success"
        assert p_data["events_processed"] >= 5
        assert p_data["detections_found"] >= 1
        assert p_data["incidents_created"] >= 1

    def test_list_incidents_with_filtering(self, client):
        res = client.get("/api/incidents")
        assert res.status_code == 200
        incidents = res.json()
        assert isinstance(incidents, list)
        assert len(incidents) >= 1

        # Test filtering by existing severity (e.g. MEDIUM from fixture)
        res_med = client.get("/api/incidents?severity=MEDIUM")
        assert res_med.status_code == 200
        for inc in res_med.json():
            assert inc["severity"] == "MEDIUM"

        # Test filtering by non-existent user
        res_none = client.get("/api/incidents?user=non_existent_ghost_user")
        assert res_none.status_code == 200
        assert len(res_none.json()) == 0

    def test_get_incident_detail_found_and_not_found(self, client):
        # Found (fixture incident INC_API_001)
        res = client.get("/api/incidents/INC_API_001")
        assert res.status_code == 200
        data = res.json()
        assert data["incident"]["incident_id"] == "INC_API_001"
        assert "evidence_events" in data
        assert "detections" in data

        # Not found
        res_404 = client.get("/api/incidents/INC_DOES_NOT_EXIST")
        assert res_404.status_code == 404
        assert res_404.json()["status_code"] == 404

    def test_analyze_incident_with_fallback_and_verification(self, client):
        # Analyze INC_API_001 (Ollama offline -> triggers deterministic fallback + verifier)
        res = client.post("/api/incidents/INC_API_001/analyze")
        assert res.status_code == 200
        data = res.json()
        assert data["incident_id"] == "INC_API_001"
        assert data["ai_status"] in ("SUCCESS", "FALLBACK", "UNAVAILABLE")
        assert "ai_analysis" in data
        assert "summary" in data["ai_analysis"]
        assert "verification_status" in data
        assert data["verification_status"] in ("VERIFIED", "PARTIAL", "UNVERIFIED")
        assert "ai_verification" in data


class TestApiReports:
    """Tests for Report Generation and Download Endpoints."""

    def test_generate_and_download_report(self, client):
        # Generate both formats for INC_API_001
        gen_res = client.post("/api/incidents/INC_API_001/report?format=both&sidecar=true")
        assert gen_res.status_code == 200
        gen_data = gen_res.json()
        assert gen_data["incident_id"] == "INC_API_001"
        assert "html" in gen_data["generated_files"]
        assert "json" in gen_data["generated_files"]

        html_fn = gen_data["generated_files"]["html"]
        json_fn = gen_data["generated_files"]["json"]

        # Download HTML
        dl_html = client.get(f"/api/reports/{html_fn}")
        assert dl_html.status_code == 200
        assert "text/html" in dl_html.headers.get("content-type", "")
        assert "AEGIS-X" in dl_html.text

        # Download JSON
        dl_json = client.get(f"/api/reports/{json_fn}")
        assert dl_json.status_code == 200
        assert "application/json" in dl_json.headers.get("content-type", "")

    def test_report_security_blocks_path_traversal(self, client):
        # Path traversal attack
        res_dotdot = client.get("/api/reports/..%2f..%2faegis.db")
        assert res_dotdot.status_code in (400, 404)

        # Unsupported extension
        res_ext = client.get("/api/reports/malicious.sh")
        assert res_ext.status_code in (400, 404)

        # Missing report file
        res_missing = client.get("/api/reports/non_existent_report_file.html")
        assert res_missing.status_code == 404
