"""
Unit tests for the ingestion module.

Tests cover:
- CSV ingestion with standard and alternative column names.
- JSON ingestion (array and single object).
- Timestamp normalization to UTC.
- Event type normalization and mapping.
- Validation error handling (missing fields, bad timestamps).
- File size limit enforcement.
- Stable event ID generation.
"""

import os
import sys
import tempfile

import pytest

# Ensure backend/app is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ingestion.ingestor import (
    ingest_csv,
    ingest_json,
    ingest_records,
    _parse_timestamp,
    _normalize_event_type,
    _map_columns,
)
from app.schemas.events import EventSource


class TestTimestampParsing:
    def test_iso8601_with_timezone(self):
        dt = _parse_timestamp("2024-11-18T10:30:00+05:30")
        assert dt is not None
        assert dt.tzinfo is not None
        # 10:30 IST = 05:00 UTC
        assert dt.hour == 5

    def test_iso8601_no_timezone(self):
        dt = _parse_timestamp("2024-11-18T10:30:00")
        assert dt is not None
        assert dt.hour == 10  # Treated as UTC

    def test_datetime_with_space(self):
        dt = _parse_timestamp("2024-11-18 14:00:00")
        assert dt is not None
        assert dt.hour == 14

    def test_invalid_timestamp(self):
        assert _parse_timestamp("not-a-date") is None
        assert _parse_timestamp("") is None
        assert _parse_timestamp(None) is None


class TestEventTypeNormalization:
    def test_standard_types(self):
        assert _normalize_event_type("login_success") == "login_success"
        assert _normalize_event_type("login_failure") == "login_failure"

    def test_alternative_names(self):
        assert _normalize_event_type("logon_failure") == "login_failure"
        assert _normalize_event_type("failed_login") == "login_failure"
        assert _normalize_event_type("authentication_success") == "login_success"
        assert _normalize_event_type("priv_esc") == "privilege_escalation"

    def test_case_insensitive(self):
        assert _normalize_event_type("LOGIN_SUCCESS") == "login_success"
        assert _normalize_event_type("Login_Failure") == "login_failure"

    def test_unknown_type(self):
        assert _normalize_event_type("custom_event") == "other"

    def test_empty_type(self):
        assert _normalize_event_type("") is None
        assert _normalize_event_type(None) is None


class TestColumnMapping:
    def test_standard_columns(self):
        raw = {"timestamp": "v1", "user": "v2", "event_type": "v3"}
        mapped = _map_columns(raw)
        assert mapped["timestamp"] == "v1"
        assert mapped["user"] == "v2"
        assert mapped["event_type"] == "v3"

    def test_alternative_columns(self):
        raw = {"datetime": "v1", "username": "v2", "action": "v3", "hostname": "v4"}
        mapped = _map_columns(raw)
        assert mapped["timestamp"] == "v1"
        assert mapped["user"] == "v2"
        assert mapped["event_type"] == "v3"
        assert mapped["device"] == "v4"

    def test_case_insensitive_columns(self):
        raw = {"TIMESTAMP": "v1", "UserName": "v2"}
        mapped = _map_columns(raw)
        assert mapped["timestamp"] == "v1"
        assert mapped["user"] == "v2"


class TestCSVIngestion:
    def test_basic_csv(self):
        csv_data = """timestamp,user,device,ip,event_type,source
2024-11-18T10:00:00Z,alice,WS-001,192.168.1.10,login_success,authentication
2024-11-18T10:05:00Z,bob,WS-002,192.168.1.11,login_failure,authentication"""

        result = ingest_csv(csv_content=csv_data)
        assert result.success_count == 2
        assert result.error_count == 0
        assert result.events[0].event_id == "E000001"
        assert result.events[0].user == "alice"
        assert result.events[0].event_type == "login_success"
        assert result.events[1].event_id == "E000002"
        assert result.events[1].event_type == "login_failure"

    def test_alternative_column_names(self):
        csv_data = """datetime,username,hostname,ip_address,action,log_source
2024-11-18T10:00:00Z,alice,WS-001,192.168.1.10,logon_failure,auth"""

        result = ingest_csv(csv_content=csv_data)
        assert result.success_count == 1
        assert result.events[0].user == "alice"
        assert result.events[0].device == "WS-001"
        assert result.events[0].event_type == "login_failure"
        assert result.events[0].source == EventSource.AUTHENTICATION

    def test_missing_timestamp_error(self):
        csv_data = """user,event_type,source
alice,login_success,authentication"""

        result = ingest_csv(csv_content=csv_data)
        assert result.success_count == 0
        assert result.error_count == 1
        assert "timestamp" in result.errors[0].field

    def test_missing_event_type_error(self):
        csv_data = """timestamp,user,source
2024-11-18T10:00:00Z,alice,authentication"""

        result = ingest_csv(csv_content=csv_data)
        assert result.success_count == 0
        assert result.error_count == 1
        assert "event_type" in result.errors[0].field

    def test_empty_csv(self):
        result = ingest_csv(csv_content="")
        assert result.success_count == 0
        assert result.error_count == 1

    def test_file_size_limit(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                          delete=False, encoding="utf-8") as f:
            f.write("timestamp,user,event_type\n")
            # Write enough to exceed a tiny limit
            for i in range(100):
                f.write(f"2024-11-18T10:00:00Z,user{i},login_success\n")
            path = f.name

        try:
            result = ingest_csv(file_path=path, max_size_bytes=100)
            assert result.success_count == 0
            assert result.error_count == 1
            assert "size" in result.errors[0].message.lower()
        finally:
            os.unlink(path)

    def test_raw_data_preserved(self):
        csv_data = """timestamp,user,event_type,source,custom_field
2024-11-18T10:00:00Z,alice,login_success,auth,some_value"""

        result = ingest_csv(csv_content=csv_data)
        assert result.success_count == 1
        # raw_data should contain the original row data
        assert result.events[0].raw_data.get("custom_field") == "some_value"


class TestJSONIngestion:
    def test_json_array(self):
        json_data = """[
            {"timestamp": "2024-11-18T10:00:00Z", "user": "alice",
             "event_type": "login_success", "source": "authentication"},
            {"timestamp": "2024-11-18T10:05:00Z", "user": "bob",
             "event_type": "login_failure", "source": "authentication"}
        ]"""

        result = ingest_json(json_content=json_data)
        assert result.success_count == 2
        assert result.events[0].user == "alice"

    def test_single_json_object(self):
        json_data = """{"timestamp": "2024-11-18T10:00:00Z", "user": "alice",
                        "event_type": "login_success", "source": "auth"}"""

        result = ingest_json(json_content=json_data)
        assert result.success_count == 1

    def test_malformed_json(self):
        result = ingest_json(json_content="{bad json")
        assert result.success_count == 0
        assert result.error_count == 1

    def test_empty_json(self):
        result = ingest_json(json_content="")
        assert result.success_count == 0


class TestIngestionResult:
    def test_summary(self):
        csv_data = """timestamp,user,event_type,source
2024-11-18T10:00:00Z,alice,login_success,auth
bad_timestamp,bob,login_failure,auth"""

        result = ingest_csv(csv_content=csv_data)
        summary = result.summary()
        assert summary["source_file"] == "<csv_content>"
        assert summary["total_rows"] == 2
        assert summary["successfully_ingested"] == 1
        assert summary["validation_errors"] == 1
