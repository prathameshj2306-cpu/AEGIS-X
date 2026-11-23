"""
Log ingestion module for AEGIS-X.

Responsibilities:
1. Accept CSV or JSON files (as file paths or raw data).
2. Map alternative column names to the normalized schema.
3. Validate every record: required fields, timestamp parsing, event type normalization.
4. Assign stable event IDs (E000001, E000002, ...).
5. Normalize timestamps to UTC.
6. Return a list of NormalizedEvent objects and a list of validation errors.

Security considerations:
- Input is treated as untrusted data.
- No code execution from input fields.
- File size limits enforced before parsing.
- Malformed records produce clear validation errors, not crashes.
"""

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any

from app.schemas.events import (
    EVENT_TYPE_MAPPINGS,
    EventSource,
    NormalizedEvent,
)


# --- Column name mappings ---
# Maps common alternative column names to our normalized field names.
# All keys are lowercase for case-insensitive matching.

COLUMN_MAPPINGS: dict[str, str] = {
    # event_id
    "event_id": "event_id",
    "eventid": "event_id",
    "id": "event_id",
    "log_id": "event_id",

    # timestamp
    "timestamp": "timestamp",
    "time": "timestamp",
    "datetime": "timestamp",
    "date_time": "timestamp",
    "event_time": "timestamp",
    "event_timestamp": "timestamp",
    "logged_at": "timestamp",
    "created_at": "timestamp",

    # user
    "user": "user",
    "username": "user",
    "user_name": "user",
    "userid": "user",
    "user_id": "user",
    "account": "user",
    "account_name": "user",
    "subject": "user",

    # device
    "device": "device",
    "hostname": "device",
    "host": "device",
    "device_name": "device",
    "computer": "device",
    "computer_name": "device",
    "machine": "device",
    "workstation": "device",

    # ip
    "ip": "ip",
    "ip_address": "ip",
    "ipaddress": "ip",
    "source_ip": "ip",
    "src_ip": "ip",
    "client_ip": "ip",
    "remote_ip": "ip",

    # event_type
    "event_type": "event_type",
    "eventtype": "event_type",
    "type": "event_type",
    "action": "event_type",
    "event_action": "event_type",
    "activity": "event_type",
    "category": "event_type",

    # process
    "process": "process",
    "process_name": "process",
    "processname": "process",
    "command": "process",
    "command_line": "process",
    "commandline": "process",
    "executable": "process",
    "exe": "process",
    "program": "process",

    # source
    "source": "source",
    "log_source": "source",
    "data_source": "source",
    "origin": "source",
}

# Maps raw source values to EventSource
SOURCE_MAPPINGS: dict[str, EventSource] = {
    "authentication": EventSource.AUTHENTICATION,
    "auth": EventSource.AUTHENTICATION,
    "login": EventSource.AUTHENTICATION,
    "logon": EventSource.AUTHENTICATION,
    "endpoint": EventSource.ENDPOINT,
    "host": EventSource.ENDPOINT,
    "edr": EventSource.ENDPOINT,
    "process": EventSource.ENDPOINT,
    "sysmon": EventSource.ENDPOINT,
}

# Maximum file size in bytes (default 10 MB)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024


class IngestionError:
    """Represents a validation error during ingestion."""

    def __init__(self, row_index: int, field: str, message: str,
                 raw_data: dict | None = None):
        self.row_index = row_index
        self.field = field
        self.message = message
        self.raw_data = raw_data or {}

    def __repr__(self) -> str:
        return f"IngestionError(row={self.row_index}, field='{self.field}', msg='{self.message}')"

    def to_dict(self) -> dict:
        return {
            "row_index": self.row_index,
            "field": self.field,
            "message": self.message,
        }


class IngestionResult:
    """Result of ingesting a file: events + errors."""

    def __init__(
        self,
        events: list[NormalizedEvent],
        errors: list[IngestionError],
        total_rows: int,
        source_file: str = "",
    ):
        self.events = events
        self.errors = errors
        self.total_rows = total_rows
        self.source_file = source_file

    @property
    def success_count(self) -> int:
        return len(self.events)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    def summary(self) -> dict:
        return {
            "source_file": self.source_file,
            "total_rows": self.total_rows,
            "successfully_ingested": self.success_count,
            "validation_errors": self.error_count,
            "error_details": [e.to_dict() for e in self.errors[:20]],  # Cap at 20
        }


def _map_columns(raw_record: dict[str, Any]) -> dict[str, Any]:
    """Map raw column names to normalized field names.

    Uses case-insensitive matching against COLUMN_MAPPINGS.
    Unknown columns are preserved in the mapping under their original name.
    """
    mapped: dict[str, Any] = {}
    for raw_key, value in raw_record.items():
        normalized_key = COLUMN_MAPPINGS.get(raw_key.strip().lower(), None)
        if normalized_key:
            # First mapping wins (don't overwrite if already set)
            if normalized_key not in mapped:
                mapped[normalized_key] = value
        # Always keep original data accessible
    return mapped


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp string into a UTC datetime.

    Supports ISO 8601 and several common formats.
    Returns None if parsing fails.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip()

    # Try ISO 8601 first (most common)
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def _normalize_event_type(raw_type: Any) -> str | None:
    """Normalize a raw event type string to our controlled vocabulary.

    Returns the normalized type, or "other" if the input is a valid string
    but doesn't match any known mapping. Returns None only for empty/missing input.
    """
    if not raw_type or not isinstance(raw_type, str):
        return None

    cleaned = raw_type.strip().lower().replace(" ", "_").replace("-", "_")
    return EVENT_TYPE_MAPPINGS.get(cleaned, "other")


def _normalize_source(raw_source: Any, default: EventSource) -> EventSource:
    """Normalize a raw source string to EventSource enum."""
    if not raw_source or not isinstance(raw_source, str):
        return default

    cleaned = raw_source.strip().lower()
    return SOURCE_MAPPINGS.get(cleaned, default)


def _make_event_id(index: int) -> str:
    """Generate a stable event ID like E000001."""
    return f"E{index:06d}"


def ingest_records(
    records: list[dict[str, Any]],
    default_source: EventSource = EventSource.AUTHENTICATION,
    id_offset: int = 1,
    source_file: str = "",
) -> IngestionResult:
    """Ingest a list of raw records (dicts) into normalized events.

    Args:
        records: List of raw log records as dictionaries.
        default_source: Default EventSource when not specified in the record.
        id_offset: Starting number for event ID generation.
        source_file: Name of the source file for reporting.

    Returns:
        IngestionResult with valid events and validation errors.
    """
    events: list[NormalizedEvent] = []
    errors: list[IngestionError] = []

    for i, raw_record in enumerate(records):
        row_index = i + 1  # 1-based for human-readable error messages
        event_index = id_offset + i

        # Map columns
        mapped = _map_columns(raw_record)

        # --- Validate required fields ---

        # Timestamp (required)
        raw_ts = mapped.get("timestamp")
        ts = _parse_timestamp(raw_ts)
        if ts is None:
            errors.append(IngestionError(
                row_index=row_index,
                field="timestamp",
                message=f"Missing or invalid timestamp: '{raw_ts}'",
                raw_data=raw_record,
            ))
            continue

        # Event type (required)
        raw_event_type = mapped.get("event_type")
        event_type = _normalize_event_type(raw_event_type)
        if event_type is None:
            errors.append(IngestionError(
                row_index=row_index,
                field="event_type",
                message=f"Missing or empty event_type: '{raw_event_type}'",
                raw_data=raw_record,
            ))
            continue

        # Source
        source = _normalize_source(mapped.get("source"), default_source)

        # Optional fields — sanitize strings
        user = _clean_str(mapped.get("user"))
        device = _clean_str(mapped.get("device"))
        ip = _clean_str(mapped.get("ip"))
        process = _clean_str(mapped.get("process"))

        # Build normalized event
        try:
            event = NormalizedEvent(
                event_id=_make_event_id(event_index),
                timestamp=ts,
                user=user,
                device=device,
                ip=ip,
                event_type=event_type,
                process=process,
                source=source,
                raw_data=raw_record,
            )
            events.append(event)
        except Exception as e:
            errors.append(IngestionError(
                row_index=row_index,
                field="general",
                message=f"Event construction failed: {str(e)}",
                raw_data=raw_record,
            ))

    return IngestionResult(
        events=events,
        errors=errors,
        total_rows=len(records),
        source_file=source_file,
    )


def _clean_str(value: Any) -> str | None:
    """Clean a string value: strip whitespace, return None for empty."""
    if value is None:
        return None
    s = str(value).strip()
    return s if s and s.lower() not in ("", "none", "null", "n/a", "na") else None


def ingest_csv(
    file_path: str | None = None,
    csv_content: str | None = None,
    default_source: EventSource = EventSource.AUTHENTICATION,
    id_offset: int = 1,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
) -> IngestionResult:
    """Ingest a CSV file or CSV string into normalized events.

    Args:
        file_path: Path to CSV file (mutually exclusive with csv_content).
        csv_content: Raw CSV string (mutually exclusive with file_path).
        default_source: Default source when not specified in the data.
        id_offset: Starting event ID number.
        max_size_bytes: Maximum allowed file size.

    Returns:
        IngestionResult with events and errors.
    """
    source_name = file_path or "<csv_content>"

    if file_path:
        # Check file size before reading
        file_size = os.path.getsize(file_path)
        if file_size > max_size_bytes:
            return IngestionResult(
                events=[],
                errors=[IngestionError(
                    row_index=0,
                    field="file",
                    message=f"File size ({file_size} bytes) exceeds limit ({max_size_bytes} bytes)",
                )],
                total_rows=0,
                source_file=source_name,
            )

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            csv_content = f.read()

    if not csv_content or not csv_content.strip():
        return IngestionResult(
            events=[],
            errors=[IngestionError(
                row_index=0, field="file", message="Empty CSV data"
            )],
            total_rows=0,
            source_file=source_name,
        )

    reader = csv.DictReader(io.StringIO(csv_content))
    records = list(reader)

    return ingest_records(
        records=records,
        default_source=default_source,
        id_offset=id_offset,
        source_file=source_name,
    )


def ingest_json(
    file_path: str | None = None,
    json_content: str | None = None,
    default_source: EventSource = EventSource.AUTHENTICATION,
    id_offset: int = 1,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
) -> IngestionResult:
    """Ingest a JSON file or JSON string into normalized events.

    Supports both JSON arrays of objects and newline-delimited JSON (NDJSON).

    Args:
        file_path: Path to JSON file.
        json_content: Raw JSON string.
        default_source: Default source when not specified.
        id_offset: Starting event ID number.
        max_size_bytes: Maximum allowed file size.

    Returns:
        IngestionResult with events and errors.
    """
    source_name = file_path or "<json_content>"

    if file_path:
        file_size = os.path.getsize(file_path)
        if file_size > max_size_bytes:
            return IngestionResult(
                events=[],
                errors=[IngestionError(
                    row_index=0,
                    field="file",
                    message=f"File size ({file_size} bytes) exceeds limit ({max_size_bytes} bytes)",
                )],
                total_rows=0,
                source_file=source_name,
            )

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            json_content = f.read()

    if not json_content or not json_content.strip():
        return IngestionResult(
            events=[],
            errors=[IngestionError(
                row_index=0, field="file", message="Empty JSON data"
            )],
            total_rows=0,
            source_file=source_name,
        )

    # Try parsing as JSON array first, then as NDJSON
    records: list[dict[str, Any]] = []
    try:
        parsed = json.loads(json_content)
        if isinstance(parsed, list):
            records = [r for r in parsed if isinstance(r, dict)]
        elif isinstance(parsed, dict):
            records = [parsed]  # Single record
        else:
            return IngestionResult(
                events=[],
                errors=[IngestionError(
                    row_index=0,
                    field="file",
                    message=f"JSON root must be an array or object, got {type(parsed).__name__}",
                )],
                total_rows=0,
                source_file=source_name,
            )
    except json.JSONDecodeError:
        # Try NDJSON (one JSON object per line)
        for line_num, line in enumerate(json_content.strip().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    records.append({})  # Will produce a validation error
            except json.JSONDecodeError as e:
                return IngestionResult(
                    events=[],
                    errors=[IngestionError(
                        row_index=line_num,
                        field="file",
                        message=f"Malformed JSON at line {line_num}: {str(e)}",
                    )],
                    total_rows=0,
                    source_file=source_name,
                )

    if not records:
        return IngestionResult(
            events=[],
            errors=[IngestionError(
                row_index=0, field="file", message="No valid records found in JSON"
            )],
            total_rows=0,
            source_file=source_name,
        )

    return ingest_records(
        records=records,
        default_source=default_source,
        id_offset=id_offset,
        source_file=source_name,
    )
