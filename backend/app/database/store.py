"""
SQLite persistence layer for AEGIS-X.

Stores normalized events and incidents in a local SQLite database.
This is the single persistence boundary — all other modules work with
in-memory Pydantic models.

Design decisions:
- Events and incidents are stored as JSON blobs in SQLite for flexibility.
  (We don't need complex SQL queries on individual fields in Phase 1.)
- Each table has an indexed primary key for fast lookup.
- The database is created on first use; no migration framework needed yet.
- Thread safety: SQLite in WAL mode with check_same_thread=False.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection, Incident


class AegisDatabase:
    """SQLite persistence for AEGIS-X events, detections, and incidents."""

    def __init__(self, db_path: str = "aegis.db"):
        """Initialize the database connection and create tables.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path

        # Ensure directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        """Create database tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
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

            CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

            CREATE TABLE IF NOT EXISTS detections (
                detection_id TEXT PRIMARY KEY,
                rule_name TEXT NOT NULL,
                explanation TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user TEXT,
                device TEXT,
                confidence TEXT,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_name);
            CREATE INDEX IF NOT EXISTS idx_detections_user ON detections(user);

            CREATE TABLE IF NOT EXISTS incidents (
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

            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

            CREATE TABLE IF NOT EXISTS analysis_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                total_events INTEGER,
                total_detections INTEGER,
                total_incidents INTEGER,
                config_json TEXT,
                summary_json TEXT
            );
        """)
        self.conn.commit()

    # --- Event operations ---

    def store_events(self, events: list[NormalizedEvent]) -> int:
        """Store normalized events. Returns count stored."""
        if not events:
            return 0

        rows = []
        for event in events:
            rows.append((
                event.event_id,
                event.timestamp.isoformat(),
                event.user,
                event.device,
                event.ip,
                event.event_type,
                event.process,
                event.source.value,
                json.dumps(event.raw_data),
                event.model_dump_json(),
                datetime.now(timezone.utc).isoformat(),
            ))

        self.conn.executemany(
            """INSERT OR REPLACE INTO events
               (event_id, timestamp, user, device, ip, event_type, process,
                source, raw_data, data_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self.conn.commit()
        return len(rows)

    def get_event(self, event_id: str) -> Optional[NormalizedEvent]:
        """Retrieve a single event by ID."""
        row = self.conn.execute(
            "SELECT data_json FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row:
            return NormalizedEvent.model_validate_json(row["data_json"])
        return None

    def get_all_events(self) -> list[NormalizedEvent]:
        """Retrieve all events, ordered by timestamp."""
        rows = self.conn.execute(
            "SELECT data_json FROM events ORDER BY timestamp"
        ).fetchall()
        return [NormalizedEvent.model_validate_json(r["data_json"]) for r in rows]

    def get_event_count(self) -> int:
        """Return total event count."""
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
        return row["cnt"]

    # --- Detection operations ---

    def store_detections(self, detections: list[Detection]) -> int:
        """Store detections. Returns count stored."""
        if not detections:
            return 0

        rows = []
        for det in detections:
            rows.append((
                det.detection_id,
                det.rule_name,
                det.explanation,
                json.dumps(det.event_ids),
                det.timestamp.isoformat(),
                det.user,
                det.device,
                det.confidence,
                det.model_dump_json(),
                datetime.now(timezone.utc).isoformat(),
            ))

        self.conn.executemany(
            """INSERT OR REPLACE INTO detections
               (detection_id, rule_name, explanation, event_ids, timestamp,
                user, device, confidence, data_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self.conn.commit()
        return len(rows)

    def get_all_detections(self) -> list[Detection]:
        """Retrieve all detections."""
        rows = self.conn.execute(
            "SELECT data_json FROM detections ORDER BY timestamp"
        ).fetchall()
        return [Detection.model_validate_json(r["data_json"]) for r in rows]

    # --- Incident operations ---

    def store_incidents(self, incidents: list[Incident]) -> int:
        """Store incidents. Returns count stored."""
        if not incidents:
            return 0

        rows = []
        for inc in incidents:
            rows.append((
                inc.incident_id,
                inc.title,
                inc.severity.value,
                inc.status.value,
                json.dumps(inc.detected_patterns),
                inc.user,
                inc.device,
                inc.start_time.isoformat(),
                inc.end_time.isoformat(),
                json.dumps(inc.evidence_event_ids),
                json.dumps(inc.detection_ids),
                inc.risk_score,
                inc.severity_rationale,
                inc.model_dump_json(),
                datetime.now(timezone.utc).isoformat(),
            ))

        self.conn.executemany(
            """INSERT OR REPLACE INTO incidents
               (incident_id, title, severity, status, detected_patterns,
                user, device, start_time, end_time, evidence_event_ids,
                detection_ids, risk_score, severity_rationale, data_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self.conn.commit()
        return len(rows)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve a single incident by ID."""
        row = self.conn.execute(
            "SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row:
            return Incident.model_validate_json(row["data_json"])
        return None

    def get_all_incidents(self) -> list[Incident]:
        """Retrieve all incidents, ordered by severity (CRITICAL first)."""
        severity_order = "CASE severity " \
                         "WHEN 'CRITICAL' THEN 1 " \
                         "WHEN 'HIGH' THEN 2 " \
                         "WHEN 'MEDIUM' THEN 3 " \
                         "WHEN 'LOW' THEN 4 END"
        rows = self.conn.execute(
            f"SELECT data_json FROM incidents ORDER BY {severity_order}, start_time"
        ).fetchall()
        return [Incident.model_validate_json(r["data_json"]) for r in rows]

    def get_incident_count(self) -> int:
        """Return total incident count."""
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()
        return row["cnt"]

    def get_incidents_by_severity(self) -> dict[str, int]:
        """Return incident counts by severity."""
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    # --- Analysis run tracking ---

    def start_run(self, config_json: str = "{}") -> int:
        """Record the start of an analysis run. Returns run_id."""
        cursor = self.conn.execute(
            """INSERT INTO analysis_runs (started_at, config_json)
               VALUES (?, ?)""",
            (datetime.now(timezone.utc).isoformat(), config_json),
        )
        self.conn.commit()
        return cursor.lastrowid

    def complete_run(self, run_id: int, total_events: int,
                     total_detections: int, total_incidents: int,
                     summary_json: str = "{}") -> None:
        """Record the completion of an analysis run."""
        self.conn.execute(
            """UPDATE analysis_runs
               SET completed_at = ?, total_events = ?, total_detections = ?,
                   total_incidents = ?, summary_json = ?
               WHERE run_id = ?""",
            (
                datetime.now(timezone.utc).isoformat(),
                total_events, total_detections, total_incidents,
                summary_json, run_id,
            ),
        )
        self.conn.commit()

    # --- Utilities ---

    def clear_all(self) -> None:
        """Clear all data (useful for testing)."""
        self.conn.executescript("""
            DELETE FROM events;
            DELETE FROM detections;
            DELETE FROM incidents;
            DELETE FROM analysis_runs;
        """)
        self.conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
