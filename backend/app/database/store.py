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
import threading
from datetime import datetime, timezone
from typing import Optional

from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection, Incident

_GLOBAL_DB_LOCK = threading.RLock()


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
        self._write_lock = _GLOBAL_DB_LOCK
        self._create_tables()
        self._apply_migrations()

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
                batch_id TEXT,
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
                batch_id TEXT,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

            CREATE TABLE IF NOT EXISTS ingestion_batches (
                batch_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                source TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'UPLOADED',
                incident_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_batches_status ON ingestion_batches(status);

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

    def _apply_migrations(self):
        """Apply incremental schema updates and backfill legacy batches safely."""
        with self._write_lock:
            # Check events table columns
            cursor = self.conn.execute("PRAGMA table_info(events)")
            event_cols = [r["name"] for r in cursor.fetchall()]
            if "batch_id" not in event_cols:
                self.conn.execute("ALTER TABLE events ADD COLUMN batch_id TEXT")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_batch ON events(batch_id)")

            # Check incidents table columns
            cursor = self.conn.execute("PRAGMA table_info(incidents)")
            incident_cols = [r["name"] for r in cursor.fetchall()]
            if "batch_id" not in incident_cols:
                self.conn.execute("ALTER TABLE incidents ADD COLUMN batch_id TEXT")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_batch ON incidents(batch_id)")

            # Backfill events with BATCH-LEGACY if batch_id is NULL or empty
            self.conn.execute("UPDATE events SET batch_id = 'BATCH-LEGACY' WHERE batch_id IS NULL OR batch_id = ''")

            # Backfill incidents with BATCH-LEGACY if batch_id is NULL or empty
            self.conn.execute("UPDATE incidents SET batch_id = 'BATCH-LEGACY' WHERE batch_id IS NULL OR batch_id = ''")

            # Check if BATCH-LEGACY needs to be registered in ingestion_batches
            cur_ev = self.conn.execute("SELECT COUNT(*) as cnt FROM events WHERE batch_id = 'BATCH-LEGACY'")
            legacy_ev_row = cur_ev.fetchone()
            legacy_ev_cnt = legacy_ev_row["cnt"] if legacy_ev_row else 0
            if legacy_ev_cnt > 0:
                cur_inc = self.conn.execute("SELECT COUNT(*) as cnt FROM incidents WHERE batch_id = 'BATCH-LEGACY'")
                legacy_inc_row = cur_inc.fetchone()
                legacy_inc_cnt = legacy_inc_row["cnt"] if legacy_inc_row else 0
                self.conn.execute("""
                    INSERT OR IGNORE INTO ingestion_batches
                    (batch_id, filename, source, event_count, status, incident_count, created_at, updated_at)
                    VALUES ('BATCH-LEGACY', 'legacy_telemetry.json', 'mixed', ?, 'INVESTIGATED', ?, datetime('now'), datetime('now'))
                """, (legacy_ev_cnt, legacy_inc_cnt))

            self.conn.commit()

    # --- Ingestion Batch operations ---

    def generate_next_batch_id(self) -> str:
        """Return the next sequential BATCH-000001 format ID under write lock."""
        with self._write_lock:
            cursor = self.conn.execute("SELECT batch_id FROM ingestion_batches WHERE batch_id LIKE 'BATCH-%'")
            max_id = 0
            for row in cursor.fetchall():
                bid = row["batch_id"] if isinstance(row, sqlite3.Row) else row[0]
                if bid == "BATCH-LEGACY":
                    continue
                suffix = bid[6:]
                if suffix.isdigit():
                    num = int(suffix)
                    if num > max_id:
                        max_id = num
            return f"BATCH-{max_id + 1:06d}"

    def create_batch(
        self,
        batch_id: Optional[str] = None,
        filename: str = "",
        source: str = "",
        event_count: int = 0,
        status: str = "UPLOADED",
    ) -> dict:
        """Create and store an ingestion batch record under atomic write lock and transaction."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                if not batch_id:
                    cursor = self.conn.execute("SELECT batch_id FROM ingestion_batches WHERE batch_id LIKE 'BATCH-%'")
                    max_id = 0
                    for row in cursor.fetchall():
                        bid_str = row["batch_id"] if isinstance(row, sqlite3.Row) else row[0]
                        if bid_str == "BATCH-LEGACY":
                            continue
                        suffix = bid_str[6:]
                        if suffix.isdigit():
                            num = int(suffix)
                            if num > max_id:
                                max_id = num
                    bid = f"BATCH-{max_id + 1:06d}"
                else:
                    bid = batch_id

                self.conn.execute(
                    """INSERT INTO ingestion_batches
                       (batch_id, filename, source, event_count, status, incident_count, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
                    (bid, filename, source, event_count, status, now_iso, now_iso),
                )
                self.conn.commit()
                return self.get_batch(bid)
            except Exception as e:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
                raise e

    def get_batch(self, batch_id: str) -> Optional[dict]:
        """Retrieve a single batch by ID."""
        row = self.conn.execute(
            "SELECT * FROM ingestion_batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if row:
            return dict(row)
        return None

    def get_latest_batch(self) -> Optional[dict]:
        """Retrieve the latest ingestion batch (excluding legacy if newer batches exist)."""
        row = self.conn.execute(
            "SELECT * FROM ingestion_batches ORDER BY CASE WHEN batch_id = 'BATCH-LEGACY' THEN 1 ELSE 0 END, created_at DESC, batch_id DESC LIMIT 1"
        ).fetchone()
        if row:
            return dict(row)
        return None

    def get_all_batches(self) -> list[dict]:
        """Retrieve all batches ordered by created_at DESC."""
        rows = self.conn.execute(
            "SELECT * FROM ingestion_batches ORDER BY CASE WHEN batch_id = 'BATCH-LEGACY' THEN 1 ELSE 0 END, created_at DESC, batch_id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_batch_status(
        self,
        batch_id: str,
        status: str,
        incident_count: Optional[int] = None,
    ) -> None:
        """Update the processing status and incident count of a batch."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._write_lock:
            if incident_count is not None:
                self.conn.execute(
                    """UPDATE ingestion_batches
                       SET status = ?, incident_count = ?, updated_at = ?
                       WHERE batch_id = ?""",
                    (status, incident_count, now_iso, batch_id),
                )
            else:
                self.conn.execute(
                    """UPDATE ingestion_batches
                       SET status = ?, updated_at = ?
                       WHERE batch_id = ?""",
                    (status, now_iso, batch_id),
                )
            self.conn.commit()

    # --- Event operations ---

    def get_max_event_id_number(self) -> int:
        """Return the highest numeric ID among existing E000001-style event IDs.

        Safely parses the numeric suffix of 'E%'-style IDs, ignoring non-numeric
        event IDs. Guarantees that subsequent allocations will be strictly greater
        even if records have been deleted or gaps exist.
        """
        cursor = self.conn.execute("SELECT event_id FROM events WHERE event_id LIKE 'E%'")
        max_id = 0
        for row in cursor.fetchall():
            eid = row["event_id"] if isinstance(row, sqlite3.Row) else row[0]
            suffix = eid[1:]
            if suffix.isdigit():
                num = int(suffix)
                if num > max_id:
                    max_id = num
        return max_id

    def allocate_and_store_events(
        self,
        events: list[NormalizedEvent],
        batch_id: Optional[str] = None,
    ) -> list[NormalizedEvent]:
        """Atomically allocate sequential E000001-style IDs and insert events under a transaction lock.

        Guarantees:
        1. Queries the maximum existing numeric event ID (not row count) to handle gaps and deletions.
        2. Acquires an atomic SQLite transaction (BEGIN IMMEDIATE) and thread write lock,
           preventing concurrent uploads from generating duplicate IDs.
        3. Assigns strictly monotonic sequential IDs preserving the 'E000001' format.
        4. Detects collisions explicitly via INSERT INTO (rejecting duplicates rather than
           silently overwriting existing evidence with INSERT OR REPLACE).
        5. Automatically rolls back on any write or constraint error, leaving no partial state.
        6. Persists batch_id association.
        """
        if not events:
            return []

        with self._write_lock:
            try:
                self.conn.execute("BEGIN IMMEDIATE")

                # 1. Determine highest existing numeric ID under active transaction
                cursor = self.conn.execute("SELECT event_id FROM events WHERE event_id LIKE 'E%'")
                max_id = 0
                for row in cursor.fetchall():
                    eid = row["event_id"] if isinstance(row, sqlite3.Row) else row[0]
                    suffix = eid[1:]
                    if suffix.isdigit():
                        num = int(suffix)
                        if num > max_id:
                            max_id = num

                # 2. Assign strictly monotonic sequential IDs
                allocated_events: list[NormalizedEvent] = []
                rows = []
                now_iso = datetime.now(timezone.utc).isoformat()

                for i, event in enumerate(events):
                    new_id_num = max_id + 1 + i
                    new_event_id = f"E{new_id_num:06d}"
                    effective_batch = batch_id or event.batch_id

                    allocated_event = event.model_copy(update={"event_id": new_event_id, "batch_id": effective_batch})
                    allocated_events.append(allocated_event)

                    rows.append((
                        allocated_event.event_id,
                        allocated_event.timestamp.isoformat(),
                        allocated_event.user,
                        allocated_event.device,
                        allocated_event.ip,
                        allocated_event.event_type,
                        allocated_event.process,
                        allocated_event.source.value,
                        json.dumps(allocated_event.raw_data),
                        effective_batch,
                        allocated_event.model_dump_json(),
                        now_iso,
                    ))

                # 3. Collision-detecting insert: INSERT INTO will raise IntegrityError on primary key conflict
                self.conn.executemany(
                    """INSERT INTO events
                       (event_id, timestamp, user, device, ip, event_type, process,
                        source, raw_data, batch_id, data_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
                self.conn.commit()
                return allocated_events

            except Exception as e:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
                raise e

    def store_events(self, events: list[NormalizedEvent], batch_id: Optional[str] = None) -> int:
        """Store normalized events with rollback safety. Returns count stored."""
        if not events:
            return 0

        with self._write_lock:
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                rows = []
                for event in events:
                    ev_batch = getattr(event, "batch_id", None)
                    effective_batch = batch_id or ev_batch
                    if effective_batch and ev_batch != effective_batch and hasattr(event, "model_copy"):
                        event = event.model_copy(update={"batch_id": effective_batch})
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
                        effective_batch,
                        event.model_dump_json(),
                        datetime.now(timezone.utc).isoformat(),
                    ))

                self.conn.executemany(
                    """INSERT OR REPLACE INTO events
                       (event_id, timestamp, user, device, ip, event_type, process,
                        source, raw_data, batch_id, data_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
                self.conn.commit()
                return len(rows)
            except Exception as e:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
                raise e

    def get_event(self, event_id: str) -> Optional[NormalizedEvent]:
        """Retrieve a single event by ID."""
        row = self.conn.execute(
            "SELECT data_json, batch_id FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row:
            ev = NormalizedEvent.model_validate_json(row["data_json"])
            if ev.batch_id is None and row["batch_id"]:
                ev = ev.model_copy(update={"batch_id": row["batch_id"]})
            return ev
        return None

    def get_all_events(self, batch_id: Optional[str] = None) -> list[NormalizedEvent]:
        """Retrieve all events, ordered by timestamp, optionally filtered by batch_id."""
        if batch_id and batch_id != "all":
            rows = self.conn.execute(
                "SELECT data_json, batch_id FROM events WHERE batch_id = ? ORDER BY timestamp",
                (batch_id,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT data_json, batch_id FROM events ORDER BY timestamp"
            ).fetchall()
        events = []
        for r in rows:
            ev = NormalizedEvent.model_validate_json(r["data_json"])
            if ev.batch_id is None and r["batch_id"]:
                ev = ev.model_copy(update={"batch_id": r["batch_id"]})
            events.append(ev)
        return events

    def get_events_by_batch(self, batch_id: str) -> list[NormalizedEvent]:
        """Retrieve all events belonging to a specific batch."""
        return self.get_all_events(batch_id=batch_id)

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

    def store_incidents(self, incidents: list[Incident], batch_id: Optional[str] = None) -> int:
        """Store incidents with write lock and transaction rollback safety. Returns count stored."""
        if not incidents:
            return 0

        with self._write_lock:
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                rows = []
                for inc in incidents:
                    inc_batch = getattr(inc, "batch_id", None)
                    effective_batch = batch_id or inc_batch
                    if effective_batch and inc_batch != effective_batch and hasattr(inc, "model_copy"):
                        inc = inc.model_copy(update={"batch_id": effective_batch})
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
                        effective_batch,
                        inc.model_dump_json(),
                        datetime.now(timezone.utc).isoformat(),
                    ))

                self.conn.executemany(
                    """INSERT OR REPLACE INTO incidents
                       (incident_id, title, severity, status, detected_patterns,
                        user, device, start_time, end_time, evidence_event_ids,
                        detection_ids, risk_score, severity_rationale, batch_id, data_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
                self.conn.commit()
                return len(rows)
            except Exception as e:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
                raise e

    def get_max_incident_id_number(self) -> int:
        """Return the highest numeric ID among existing INC000001-style incident IDs."""
        cursor = self.conn.execute("SELECT incident_id FROM incidents WHERE incident_id LIKE 'INC%'")
        max_id = 0
        for row in cursor.fetchall():
            iid = row["incident_id"] if isinstance(row, sqlite3.Row) else row[0]
            suffix = iid[3:]
            if suffix.isdigit():
                num = int(suffix)
                if num > max_id:
                    max_id = num
        return max_id

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve a single incident by ID."""
        row = self.conn.execute(
            "SELECT data_json, batch_id FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row:
            inc = Incident.model_validate_json(row["data_json"])
            if inc.batch_id is None and row["batch_id"]:
                inc = inc.model_copy(update={"batch_id": row["batch_id"]})
            return inc
        return None

    def get_all_incidents(self, batch_id: Optional[str] = None) -> list[Incident]:
        """Retrieve all incidents, ordered by severity (CRITICAL first), optionally filtered by batch_id."""
        severity_order = "CASE severity " \
                         "WHEN 'CRITICAL' THEN 1 " \
                         "WHEN 'HIGH' THEN 2 " \
                         "WHEN 'MEDIUM' THEN 3 " \
                         "WHEN 'LOW' THEN 4 END"
        if batch_id and batch_id != "all":
            rows = self.conn.execute(
                f"SELECT data_json, batch_id FROM incidents WHERE batch_id = ? ORDER BY {severity_order}, start_time",
                (batch_id,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                f"SELECT data_json, batch_id FROM incidents ORDER BY {severity_order}, start_time"
            ).fetchall()
        incidents = []
        for r in rows:
            inc = Incident.model_validate_json(r["data_json"])
            if inc.batch_id is None and r["batch_id"]:
                inc = inc.model_copy(update={"batch_id": r["batch_id"]})
            incidents.append(inc)
        return incidents

    def get_incidents_by_batch(self, batch_id: str) -> list[Incident]:
        """Retrieve all incidents belonging to a specific batch."""
        return self.get_all_incidents(batch_id=batch_id)

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
            DELETE FROM ingestion_batches;
        """)
        self.conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
