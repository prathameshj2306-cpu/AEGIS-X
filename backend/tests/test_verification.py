"""
Unit and integration tests for AEGIS-X Evidence Verification Engine (Phase 2 Checkpoint 3A).

Tests cover:
1. Valid evidence verification (VERIFIED).
2. Missing evidence in database (UNVERIFIED).
3. Fabricated citations (UNVERIFIED).
4. Cross-incident citations (UNVERIFIED).
5. User identity mismatch detection.
6. Device identity mismatch detection.
7. IP address mismatch detection.
8. Process name/lineage mismatch detection.
9. Out-of-bounds timestamp detection.
10. Partial citation coverage (PARTIAL).
11. Safe deduplication of duplicate citations.
12. Empty incident evidence handling.
13. Nullable entity fields handling (no false positive mismatches).
14. Multi-user incident support (no false positive mismatches on legitimate transitions).
15. Malformed structured claims rejection.
16. Fail-closed database lookup error handling.
17. UTC timestamp normalization.
18. Guarantee that incident severity is never modified.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from pydantic import ValidationError

from app.database.store import AegisDatabase
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Incident, IncidentStatus, Severity
from app.verification import (
    EventDiscrepancy,
    EvidenceVerificationResult,
    MismatchType,
    StructuredClaims,
    VerificationStatus,
    verify_incident_evidence,
)


def _create_event(
    event_id: str,
    timestamp: datetime,
    user: str = "alice",
    device: str = "WS-001",
    ip: str = "192.168.1.10",
    process: str = "powershell.exe",
    event_type: str = "login_success",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user=user,
        device=device,
        ip=ip,
        event_type=event_type,
        process=process,
        source=EventSource.AUTHENTICATION,
        raw_data={"raw_id": event_id, "original": "test log"},
    )


def _create_incident(
    incident_id: str = "INC001",
    evidence_ids: list[str] = None,
    start_time: datetime = None,
    end_time: datetime = None,
    user: str = "alice",
    device: str = "WS-001",
    severity: Severity = Severity.HIGH,
) -> Incident:
    t0 = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
    t1 = datetime(2024, 11, 20, 10, 30, tzinfo=timezone.utc)
    return Incident(
        incident_id=incident_id,
        title=f"Incident {incident_id}",
        severity=severity,
        status=IncidentStatus.OPEN,
        detected_patterns=["brute_force_login"],
        user=user,
        device=device,
        start_time=start_time or t0,
        end_time=end_time or t1,
        evidence_event_ids=evidence_ids if evidence_ids is not None else ["E001"],
        detection_ids=["D001"],
        severity_rationale="Deterministic high severity assignment.",
    )


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary SQLite database."""
    db_file = tmp_path / "test_verification.db"
    db = AegisDatabase(str(db_file))
    yield db
    db.close()


class TestEvidenceVerificationCore:
    """Core verification test cases covering requirements 1 through 18."""

    def test_1_valid_evidence_verification(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1, user="alice", device="WS-001")
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"])
        temp_db.store_incidents([inc])

        claims = StructuredClaims(
            claimed_user="alice",
            claimed_device="WS-001",
            claimed_ip="192.168.1.10",
            claimed_process="powershell.exe",
        )

        result = verify_incident_evidence(
            incident=inc,
            db=temp_db,
            claims=claims,
            ai_citations=["E001"],
        )

        assert result.status == VerificationStatus.VERIFIED
        assert result.resolved_evidence_count == 1
        assert result.missing_evidence_count == 0
        assert result.valid_citation_count == 1
        assert result.verified_evidence_ids == ["E001"]
        assert len(result.discrepancies) == 0

    def test_2_missing_event_id(self, temp_db):
        # E001 declared in incident, but never stored in SQLite
        inc = _create_incident("INC001", evidence_ids=["E001"])
        temp_db.store_incidents([inc])

        result = verify_incident_evidence(incident=inc, db=temp_db)

        assert result.status == VerificationStatus.UNVERIFIED
        assert result.missing_evidence_count == 1
        assert "E001" in result.missing_evidence_ids
        assert any(d.mismatch_type == MismatchType.MISSING_EVIDENCE for d in result.discrepancies)

    def test_3_fabricated_citation(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1)
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"])
        temp_db.store_incidents([inc])

        # Model cites E999 which is not part of incident evidence
        result = verify_incident_evidence(
            incident=inc,
            db=temp_db,
            ai_citations=["E001", "E999"],
        )

        assert result.status == VerificationStatus.UNVERIFIED
        assert "E999" in result.invalid_citation_ids
        assert any(d.mismatch_type == MismatchType.FABRICATED_CITATION for d in result.discrepancies)

    def test_4_cross_incident_citation(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev1 = _create_event("E001", t1)
        ev2 = _create_event("E002", t1)
        temp_db.store_events([ev1, ev2])

        inc1 = _create_incident("INC001", evidence_ids=["E001"])
        inc2 = _create_incident("INC002", evidence_ids=["E002"])
        temp_db.store_incidents([inc1, inc2])

        # Verifying INC001, but citation references E002 (belonging to INC002)
        result = verify_incident_evidence(
            incident=inc1,
            db=temp_db,
            ai_citations=["E002"],
        )

        assert result.status == VerificationStatus.UNVERIFIED
        assert "E002" in result.invalid_citation_ids
        assert any(d.mismatch_type == MismatchType.CROSS_INCIDENT_CITATION for d in result.discrepancies)

    def test_5_user_mismatch(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1, user="bob")
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"], user="bob")
        temp_db.store_incidents([inc])

        # Claim states user was 'alice', but actual was 'bob'
        claims = StructuredClaims(claimed_user="alice", claimed_event_ids=["E001"])
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=claims)

        assert result.status == VerificationStatus.UNVERIFIED
        assert any(d.mismatch_type == MismatchType.USER_MISMATCH for d in result.discrepancies)

    def test_6_device_mismatch(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1, device="SERVER-01")
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"], device="SERVER-01")
        temp_db.store_incidents([inc])

        claims = StructuredClaims(claimed_device="LAPTOP-99")
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=claims)

        assert result.status == VerificationStatus.UNVERIFIED
        assert any(d.mismatch_type == MismatchType.DEVICE_MISMATCH for d in result.discrepancies)

    def test_7_ip_mismatch(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1, ip="10.0.0.1")
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"])
        temp_db.store_incidents([inc])

        claims = StructuredClaims(claimed_ip="192.168.1.99")
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=claims)

        assert result.status == VerificationStatus.UNVERIFIED
        assert any(d.mismatch_type == MismatchType.IP_MISMATCH for d in result.discrepancies)

    def test_8_process_mismatch(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1, process="cmd.exe")
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"])
        temp_db.store_incidents([inc])

        claims = StructuredClaims(claimed_process="mimikatz.exe")
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=claims)

        assert result.status == VerificationStatus.UNVERIFIED
        assert any(d.mismatch_type == MismatchType.PROCESS_MISMATCH for d in result.discrepancies)

    def test_9_timestamp_outside_incident_window(self, temp_db):
        # Event is at 12:00, but incident window is 10:00 to 10:30
        t_out = datetime(2024, 11, 20, 12, 0, tzinfo=timezone.utc)
        ev = _create_event("E001", t_out)
        temp_db.store_events([ev])

        t_start = datetime(2024, 11, 20, 10, 0, tzinfo=timezone.utc)
        t_end = datetime(2024, 11, 20, 10, 30, tzinfo=timezone.utc)
        inc = _create_incident("INC001", evidence_ids=["E001"], start_time=t_start, end_time=t_end)
        temp_db.store_incidents([inc])

        result = verify_incident_evidence(incident=inc, db=temp_db, tolerance_seconds=0.0)

        assert result.status == VerificationStatus.UNVERIFIED
        assert any(d.mismatch_type == MismatchType.TIMESTAMP_OUT_OF_BOUNDS for d in result.discrepancies)

    def test_10_partial_citation_coverage(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        t2 = datetime(2024, 11, 20, 10, 15, tzinfo=timezone.utc)
        ev1 = _create_event("E001", t1)
        ev2 = _create_event("E002", t2)
        temp_db.store_events([ev1, ev2])

        inc = _create_incident("INC001", evidence_ids=["E001", "E002"])
        temp_db.store_incidents([inc])

        # Model only cites E001 (E002 omitted)
        result = verify_incident_evidence(
            incident=inc,
            db=temp_db,
            ai_citations=["E001"],
        )

        assert result.status == VerificationStatus.PARTIAL
        assert result.valid_citation_count == 1
        assert result.total_evidence_count == 2
        assert result.uncited_evidence_ids == ["E002"]
        assert len(result.discrepancies) == 0

    def test_11_duplicate_citations(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1)
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"])
        temp_db.store_incidents([inc])

        result = verify_incident_evidence(
            incident=inc,
            db=temp_db,
            ai_citations=["E001", "E001", "E001"],
        )

        assert result.status == VerificationStatus.VERIFIED
        assert result.valid_citation_count == 1
        assert result.duplicate_citation_ids == ["E001", "E001"]

    def test_12_empty_evidence(self, temp_db):
        inc = _create_incident("INC_EMPTY", evidence_ids=[])
        temp_db.store_incidents([inc])

        result = verify_incident_evidence(incident=inc, db=temp_db)

        assert result.status == VerificationStatus.UNVERIFIED
        assert result.total_evidence_count == 0
        assert any(d.mismatch_type == MismatchType.EMPTY_EVIDENCE for d in result.discrepancies)

    def test_13_nullable_user_device_fields(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        # Auth event with None device and None process
        ev = NormalizedEvent(
            event_id="E001",
            timestamp=t1,
            user="alice",
            device=None,
            ip="10.0.0.1",
            event_type="login_success",
            process=None,
            source=EventSource.AUTHENTICATION,
            raw_data={},
        )
        temp_db.store_events([ev])

        inc = _create_incident("INC001", evidence_ids=["E001"], user="alice", device=None)
        temp_db.store_incidents([inc])

        # Claim with device specified
        claims = StructuredClaims(claimed_user="alice", claimed_device="WS-001")
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=claims)

        # Since actual device is None, it is not a direct contradiction, but status is PARTIAL
        assert result.status == VerificationStatus.PARTIAL
        assert not any(d.mismatch_type == MismatchType.DEVICE_MISMATCH for d in result.discrepancies)

    def test_14_multi_user_incident_without_false_mismatch(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        t2 = datetime(2024, 11, 20, 10, 15, tzinfo=timezone.utc)
        # Multi-user chain: bob starts, then admin executes
        ev1 = _create_event("E001", t1, user="bob")
        ev2 = _create_event("E002", t2, user="admin")
        temp_db.store_events([ev1, ev2])

        inc = _create_incident("INC_MULTI", evidence_ids=["E001", "E002"], user="bob")
        temp_db.store_incidents([inc])

        # Claiming either user should be accepted across incident scope without false mismatch
        claims = StructuredClaims(claimed_user="admin")
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=claims)

        assert not any(d.mismatch_type == MismatchType.USER_MISMATCH for d in result.discrepancies)

    def test_15_malformed_structured_claims(self):
        # Extra fields forbidden in StructuredClaims
        with pytest.raises(ValidationError):
            StructuredClaims(claimed_user="alice", unexpected_field="attack")

    def test_16_database_lookup_failure(self):
        inc = _create_incident("INC001", evidence_ids=["E001"])

        # No database provided -> fails closed
        result = verify_incident_evidence(incident=inc, db=None)

        assert result.status == VerificationStatus.UNVERIFIED
        assert result.database_error is not None
        assert any(d.mismatch_type == MismatchType.DATABASE_ERROR for d in result.discrepancies)

    def test_17_utc_timestamp_normalization(self, temp_db):
        # Naive datetime in claims should normalize to UTC without crashing
        naive_start = datetime(2024, 11, 20, 10, 0)
        naive_end = datetime(2024, 11, 20, 10, 30)

        claims = StructuredClaims(
            claimed_start_time=naive_start,
            claimed_end_time=naive_end,
        )
        assert claims.claimed_start_time.tzinfo == timezone.utc
        assert claims.claimed_end_time.tzinfo == timezone.utc

    def test_18_no_severity_modification(self, temp_db):
        t1 = datetime(2024, 11, 20, 10, 5, tzinfo=timezone.utc)
        ev = _create_event("E001", t1)
        temp_db.store_events([ev])

        original_severity = Severity.HIGH
        inc = _create_incident("INC001", evidence_ids=["E001"], severity=original_severity)
        temp_db.store_incidents([inc])

        # Run verification with failing claims
        failing_claims = StructuredClaims(claimed_user="completely_wrong_user")
        result = verify_incident_evidence(incident=inc, db=temp_db, claims=failing_claims)

        assert result.status == VerificationStatus.UNVERIFIED
        # Guarantee incident severity was not touched
        assert inc.severity == original_severity
        assert inc.severity.value == "HIGH"
