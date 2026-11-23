"""
Deterministic Evidence Verification Engine for AEGIS-X (Phase 2 Checkpoint 3A).

Strict Architectural Guarantees:
1. Determinism: 100% deterministic Python logic. Never uses an SLM to judge evidence.
2. Ground-Truth Persistence Check: Resolves every evidence ID against actual SQLite records.
3. Citation Validation: Rejects fabricated citations, hallucinated IDs, and cross-incident references.
4. Entity Consistency: Verifies claimed users, devices, IPs, and processes without misflagging
   legitimate multi-user incident transitions.
5. Temporal Integrity: Validates UTC-normalized timestamps against incident window boundaries.
6. Fail-Closed Error Handling: Database errors and corrupted lookups yield explicit UNVERIFIED results.
7. Non-Destructive: Never modifies incident severity, detection rules, correlation, or database records.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from app.database.store import AegisDatabase
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident
from app.verification.models import (
    EventDiscrepancy,
    EvidenceVerificationResult,
    MismatchType,
    StructuredClaims,
    VerificationStatus,
    _ensure_utc,
)


def verify_incident_evidence(
    incident: Incident,
    db: Optional[AegisDatabase] = None,
    events: Optional[list[NormalizedEvent]] = None,
    claims: Optional[StructuredClaims] = None,
    ai_citations: Optional[list[str]] = None,
    tolerance_seconds: float = 0.0,
) -> EvidenceVerificationResult:
    """Deterministically verify incident evidence against SQLite telemetry records and structured claims.

    Args:
        incident: The Incident instance under verification.
        db: Active AegisDatabase connection (required for persistence validation).
        events: Optional list of in-memory NormalizedEvent records for cross-validation.
        claims: Optional structured claims (e.g. claimed user, device, IP, process, time window).
        ai_citations: Optional list of event IDs cited by the SLM or investigator.
        tolerance_seconds: Time tolerance in seconds for window comparison (default: 0.0s).

    Returns:
        Immutable EvidenceVerificationResult with audit trail and status.
    """
    incident_id = incident.incident_id
    total_evidence_ids = list(incident.evidence_event_ids)
    total_evidence_count = len(total_evidence_ids)

    discrepancies: list[EventDiscrepancy] = []
    rationale: list[str] = []

    # 1. Empty Evidence Guard
    if total_evidence_count == 0:
        discrepancies.append(
            EventDiscrepancy(
                event_id=None,
                mismatch_type=MismatchType.EMPTY_EVIDENCE,
                expected_value=">= 1 evidence event ID",
                actual_value="0",
                explanation="Incident contains no supporting evidence event IDs.",
            )
        )
        return EvidenceVerificationResult(
            incident_id=incident_id,
            status=VerificationStatus.UNVERIFIED,
            total_evidence_count=0,
            resolved_evidence_count=0,
            missing_evidence_count=0,
            cited_evidence_count=0,
            valid_citation_count=0,
            verified_evidence_ids=[],
            uncited_evidence_ids=[],
            missing_evidence_ids=[],
            invalid_citation_ids=[],
            duplicate_citation_ids=[],
            discrepancies=discrepancies,
            verification_rationale=["Incident contains empty evidence_event_ids list."],
            database_error=None,
        )

    # 2. Database Connection Check (Fail Closed)
    if db is None:
        db_err = "No active database connection provided for ground-truth evidence verification."
        discrepancies.append(
            EventDiscrepancy(
                event_id=None,
                mismatch_type=MismatchType.DATABASE_ERROR,
                expected_value="Active AegisDatabase connection",
                actual_value="None",
                explanation=db_err,
            )
        )
        return EvidenceVerificationResult(
            incident_id=incident_id,
            status=VerificationStatus.UNVERIFIED,
            total_evidence_count=total_evidence_count,
            resolved_evidence_count=0,
            missing_evidence_count=total_evidence_count,
            cited_evidence_count=len(ai_citations) if ai_citations else 0,
            valid_citation_count=0,
            verified_evidence_ids=[],
            uncited_evidence_ids=[],
            missing_evidence_ids=total_evidence_ids,
            invalid_citation_ids=[],
            duplicate_citation_ids=[],
            discrepancies=discrepancies,
            verification_rationale=[db_err],
            database_error=db_err,
        )

    # 3. Ground-Truth Persistence Resolution
    resolved_events_map: dict[str, NormalizedEvent] = {}
    missing_evidence_ids: list[str] = []

    try:
        for eid in total_evidence_ids:
            ev = db.get_event(eid)
            if ev is not None:
                resolved_events_map[eid] = ev
            else:
                missing_evidence_ids.append(eid)
                discrepancies.append(
                    EventDiscrepancy(
                        event_id=eid,
                        mismatch_type=MismatchType.MISSING_EVIDENCE,
                        expected_value=f"Event {eid} present in SQLite 'events' table",
                        actual_value="Record not found",
                        explanation=f"Evidence event '{eid}' declared in incident evidence could not be resolved from database.",
                    )
                )
    except Exception as ex:
        db_err = f"Database query failure during evidence resolution: {type(ex).__name__}"
        discrepancies.append(
            EventDiscrepancy(
                event_id=None,
                mismatch_type=MismatchType.DATABASE_ERROR,
                expected_value="Successful SQLite query",
                actual_value=str(type(ex).__name__),
                explanation=db_err,
            )
        )
        return EvidenceVerificationResult(
            incident_id=incident_id,
            status=VerificationStatus.UNVERIFIED,
            total_evidence_count=total_evidence_count,
            resolved_evidence_count=len(resolved_events_map),
            missing_evidence_count=len(missing_evidence_ids),
            cited_evidence_count=len(ai_citations) if ai_citations else 0,
            valid_citation_count=0,
            verified_evidence_ids=[],
            uncited_evidence_ids=[],
            missing_evidence_ids=missing_evidence_ids,
            invalid_citation_ids=[],
            duplicate_citation_ids=[],
            discrepancies=discrepancies,
            verification_rationale=[db_err],
            database_error=db_err,
        )

    # 4. Citation Validation & Deduplication
    citations_to_check = ai_citations
    if citations_to_check is None and incident.ai_analysis:
        citations_to_check = incident.ai_analysis.get("cited_event_ids", [])

    cited_count = len(citations_to_check) if citations_to_check else 0
    valid_citation_ids: list[str] = []
    invalid_citation_ids: list[str] = []
    duplicate_citation_ids: list[str] = []
    seen_citations = set()
    unique_citations: list[str] = []

    if citations_to_check:
        for c in citations_to_check:
            if c in seen_citations:
                duplicate_citation_ids.append(c)
            else:
                seen_citations.add(c)
                unique_citations.append(c)

        # Cross-incident and fabrication detection
        other_incidents_cache: Optional[list[Incident]] = None

        for c in unique_citations:
            if c in incident.evidence_event_ids:
                if c in resolved_events_map:
                    valid_citation_ids.append(c)
                else:
                    # In incident evidence list but missing from SQLite
                    invalid_citation_ids.append(c)
            else:
                invalid_citation_ids.append(c)
                # Check if it belongs to another incident
                is_cross_incident = False
                belonging_incident_id = None
                try:
                    if other_incidents_cache is None:
                        other_incidents_cache = db.get_all_incidents()
                    for other_inc in other_incidents_cache:
                        if other_inc.incident_id != incident.incident_id and c in other_inc.evidence_event_ids:
                            is_cross_incident = True
                            belonging_incident_id = other_inc.incident_id
                            break
                except Exception:
                    pass

                if is_cross_incident:
                    discrepancies.append(
                        EventDiscrepancy(
                            event_id=c,
                            mismatch_type=MismatchType.CROSS_INCIDENT_CITATION,
                            expected_value=f"Evidence belonging to {incident_id}",
                            actual_value=f"Belongs to {belonging_incident_id}",
                            explanation=(
                                f"Citation '{c}' belongs to another incident '{belonging_incident_id}' "
                                f"(cross-incident evidence contamination)."
                            ),
                        )
                    )
                else:
                    discrepancies.append(
                        EventDiscrepancy(
                            event_id=c,
                            mismatch_type=MismatchType.FABRICATED_CITATION,
                            expected_value=f"Member of {incident_id}.evidence_event_ids",
                            actual_value=f"Unrecognized citation '{c}'",
                            explanation=f"Citation '{c}' does not belong to incident evidence list.",
                        )
                    )

    uncited_evidence_ids = [
        eid for eid in total_evidence_ids if eid not in seen_citations
    ]

    # 5. Timestamp Window Boundaries Validation
    inc_start = _ensure_utc(incident.start_time)
    inc_end = _ensure_utc(incident.end_time)
    tolerance = timedelta(seconds=max(0.0, float(tolerance_seconds)))

    for eid, ev in resolved_events_map.items():
        ev_time = _ensure_utc(ev.timestamp)
        if ev_time < (inc_start - tolerance) or ev_time > (inc_end + tolerance):
            discrepancies.append(
                EventDiscrepancy(
                    event_id=eid,
                    mismatch_type=MismatchType.TIMESTAMP_OUT_OF_BOUNDS,
                    expected_value=f"{inc_start.isoformat()} .. {inc_end.isoformat()} (±{tolerance_seconds}s)",
                    actual_value=ev_time.isoformat(),
                    explanation=(
                        f"Event '{eid}' timestamp {ev_time.isoformat()} falls outside declared incident "
                        f"window [{inc_start.isoformat()} .. {inc_end.isoformat()}] with tolerance {tolerance_seconds}s."
                    ),
                )
            )

    # 6. Entity & Structured Claims Verification
    has_nullable_attr_gap = False

    if claims is not None:
        # Collect candidate ground-truth entities across all resolved incident evidence events
        all_event_users = {ev.user for ev in resolved_events_map.values() if ev.user}
        all_event_devices = {ev.device for ev in resolved_events_map.values() if ev.device}
        all_event_ips = {ev.ip for ev in resolved_events_map.values() if ev.ip}
        all_event_processes = {ev.process for ev in resolved_events_map.values() if ev.process}

        candidate_valid_users = set(all_event_users)
        if incident.user:
            candidate_valid_users.add(incident.user)

        candidate_valid_devices = set(all_event_devices)
        if incident.device:
            candidate_valid_devices.add(incident.device)

        # Check if optional attributes are missing from some events
        if any(ev.user is None for ev in resolved_events_map.values()) or any(ev.device is None for ev in resolved_events_map.values()):
            has_nullable_attr_gap = True

        # Specific event-level targeted claims
        if claims.claimed_event_ids:
            for target_eid in claims.claimed_event_ids:
                if target_eid in resolved_events_map:
                    ev = resolved_events_map[target_eid]
                    # User check
                    if claims.claimed_user is not None and ev.user is not None:
                        if claims.claimed_user.strip().lower() != ev.user.strip().lower():
                            discrepancies.append(
                                EventDiscrepancy(
                                    event_id=target_eid,
                                    mismatch_type=MismatchType.USER_MISMATCH,
                                    expected_value=claims.claimed_user,
                                    actual_value=ev.user,
                                    explanation=f"Event '{target_eid}' user '{ev.user}' does not match claimed user '{claims.claimed_user}'.",
                                )
                            )
                    # Device check
                    if claims.claimed_device is not None and ev.device is not None:
                        if claims.claimed_device.strip().lower() != ev.device.strip().lower():
                            discrepancies.append(
                                EventDiscrepancy(
                                    event_id=target_eid,
                                    mismatch_type=MismatchType.DEVICE_MISMATCH,
                                    expected_value=claims.claimed_device,
                                    actual_value=ev.device,
                                    explanation=f"Event '{target_eid}' device '{ev.device}' does not match claimed device '{claims.claimed_device}'.",
                                )
                            )
                    # IP check
                    if claims.claimed_ip is not None and ev.ip is not None:
                        if claims.claimed_ip.strip() != ev.ip.strip():
                            discrepancies.append(
                                EventDiscrepancy(
                                    event_id=target_eid,
                                    mismatch_type=MismatchType.IP_MISMATCH,
                                    expected_value=claims.claimed_ip,
                                    actual_value=ev.ip,
                                    explanation=f"Event '{target_eid}' IP '{ev.ip}' does not match claimed IP '{claims.claimed_ip}'.",
                                )
                            )
                    # Process check
                    if claims.claimed_process is not None and ev.process is not None:
                        if claims.claimed_process.strip().lower() != ev.process.strip().lower():
                            discrepancies.append(
                                EventDiscrepancy(
                                    event_id=target_eid,
                                    mismatch_type=MismatchType.PROCESS_MISMATCH,
                                    expected_value=claims.claimed_process,
                                    actual_value=ev.process,
                                    explanation=f"Event '{target_eid}' process '{ev.process}' does not match claimed process '{claims.claimed_process}'.",
                                )
                            )
        else:
            # Broad claims evaluated against full incident scope (multi-user aware)
            if claims.claimed_user is not None and candidate_valid_users:
                user_matches = {u.strip().lower() for u in candidate_valid_users}
                if claims.claimed_user.strip().lower() not in user_matches:
                    discrepancies.append(
                        EventDiscrepancy(
                            event_id=None,
                            mismatch_type=MismatchType.USER_MISMATCH,
                            expected_value=claims.claimed_user,
                            actual_value=", ".join(sorted(candidate_valid_users)),
                            explanation=(
                                f"Claimed user '{claims.claimed_user}' does not match incident user or "
                                f"any involved evidence event user: {sorted(candidate_valid_users)}."
                            ),
                        )
                    )

            if claims.claimed_device is not None and candidate_valid_devices:
                device_matches = {d.strip().lower() for d in candidate_valid_devices}
                if claims.claimed_device.strip().lower() not in device_matches:
                    discrepancies.append(
                        EventDiscrepancy(
                            event_id=None,
                            mismatch_type=MismatchType.DEVICE_MISMATCH,
                            expected_value=claims.claimed_device,
                            actual_value=", ".join(sorted(candidate_valid_devices)),
                            explanation=(
                                f"Claimed device '{claims.claimed_device}' does not match incident device or "
                                f"any involved evidence event device: {sorted(candidate_valid_devices)}."
                            ),
                        )
                    )

            if claims.claimed_ip is not None and all_event_ips:
                if claims.claimed_ip.strip() not in all_event_ips:
                    discrepancies.append(
                        EventDiscrepancy(
                            event_id=None,
                            mismatch_type=MismatchType.IP_MISMATCH,
                            expected_value=claims.claimed_ip,
                            actual_value=", ".join(sorted(all_event_ips)),
                            explanation=f"Claimed IP '{claims.claimed_ip}' does not match any evidence event IP: {sorted(all_event_ips)}.",
                        )
                    )

            if claims.claimed_process is not None and all_event_processes:
                proc_matches = {p.strip().lower() for p in all_event_processes}
                if claims.claimed_process.strip().lower() not in proc_matches:
                    discrepancies.append(
                        EventDiscrepancy(
                            event_id=None,
                            mismatch_type=MismatchType.PROCESS_MISMATCH,
                            expected_value=claims.claimed_process,
                            actual_value=", ".join(sorted(all_event_processes)),
                            explanation=f"Claimed process '{claims.claimed_process}' does not match any evidence event process: {sorted(all_event_processes)}.",
                        )
                    )

        # Claimed timestamp window checks
        if claims.claimed_start_time is not None and claims.claimed_end_time is not None:
            c_start = _ensure_utc(claims.claimed_start_time)
            c_end = _ensure_utc(claims.claimed_end_time)
            if c_start > c_end:
                discrepancies.append(
                    EventDiscrepancy(
                        event_id=None,
                        mismatch_type=MismatchType.TIMESTAMP_OUT_OF_BOUNDS,
                        expected_value=f"claimed_start <= claimed_end",
                        actual_value=f"start: {c_start.isoformat()} > end: {c_end.isoformat()}",
                        explanation="Claimed start time is chronologically later than claimed end time.",
                    )
                )
            if c_start < (inc_start - tolerance) or c_end > (inc_end + tolerance):
                discrepancies.append(
                    EventDiscrepancy(
                        event_id=None,
                        mismatch_type=MismatchType.TIMESTAMP_OUT_OF_BOUNDS,
                        expected_value=f"{inc_start.isoformat()} .. {inc_end.isoformat()}",
                        actual_value=f"{c_start.isoformat()} .. {c_end.isoformat()}",
                        explanation="Claimed time window exceeds incident boundaries.",
                    )
                )

    # 7. Identify Discrepancy-Free Verified Evidence IDs
    discrepant_event_ids = {d.event_id for d in discrepancies if d.event_id is not None}
    verified_evidence_ids = [
        eid for eid in resolved_events_map if eid not in discrepant_event_ids
    ]

    # 8. Deterministic Status Determination
    status = VerificationStatus.VERIFIED

    # Hard invalidation triggers -> UNVERIFIED
    if missing_evidence_ids:
        status = VerificationStatus.UNVERIFIED
        rationale.append(f"{len(missing_evidence_ids)} declared evidence event(s) not found in SQLite store.")

    if invalid_citation_ids:
        status = VerificationStatus.UNVERIFIED
        rationale.append(f"{len(invalid_citation_ids)} invalid or hallucinated citation(s) detected.")

    critical_discrepancies = [
        d for d in discrepancies
        if d.mismatch_type in (
            MismatchType.USER_MISMATCH,
            MismatchType.DEVICE_MISMATCH,
            MismatchType.IP_MISMATCH,
            MismatchType.PROCESS_MISMATCH,
            MismatchType.TIMESTAMP_OUT_OF_BOUNDS,
            MismatchType.CROSS_INCIDENT_CITATION,
            MismatchType.FABRICATED_CITATION,
            MismatchType.MISSING_EVIDENCE,
            MismatchType.EMPTY_EVIDENCE,
            MismatchType.DATABASE_ERROR,
        )
    ]
    if critical_discrepancies:
        status = VerificationStatus.UNVERIFIED
        rationale.append(f"{len(critical_discrepancies)} critical factual discrepancy/discrepancies detected.")

    # Soft partial triggers -> PARTIAL (only if not already UNVERIFIED)
    if status != VerificationStatus.UNVERIFIED:
        if citations_to_check and len(uncited_evidence_ids) > 0:
            status = VerificationStatus.PARTIAL
            rationale.append(
                f"All cited events verified, but citations cover {len(valid_citation_ids)} of {total_evidence_count} evidence events."
            )
        elif has_nullable_attr_gap:
            status = VerificationStatus.PARTIAL
            rationale.append("All evidence resolved; some optional attribute fields are null in telemetry.")
        else:
            rationale.append("All incident evidence events resolved from database and verified free of discrepancies.")

    if duplicate_citation_ids:
        rationale.append(f"{len(duplicate_citation_ids)} duplicate citation(s) safely deduplicated.")

    return EvidenceVerificationResult(
        incident_id=incident_id,
        status=status,
        total_evidence_count=total_evidence_count,
        resolved_evidence_count=len(resolved_events_map),
        missing_evidence_count=len(missing_evidence_ids),
        cited_evidence_count=cited_count,
        valid_citation_count=len(valid_citation_ids),
        verified_evidence_ids=verified_evidence_ids,
        uncited_evidence_ids=uncited_evidence_ids,
        missing_evidence_ids=missing_evidence_ids,
        invalid_citation_ids=invalid_citation_ids,
        duplicate_citation_ids=duplicate_citation_ids,
        discrepancies=discrepancies,
        verification_rationale=rationale,
        database_error=None,
    )
