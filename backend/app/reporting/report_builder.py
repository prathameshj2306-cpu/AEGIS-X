"""
Report Context Builder for AEGIS-X (Phase 3).

Assembles verified, structured report data contexts from existing incidents,
detections, and supporting normalized events.

Strict Architectural Guarantees:
1. Read-Only: Never modifies incidents, detections, events, or database records.
2. Deterministic Integrity: Preserves assigned severity, rationale, and rule findings.
3. Chronological Ordering: Sorts supporting timeline events strictly by UTC timestamp.
4. Evidence Traceability: Preserves all evidence event IDs and raw telemetry records.
5. Missing Data Transparency: Reconciles missing or unresolvable event/detection IDs
   explicitly without ever inventing synthetic data.
6. Clear Separation: Strictly demarcates deterministic system findings from AI-assisted
   narratives and notes when AI analysis was not executed.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from app.database.store import AegisDatabase
from app.reporting.models import (
    AIInvestigationSection,
    CategorizedRecommendations,
    DetectionFinding,
    EvidenceDiscrepancyItem,
    EvidenceInventory,
    EvidenceVerificationSection,
    ExecutiveSummary,
    IncidentOverview,
    IncidentReport,
    ReportHeader,
    SeverityAssessment,
    TimelineEvent,
    _ensure_utc,
)
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection, Incident


def _categorize_recommendations(actions: list[str]) -> CategorizedRecommendations:
    """Group flat recommendation strings into actionable SOC triage categories.

    Uses keyword matching to separate immediate containment, investigative steps,
    and remediation/hardening tasks.
    """
    containment_keywords = (
        "isolate", "terminate", "kill", "quarantine", "block",
        "lockout", "lock account", "disable account", "revoke"
    )
    investigation_keywords = (
        "investigate", "review", "audit", "verify", "inspect",
        "check", "analyze", "sweep", "collect", "dump", "examine"
    )
    remediation_keywords = (
        "reset", "mfa", "patch", "rotate", "harden", "remediate",
        "policy", "train", "update", "configure"
    )

    immediate_containment = []
    investigation_steps = []
    remediation_and_hardening = []

    for action in actions:
        act_clean = action.strip()
        if not act_clean:
            continue
        act_lower = act_clean.lower()
        if any(kw in act_lower for kw in containment_keywords):
            immediate_containment.append(act_clean)
        elif any(kw in act_lower for kw in investigation_keywords):
            investigation_steps.append(act_clean)
        elif any(kw in act_lower for kw in remediation_keywords):
            remediation_and_hardening.append(act_clean)
        else:
            remediation_and_hardening.append(act_clean)

    return CategorizedRecommendations(
        immediate_containment=immediate_containment,
        investigation_steps=investigation_steps,
        remediation_and_hardening=remediation_and_hardening,
    )


def _generate_fallback_recommendations(patterns: list[str]) -> list[str]:
    """Generate baseline recommendations when AI analysis is not present."""
    recs = []
    if "brute_force_login" in patterns:
        recs.append("Review authentication failure logs and investigate source IP addresses.")
        recs.append("Consider temporary account lockout or password reset with MFA enforcement.")
    if "unusual_login_time" in patterns:
        recs.append("Verify with account owner whether off-hours access was legitimate.")
        recs.append("Review surrounding access logs for anomalous activity.")
    if "privilege_escalation" in patterns:
        recs.append("Verify administrative authorization for elevated privileges.")
        recs.append("Audit privileged audit records and active sessions on the host.")
    if "suspicious_process" in patterns:
        recs.append("Investigate process execution details, parent process lineage, and command-line arguments.")
        recs.append("If malicious activity is confirmed, isolate host from network and terminate suspicious processes.")
    recs.append("Document triage findings and update incident status in the SOC investigation log.")
    return recs


def build_incident_report(
    incident: Incident,
    events: Optional[list[NormalizedEvent]] = None,
    detections: Optional[list[Detection]] = None,
    db: Optional[AegisDatabase] = None,
    report_title: Optional[str] = None,
) -> IncidentReport:
    """Assemble a validated IncidentReport data context from existing incident data.

    Args:
        incident: Correlated Incident instance with deterministic severity.
        events: Optional list of supporting NormalizedEvent instances.
        detections: Optional list of triggering Detection instances.
        db: Optional AegisDatabase connection used to resolve supporting records if omitted.
        report_title: Optional custom report title.

    Returns:
        Validated IncidentReport model ready for serialization or rendering.
    """
    # 1. Resolve Supporting Events
    resolved_events_map: dict[str, NormalizedEvent] = {}
    missing_event_ids: list[str] = []

    if events is not None:
        for ev in events:
            resolved_events_map[ev.event_id] = ev

    # If database is available, resolve any missing evidence IDs from SQLite
    for eid in incident.evidence_event_ids:
        if eid not in resolved_events_map:
            if db is not None:
                db_event = db.get_event(eid)
                if db_event is not None:
                    resolved_events_map[eid] = db_event
                else:
                    missing_event_ids.append(eid)
            else:
                missing_event_ids.append(eid)

    # Convert resolved events to timeline models and sort chronologically
    resolved_events = list(resolved_events_map.values())
    resolved_events.sort(key=lambda e: _ensure_utc(e.timestamp))

    timeline_items: list[TimelineEvent] = []
    for ev in resolved_events:
        timeline_items.append(
            TimelineEvent(
                event_id=ev.event_id,
                timestamp=_ensure_utc(ev.timestamp),
                event_type=ev.event_type,
                source=ev.source.value if hasattr(ev.source, "value") else str(ev.source),
                user=ev.user,
                device=ev.device,
                ip=ev.ip,
                process=ev.process,
                raw_data=dict(ev.raw_data) if ev.raw_data else {},
                is_primary_evidence=(ev.event_id in incident.evidence_event_ids),
            )
        )

    # 2. Resolve Grouped Detections
    resolved_detections_map: dict[str, Detection] = {}
    missing_detection_ids: list[str] = []

    if detections is not None:
        for det in detections:
            resolved_detections_map[det.detection_id] = det

    if db is not None and len(resolved_detections_map) < len(incident.detection_ids):
        all_db_detections = db.get_all_detections()
        for det in all_db_detections:
            if det.detection_id in incident.detection_ids:
                resolved_detections_map[det.detection_id] = det

    for did in incident.detection_ids:
        if did not in resolved_detections_map:
            missing_detection_ids.append(did)

    detection_findings: list[DetectionFinding] = []
    for did in incident.detection_ids:
        if did in resolved_detections_map:
            det = resolved_detections_map[did]
            detection_findings.append(
                DetectionFinding(
                    detection_id=det.detection_id,
                    rule_name=det.rule_name,
                    explanation=det.explanation,
                    timestamp=_ensure_utc(det.timestamp),
                    confidence=det.confidence,
                    user=det.user,
                    device=det.device,
                    triggering_event_ids=list(det.event_ids),
                    metadata=dict(det.metadata) if det.metadata else {},
                )
            )

    # 3. Time Calculations
    start_utc = _ensure_utc(incident.start_time)
    end_utc = _ensure_utc(incident.end_time)
    duration_seconds = max(0.0, (end_utc - start_utc).total_seconds())

    # 4. Process AI Investigation Context
    raw_ai = incident.ai_analysis
    has_ai = raw_ai is not None
    ai_status = incident.ai_status

    ai_summary: Optional[str] = None
    attack_interpretation: Optional[str] = None
    potential_impact: Optional[str] = None
    recommended_actions: list[str] = []
    cited_event_ids: list[str] = []
    uncited_evidence_ids: list[str] = []
    is_fallback = False
    ai_notes: Optional[str] = None

    if has_ai:
        if isinstance(raw_ai, dict):
            ai_summary = raw_ai.get("summary")
            attack_interpretation = raw_ai.get("attack_interpretation")
            potential_impact = raw_ai.get("potential_impact")
            recommended_actions = list(raw_ai.get("recommended_actions", []))
            cited_event_ids = list(raw_ai.get("cited_event_ids", []))
        elif hasattr(raw_ai, "summary"):
            ai_summary = getattr(raw_ai, "summary")
            attack_interpretation = getattr(raw_ai, "attack_interpretation")
            potential_impact = getattr(raw_ai, "potential_impact")
            recommended_actions = list(getattr(raw_ai, "recommended_actions", []))
            cited_event_ids = list(getattr(raw_ai, "cited_event_ids", []))

        is_fallback = ai_status in ("FALLBACK", "UNAVAILABLE")
        uncited_evidence_ids = [
            eid for eid in incident.evidence_event_ids if eid not in cited_event_ids
        ]
        if is_fallback:
            ai_notes = (
                f"SLM analysis operated in {ai_status} mode. Deterministic rule-grounded "
                "fallback explanation was utilized to ensure fail-safe availability."
            )
    else:
        ai_notes = (
            "AI investigation analysis was not executed for this incident. "
            "Report reflects deterministic detection rules and evidence correlation only."
        )
        # Use baseline recommendations when AI analysis is absent
        recommended_actions = _generate_fallback_recommendations(incident.detected_patterns)

    categorized_recs = _categorize_recommendations(recommended_actions)

    # 5. Assemble Sections
    batch_id = incident.batch_id
    source_filename = None
    if db is not None and batch_id:
        batch_record = db.get_batch(batch_id)
        if batch_record:
            source_filename = batch_record.get("filename")

    header = ReportHeader(
        report_title=report_title or f"Incident Investigation Report: {incident.incident_id}",
        incident_id=incident.incident_id,
        batch_id=batch_id,
        source_filename=source_filename,
    )

    user_str = incident.user or "Unknown"
    device_str = incident.device or "Unknown"
    patterns_str = ", ".join(incident.detected_patterns) if incident.detected_patterns else "unusual activity"

    exec_summary_text = (
        f"Incident {incident.incident_id} classified as {incident.severity.value}. "
        f"Identified {patterns_str} involving account '{user_str}' on host '{device_str}' "
        f"between {start_utc.strftime('%Y-%m-%d %H:%M:%S UTC')} and {end_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}."
    )

    executive_summary = ExecutiveSummary(
        incident_id=incident.incident_id,
        title=incident.title,
        severity=incident.severity.value,
        status=incident.status.value,
        summary_text=exec_summary_text,
        user=incident.user,
        device=incident.device,
        risk_score=incident.risk_score,
        potential_impact=potential_impact,
        batch_id=batch_id,
        source_filename=source_filename,
    )

    incident_overview = IncidentOverview(
        incident_id=incident.incident_id,
        start_time=start_utc,
        end_time=end_utc,
        duration_seconds=duration_seconds,
        primary_user=incident.user,
        primary_device=incident.device,
        detected_patterns=list(incident.detected_patterns),
        total_detections=len(incident.detection_ids),
        total_evidence_events=len(incident.evidence_event_ids),
    )

    severity_assessment = SeverityAssessment(
        severity=incident.severity.value,
        risk_score=incident.risk_score,
        severity_rationale=incident.severity_rationale,
        contributing_patterns=list(incident.detected_patterns),
    )

    ai_investigation = AIInvestigationSection(
        has_ai_analysis=has_ai,
        status=ai_status,
        model="qwen2.5:1.5b-instruct" if has_ai else None,
        summary=ai_summary,
        attack_interpretation=attack_interpretation,
        potential_impact=potential_impact,
        recommended_actions=recommended_actions,
        cited_event_ids=cited_event_ids,
        uncited_evidence_ids=uncited_evidence_ids,
        is_fallback=is_fallback,
        notes=ai_notes,
    )

    # 6. Evidence Verification Section
    raw_verification = incident.ai_verification
    if raw_verification and isinstance(raw_verification, dict):
        ver_status = raw_verification.get("status", "UNVERIFIED")
        # Map canonical VerificationStatus enum values
        if ver_status not in ("VERIFIED", "PARTIAL", "UNVERIFIED"):
            ver_status = "UNVERIFIED"

        # Build discrepancy items for the report
        disc_items = []
        for disc in raw_verification.get("discrepancies", []):
            if isinstance(disc, dict):
                disc_items.append(EvidenceDiscrepancyItem(
                    event_id=disc.get("event_id"),
                    mismatch_type=disc.get("mismatch_type", "UNKNOWN"),
                    expected_value=disc.get("expected_value"),
                    actual_value=disc.get("actual_value"),
                    explanation=disc.get("explanation", ""),
                ))

        rationale_list = raw_verification.get("verification_rationale", [])
        if not isinstance(rationale_list, list):
            rationale_list = []

        # Build a human-readable details string
        details_parts = [f"Evidence verification status: {ver_status}."]
        if rationale_list:
            details_parts.append(" ".join(str(r) for r in rationale_list))
        db_error = raw_verification.get("database_error")
        if db_error:
            details_parts.append(f"Database error: {db_error}")

        cited_count = raw_verification.get("cited_evidence_count", len(cited_event_ids))
        evidence_verification = EvidenceVerificationSection(
            verification_performed=True,
            status=ver_status,
            status_label=ver_status,
            is_verified=(ver_status == "VERIFIED"),
            verification_type="Deterministic Evidence Verification Engine",
            verification_rationale=rationale_list,
            total_evidence_count=raw_verification.get("total_evidence_count", len(incident.evidence_event_ids)),
            resolved_evidence_count=raw_verification.get("resolved_evidence_count", 0),
            missing_evidence_count=raw_verification.get("missing_evidence_count", 0),
            cited_evidence_count=cited_count,
            valid_citation_count=raw_verification.get("valid_citation_count", 0),
            ai_cited_count=cited_count,
            verified_evidence_ids=raw_verification.get("verified_evidence_ids", []),
            uncited_evidence_ids=raw_verification.get("uncited_evidence_ids", []),
            missing_evidence_ids=raw_verification.get("missing_evidence_ids", []),
            invalid_citation_ids=raw_verification.get("invalid_citation_ids", []),
            duplicate_citation_ids=raw_verification.get("duplicate_citation_ids", []),
            discrepancies=disc_items,
            database_error=db_error,
            details=" ".join(details_parts),
        )
    else:
        evidence_verification = EvidenceVerificationSection(
            verification_performed=False,
            status="NOT_AVAILABLE",
            status_label="PENDING_PHASE_2_CHECKPOINT_3",
            is_verified=False,
            verification_type="Citation Membership Validation Only",
            total_evidence_count=len(incident.evidence_event_ids),
            ai_cited_count=len(cited_event_ids),
            details=(
                "Evidence verification has not been performed for this incident. "
                "Phase 2 Checkpoint 3 (Evidence Verification Engine) is not yet implemented. "
                "AI-cited event IDs have been verified for incident evidence membership only."
            ),
        )

    evidence_inventory = EvidenceInventory(
        all_evidence_event_ids=list(incident.evidence_event_ids),
        resolved_event_count=len(resolved_events),
        missing_event_ids=missing_event_ids,
        detection_ids=list(incident.detection_ids),
        resolved_detection_count=len(detection_findings),
        missing_detection_ids=missing_detection_ids,
    )

    return IncidentReport(
        header=header,
        executive_summary=executive_summary,
        incident_overview=incident_overview,
        detection_findings=detection_findings,
        timeline=timeline_items,
        severity_assessment=severity_assessment,
        ai_investigation=ai_investigation,
        evidence_verification=evidence_verification,
        recommendations=categorized_recs,
        evidence_inventory=evidence_inventory,
    )


def build_incident_report_from_db(
    incident_id: str,
    db: AegisDatabase,
    report_title: Optional[str] = None,
) -> IncidentReport:
    """Retrieve an incident from SQLite database and assemble its complete report context.

    Args:
        incident_id: Unique incident ID to look up (e.g., 'INC000001').
        db: Active AegisDatabase connection.
        report_title: Optional custom report title.

    Returns:
        Assembled IncidentReport instance.

    Raises:
        ValueError: If incident_id does not exist in the database.
    """
    incident = db.get_incident(incident_id)
    if incident is None:
        raise ValueError(f"Incident with ID '{incident_id}' not found in database.")

    return build_incident_report(
        incident=incident,
        db=db,
        report_title=report_title,
    )
