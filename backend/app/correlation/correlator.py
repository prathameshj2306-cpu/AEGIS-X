"""
Event correlation engine for AEGIS-X.

Takes detections and their associated events, groups them into incidents
based on shared user identity, device identity, and timestamp proximity.

Key design decisions:
- Correlation is by USER first, then by DEVICE within that user's detections.
- Detections for different users are NEVER merged, even if they share a device.
  (Reason: combining unrelated users into one incident creates false narratives.)
- Time window is configurable (default: 30 minutes).
- Each correlation group becomes one Incident.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.config import AegisConfig
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection, Incident, IncidentStatus


class CorrelationGroup:
    """An intermediate group of related detections before incident creation."""

    def __init__(self):
        self.detections: list[Detection] = []
        self.event_ids: set[str] = set()
        self.users: set[str] = set()
        self.devices: set[str] = set()
        self.min_time: datetime | None = None
        self.max_time: datetime | None = None

    def add_detection(self, detection: Detection, events_map: dict[str, NormalizedEvent]):
        """Add a detection to this group and update time bounds."""
        self.detections.append(detection)
        self.event_ids.update(detection.event_ids)

        if detection.user:
            self.users.add(detection.user)
        if detection.device:
            self.devices.add(detection.device)

        # Update time bounds from the actual events
        for eid in detection.event_ids:
            if eid in events_map:
                evt_time = events_map[eid].timestamp
                if self.min_time is None or evt_time < self.min_time:
                    self.min_time = evt_time
                if self.max_time is None or evt_time > self.max_time:
                    self.max_time = evt_time

    def overlaps_in_time(self, other: "CorrelationGroup", window: timedelta) -> bool:
        """Check if two groups overlap within the correlation window."""
        if self.min_time is None or other.min_time is None:
            return False
        if self.max_time is None or other.max_time is None:
            return False

        # Groups overlap if the gap between them is within the window
        gap = max(
            (other.min_time - self.max_time).total_seconds(),
            (self.min_time - other.max_time).total_seconds(),
        )
        return gap <= window.total_seconds()

    def shares_device(self, other: "CorrelationGroup") -> bool:
        """Check if two groups share any device."""
        return bool(self.devices & other.devices)

    def merge(self, other: "CorrelationGroup"):
        """Merge another group into this one."""
        self.detections.extend(other.detections)
        self.event_ids.update(other.event_ids)
        self.users.update(other.users)
        self.devices.update(other.devices)
        if other.min_time and (self.min_time is None or other.min_time < self.min_time):
            self.min_time = other.min_time
        if other.max_time and (self.max_time is None or other.max_time > self.max_time):
            self.max_time = other.max_time


def correlate_detections(
    detections: list[Detection],
    events: list[NormalizedEvent],
    config: AegisConfig | None = None,
) -> list[CorrelationGroup]:
    """Group detections into correlation groups.

    Algorithm:
    1. Group detections by user (primary key).
    2. Within each user's detections, create initial groups (one per detection).
    3. Merge groups that share a device AND overlap in time within the window.
    4. Return the final merged groups.

    Detections with no user form their own single-detection groups.
    """
    if config is None:
        config = AegisConfig()

    window = timedelta(minutes=config.correlation.window_minutes)

    # Build event lookup
    events_map: dict[str, NormalizedEvent] = {e.event_id: e for e in events}

    # Group detections by user
    detections_by_user: dict[str, list[Detection]] = defaultdict(list)
    no_user_detections: list[Detection] = []

    for detection in detections:
        if detection.user:
            detections_by_user[detection.user].append(detection)
        else:
            no_user_detections.append(detection)

    all_groups: list[CorrelationGroup] = []

    # Process each user's detections
    for user, user_detections in detections_by_user.items():
        # Start with one group per detection
        groups: list[CorrelationGroup] = []
        for det in user_detections:
            group = CorrelationGroup()
            group.add_detection(det, events_map)
            groups.append(group)

        # Merge groups that overlap in time and share a device (or same user is enough)
        # For same-user detections, time proximity alone justifies correlation
        merged = True
        while merged:
            merged = False
            new_groups: list[CorrelationGroup] = []
            used: set[int] = set()

            for i in range(len(groups)):
                if i in used:
                    continue
                current = groups[i]
                for j in range(i + 1, len(groups)):
                    if j in used:
                        continue
                    candidate = groups[j]
                    # Same user + within time window → merge
                    if current.overlaps_in_time(candidate, window):
                        current.merge(candidate)
                        used.add(j)
                        merged = True
                new_groups.append(current)
                used.add(i)

            groups = new_groups

        all_groups.extend(groups)

    # Detections with no user → each becomes its own group
    for det in no_user_detections:
        group = CorrelationGroup()
        group.add_detection(det, events_map)
        all_groups.append(group)

    return all_groups


def build_incidents(
    groups: list[CorrelationGroup],
    id_offset: int = 1,
    existing_incidents: list[Incident] | None = None,
) -> list[Incident]:
    """Convert correlation groups into Incident objects, reconciling with existing records.

    If existing_incidents is provided:
    1. Matches regenerated groups to existing incidents based on stable identity
       (user identity and evidence event ID membership).
    2. Preserves existing incident IDs where identity is unchanged.
    3. Preserves AI analysis, AI status, and AI verification ONLY if evidence remains unchanged.
    4. Invalidates AI analysis and verification if underlying evidence changed.
    5. Never transfers analysis/verification between different incidents.
    6. Assigns strictly non-colliding sequential IDs for newly added incidents.
    """
    if not existing_incidents:
        incidents: list[Incident] = []
        for i, group in enumerate(groups):
            incident_id = f"INC{(id_offset + i):06d}"
            primary_user = next(iter(group.users), None)
            primary_device = next(iter(group.devices), None)
            patterns = list({d.rule_name for d in group.detections})
            detection_ids = [d.detection_id for d in group.detections]
            title = _build_incident_title(patterns, primary_user)
            start_time = group.min_time or datetime.now(timezone.utc)
            end_time = group.max_time or start_time

            incidents.append(Incident(
                incident_id=incident_id,
                title=title,
                severity="LOW",
                status=IncidentStatus.OPEN,
                detected_patterns=patterns,
                user=primary_user,
                device=primary_device,
                start_time=start_time,
                end_time=end_time,
                evidence_event_ids=sorted(group.event_ids),
                detection_ids=detection_ids,
                severity_rationale="Pending classification",
                created_at=datetime.now(timezone.utc),
            ))
        return incidents

    # Reconcile against existing incidents
    incidents: list[Incident] = []
    claimed_existing_ids: set[str] = set()

    # Track maximum allocated incident ID number to generate safe non-colliding IDs for new groups
    max_num = id_offset - 1
    for inc in existing_incidents:
        if inc.incident_id.startswith("INC"):
            suffix = inc.incident_id[3:]
            if suffix.isdigit():
                max_num = max(max_num, int(suffix))

    for group in groups:
        group_eids = set(group.event_ids)
        group_users = set(group.users)
        primary_user = next(iter(group.users), None)
        primary_device = next(iter(group.devices), None)
        patterns = list({d.rule_name for d in group.detections})
        detection_ids = [d.detection_id for d in group.detections]
        title = _build_incident_title(patterns, primary_user)
        start_time = group.min_time or datetime.now(timezone.utc)
        end_time = group.max_time or start_time

        matched_incident: Incident | None = None
        evidence_unchanged = False

        # Phase 1: Look for exact evidence + user match
        for existing in existing_incidents:
            if existing.incident_id in claimed_existing_ids:
                continue
            existing_eids = set(existing.evidence_event_ids)
            user_match = (existing.user in group_users) or (not existing.user and not group_users)
            if user_match and existing_eids == group_eids:
                matched_incident = existing
                evidence_unchanged = True
                claimed_existing_ids.add(existing.incident_id)
                break

        # Phase 2: If no exact evidence match, look for overlapping evidence for the same user (evidence changed/expanded)
        if matched_incident is None:
            for existing in existing_incidents:
                if existing.incident_id in claimed_existing_ids:
                    continue
                existing_eids = set(existing.evidence_event_ids)
                user_match = (existing.user in group_users) or (not existing.user and not group_users)
                if user_match and bool(existing_eids & group_eids):
                    matched_incident = existing
                    evidence_unchanged = False
                    claimed_existing_ids.add(existing.incident_id)
                    break

        if matched_incident is not None:
            incident_id = matched_incident.incident_id
            created_at = matched_incident.created_at
            status = matched_incident.status
            if evidence_unchanged:
                # Evidence unchanged: preserve AI analysis and verification
                ai_analysis = matched_incident.ai_analysis
                ai_status = matched_incident.ai_status
                ai_verification = matched_incident.ai_verification
            else:
                # Evidence changed: invalidate stale analysis and verification
                ai_analysis = None
                ai_status = None
                ai_verification = None
        else:
            # New incident: allocate next monotonic sequential ID
            max_num += 1
            incident_id = f"INC{max_num:06d}"
            created_at = datetime.now(timezone.utc)
            status = IncidentStatus.OPEN
            ai_analysis = None
            ai_status = None
            ai_verification = None

        incidents.append(Incident(
            incident_id=incident_id,
            title=title,
            severity="LOW",
            status=status,
            detected_patterns=patterns,
            user=primary_user,
            device=primary_device,
            start_time=start_time,
            end_time=end_time,
            evidence_event_ids=sorted(group.event_ids),
            detection_ids=detection_ids,
            severity_rationale="Pending classification",
            created_at=created_at,
            ai_analysis=ai_analysis,
            ai_status=ai_status,
            ai_verification=ai_verification,
        ))

    return incidents


def _build_incident_title(patterns: list[str], user: str | None) -> str:
    """Generate a human-readable incident title from detection patterns."""
    pattern_labels = {
        "brute_force_login": "Brute-Force Login",
        "unusual_login_time": "Unusual Login Time",
        "privilege_escalation": "Privilege Escalation",
        "suspicious_process": "Suspicious Process Execution",
    }

    labels = [pattern_labels.get(p, p.replace("_", " ").title()) for p in sorted(patterns)]
    user_part = f" — {user}" if user else ""

    if len(labels) == 1:
        return f"{labels[0]}{user_part}"
    elif len(labels) == 2:
        return f"{labels[0]} + {labels[1]}{user_part}"
    else:
        return f"Multi-Stage Attack ({len(labels)} patterns){user_part}"
