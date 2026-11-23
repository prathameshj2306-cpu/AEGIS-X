"""
Detection rules for AEGIS-X.

Each rule is a pure function:
    Input:  list[NormalizedEvent], AegisConfig
    Output: list[Detection]

Rules never touch the database or network. They're deterministic given the
same input events and config — this makes them easy to test and audit.

Four rules implemented:
1. Brute-force login detection
2. Unusual login time detection
3. Privilege escalation detection
4. Suspicious process execution detection
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone, time as dt_time
from typing import Optional

from app.config import AegisConfig, AuthorizedSchedule
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection

# Module-level counter for detection IDs (reset per engine run)
_detection_counter: int = 0


def _next_detection_id() -> str:
    """Generate the next detection ID."""
    global _detection_counter
    _detection_counter += 1
    return f"D{_detection_counter:06d}"


def reset_detection_counter(start: int = 0) -> None:
    """Reset the detection ID counter. Call before each engine run."""
    global _detection_counter
    _detection_counter = start


# =============================================================================
# RULE 1: Brute-Force Login Detection
# =============================================================================

def detect_brute_force(
    events: list[NormalizedEvent],
    config: AegisConfig,
) -> list[Detection]:
    """Detect brute-force login attempts.

    Logic:
    - Group login_failure events by user.
    - Within each user's failures, find sliding windows of `window_minutes`
      that contain >= `threshold` failures.
    - 2-4 failures within the window must NOT trigger.
    - Device and IP are recorded as context but grouping is by user.

    Returns one Detection per user who exceeds the threshold.
    """
    threshold = config.brute_force.threshold
    window = timedelta(minutes=config.brute_force.window_minutes)
    detections: list[Detection] = []

    # Collect login failures grouped by user
    failures_by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "login_failure" and event.user:
            failures_by_user[event.user].append(event)

    for user, failures in failures_by_user.items():
        if len(failures) < threshold:
            continue  # Not enough failures total — can't reach threshold

        # Sort by timestamp
        failures.sort(key=lambda e: e.timestamp)

        # Sliding window: for each failure, count how many others fall
        # within [failure.timestamp, failure.timestamp + window]
        # Use two-pointer for efficiency.
        i = 0
        already_detected = False  # One detection per user per run

        for j in range(len(failures)):
            # Advance i to keep the window valid
            while failures[j].timestamp - failures[i].timestamp > window:
                i += 1

            window_count = j - i + 1
            if window_count >= threshold and not already_detected:
                # Collect all event IDs in this window
                window_events = failures[i:j + 1]
                event_ids = [e.event_id for e in window_events]
                devices = {e.device for e in window_events if e.device}
                ips = {e.ip for e in window_events if e.ip}

                detections.append(Detection(
                    detection_id=_next_detection_id(),
                    rule_name="brute_force_login",
                    explanation=(
                        f"User '{user}' had {window_count} failed login attempts "
                        f"within {config.brute_force.window_minutes} minutes "
                        f"(threshold: {threshold}). "
                        f"Devices: {', '.join(devices) if devices else 'unknown'}. "
                        f"IPs: {', '.join(ips) if ips else 'unknown'}."
                    ),
                    event_ids=event_ids,
                    timestamp=datetime.now(timezone.utc),
                    user=user,
                    device=next(iter(devices), None),
                    confidence="high",
                    metadata={
                        "failure_count": window_count,
                        "window_minutes": config.brute_force.window_minutes,
                        "devices": list(devices),
                        "ips": list(ips),
                        "first_failure": window_events[0].timestamp.isoformat(),
                        "last_failure": window_events[-1].timestamp.isoformat(),
                    },
                ))
                already_detected = True

    return detections


# =============================================================================
# RULE 2: Unusual Login Time Detection
# =============================================================================

def _parse_time(time_str: str) -> dt_time:
    """Parse HH:MM string to time object."""
    parts = time_str.strip().split(":")
    return dt_time(int(parts[0]), int(parts[1]))


def _is_within_schedule(
    event_dt: datetime,
    schedule: AuthorizedSchedule,
    default_tz_name: str,
) -> bool:
    """Check if an event timestamp falls within an authorized schedule.

    Args:
        event_dt: The event timestamp (UTC).
        schedule: An authorized schedule entry.
        default_tz_name: Fallback timezone if schedule.timezone is None.

    Returns:
        True if the event is within the authorized schedule.
    """
    try:
        import zoneinfo
        tz_name = schedule.timezone or default_tz_name
        tz = zoneinfo.ZoneInfo(tz_name)
    except (ImportError, KeyError):
        # If zoneinfo is unavailable or timezone is invalid, use UTC
        tz = timezone.utc

    # Convert event to the schedule's timezone
    local_dt = event_dt.astimezone(tz)

    # Check day of week
    day_names = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
    event_day = day_names[local_dt.weekday()]
    if event_day not in [d.upper() for d in schedule.days]:
        return False

    # Check time range
    start = _parse_time(schedule.start)
    end = _parse_time(schedule.end)
    event_time = local_dt.time()

    if start <= end:
        # Normal range: e.g., 08:00–20:00
        return start <= event_time <= end
    else:
        # Overnight range: e.g., 22:00–06:00
        return event_time >= start or event_time <= end


def detect_unusual_login_time(
    events: list[NormalizedEvent],
    config: AegisConfig,
) -> list[Detection]:
    """Detect logins outside normal working hours.

    Logic:
    - Check login_success events against the configured work hours.
    - For each login outside work hours, check authorized schedules.
    - If the user has an authorized schedule that covers the time, skip.
    - Otherwise, create a detection.

    Does not assume the machine timezone — uses config.work_hours.timezone.
    """
    detections: list[Detection] = []
    work_start = _parse_time(config.work_hours.start)
    work_end = _parse_time(config.work_hours.end)
    work_tz_name = config.work_hours.timezone

    try:
        import zoneinfo
        work_tz = zoneinfo.ZoneInfo(work_tz_name)
    except (ImportError, KeyError):
        work_tz = timezone.utc

    # Build lookup for authorized schedules by user
    schedules_by_user: dict[str, list[AuthorizedSchedule]] = defaultdict(list)
    for schedule in config.authorized_schedules:
        schedules_by_user[schedule.user.lower()].append(schedule)

    for event in events:
        if event.event_type != "login_success":
            continue

        # Convert to work timezone
        local_dt = event.timestamp.astimezone(work_tz)
        event_time = local_dt.time()

        # Check if within normal work hours
        is_normal = False
        if work_start <= work_end:
            is_normal = work_start <= event_time <= work_end
        else:
            is_normal = event_time >= work_start or event_time <= work_end

        if is_normal:
            continue

        # Check authorized schedules for this user
        user_key = (event.user or "").lower()
        if user_key and user_key in schedules_by_user:
            authorized = any(
                _is_within_schedule(event.timestamp, sched, work_tz_name)
                for sched in schedules_by_user[user_key]
            )
            if authorized:
                continue  # User is authorized for this time

        detections.append(Detection(
            detection_id=_next_detection_id(),
            rule_name="unusual_login_time",
            explanation=(
                f"User '{event.user or 'unknown'}' logged in at "
                f"{local_dt.strftime('%H:%M:%S %Z')} on {local_dt.strftime('%A')}, "
                f"outside normal hours ({config.work_hours.start}–{config.work_hours.end} "
                f"{work_tz_name}). No authorized schedule exception found."
            ),
            event_ids=[event.event_id],
            timestamp=datetime.now(timezone.utc),
            user=event.user,
            device=event.device,
            confidence="medium",
            metadata={
                "login_time_local": local_dt.isoformat(),
                "work_hours": f"{config.work_hours.start}-{config.work_hours.end}",
                "timezone": work_tz_name,
            },
        ))

    return detections


# =============================================================================
# RULE 3: Privilege Escalation Detection
# =============================================================================

def detect_privilege_escalation(
    events: list[NormalizedEvent],
    config: AegisConfig,
) -> list[Detection]:
    """Detect privilege escalation events.

    Logic:
    - Check each event's normalized event_type against the configured
      trigger_event_types list.
    - Each matching event generates a detection.

    These events are inherently notable because they change access levels.
    """
    trigger_types = set(config.privilege_escalation.trigger_event_types)
    detections: list[Detection] = []

    for event in events:
        if event.event_type in trigger_types:
            detections.append(Detection(
                detection_id=_next_detection_id(),
                rule_name="privilege_escalation",
                explanation=(
                    f"Privilege escalation detected: event type '{event.event_type}' "
                    f"for user '{event.user or 'unknown'}' on device "
                    f"'{event.device or 'unknown'}' at "
                    f"{event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}."
                ),
                event_ids=[event.event_id],
                timestamp=datetime.now(timezone.utc),
                user=event.user,
                device=event.device,
                confidence="high",
                metadata={
                    "event_type": event.event_type,
                    "ip": event.ip,
                },
            ))

    return detections


# =============================================================================
# RULE 4: Suspicious Process Execution Detection
# =============================================================================

def detect_suspicious_process(
    events: list[NormalizedEvent],
    config: AegisConfig,
) -> list[Detection]:
    """Detect suspicious process execution.

    Logic:
    - Check process_start events (and events with a process field).
    - Match process name against the suspicious process list.
    - Match command-line arguments against suspicious argument patterns.
    - Skip allowed processes and commands.
    - Not every PowerShell execution is malicious — only those with
      suspicious arguments trigger.

    Returns one Detection per suspicious event.
    """
    suspicious_procs = {p.lower() for p in config.suspicious_process.suspicious_processes}
    suspicious_args = [a.lower() for a in config.suspicious_process.suspicious_arguments]
    allowed_procs = {p.lower() for p in config.suspicious_process.allowed_processes}
    allowed_cmds = [c.lower() for c in config.suspicious_process.allowed_commands]

    detections: list[Detection] = []

    for event in events:
        # Only inspect events that have process information
        if not event.process:
            continue

        process_lower = event.process.lower().strip()

        # Check allowlists first
        if process_lower in allowed_procs:
            continue
        if any(cmd in process_lower for cmd in allowed_cmds if cmd):
            continue

        reasons: list[str] = []

        # Check 1: Process name matches suspicious list
        # Extract just the executable name from the full path/command
        process_parts = process_lower.replace("\\", "/").split("/")
        exe_name = process_parts[-1].split()[0] if process_parts else process_lower
        # Also check the full first token (might be just the exe name without path)
        first_token = process_lower.split()[0] if process_lower else ""
        first_token_name = first_token.replace("\\", "/").split("/")[-1]

        is_suspicious_proc = (
            exe_name in suspicious_procs or
            first_token_name in suspicious_procs
        )
        if is_suspicious_proc:
            reasons.append(f"Suspicious process: '{exe_name}'")

        # Check 2: Suspicious command-line arguments
        suspicious_arg_matches: list[str] = []
        for arg_pattern in suspicious_args:
            if arg_pattern in process_lower:
                suspicious_arg_matches.append(arg_pattern)

        if suspicious_arg_matches:
            reasons.append(
                f"Suspicious arguments detected: {', '.join(suspicious_arg_matches)}"
            )

        # Only create detection if there's actually something suspicious
        if not reasons:
            continue

        detections.append(Detection(
            detection_id=_next_detection_id(),
            rule_name="suspicious_process",
            explanation=(
                f"Suspicious process execution on device "
                f"'{event.device or 'unknown'}' by user "
                f"'{event.user or 'unknown'}': {'; '.join(reasons)}. "
                f"Full command: '{event.process}'."
            ),
            event_ids=[event.event_id],
            timestamp=datetime.now(timezone.utc),
            user=event.user,
            device=event.device,
            confidence="high" if is_suspicious_proc else "medium",
            metadata={
                "process": event.process,
                "reasons": reasons,
                "suspicious_args": suspicious_arg_matches,
                "ip": event.ip,
            },
        ))

    return detections
