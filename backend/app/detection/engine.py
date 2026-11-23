"""
Detection engine — orchestrates all detection rules.

The engine:
1. Resets the detection ID counter.
2. Runs all four rules against the normalized events.
3. Returns the combined list of Detections.

This is the single entry point for the detection subsystem.
Downstream modules (correlation, severity) consume its output.
"""

from app.config import AegisConfig
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Detection
from app.detection.rules import (
    detect_brute_force,
    detect_unusual_login_time,
    detect_privilege_escalation,
    detect_suspicious_process,
    reset_detection_counter,
)


def run_detection(
    events: list[NormalizedEvent],
    config: AegisConfig | None = None,
) -> list[Detection]:
    """Run all detection rules against normalized events.

    Args:
        events: List of normalized security events.
        config: Engine configuration. Uses defaults if None.

    Returns:
        Combined list of all detections from all rules.
    """
    if config is None:
        config = AegisConfig()

    # Reset counter so detection IDs are deterministic per run
    reset_detection_counter(0)

    detections: list[Detection] = []

    # Rule 1: Brute-force login detection
    detections.extend(detect_brute_force(events, config))

    # Rule 2: Unusual login time detection
    detections.extend(detect_unusual_login_time(events, config))

    # Rule 3: Privilege escalation detection
    detections.extend(detect_privilege_escalation(events, config))

    # Rule 4: Suspicious process execution detection
    detections.extend(detect_suspicious_process(events, config))

    return detections
