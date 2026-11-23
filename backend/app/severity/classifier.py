"""
Deterministic severity classifier for AEGIS-X.

Assigns severity to incidents based on the number and type of detections.
The SLM never modifies severity — this module has the final word.

Severity levels:
- CRITICAL: Multi-stage attack chain with 3+ distinct serious detection types.
- HIGH: 2+ serious correlated detections, or privilege escalation with other activity.
- MEDIUM: Confirmed brute-force, or suspicious process execution.
- LOW: Isolated unusual login time, or single low-confidence indicator.

Each incident gets a human-readable severity_rationale explaining the assignment.
"""

from app.config import AegisConfig
from app.schemas.incidents import Incident, Severity


def classify_severity(
    incident: Incident,
    config: AegisConfig | None = None,
) -> Incident:
    """Assign severity and rationale to an incident.

    Args:
        incident: The incident to classify (modified in place and returned).
        config: Configuration with severity thresholds.

    Returns:
        The same incident with severity and severity_rationale set.
    """
    if config is None:
        config = AegisConfig()

    patterns = set(incident.detected_patterns)
    serious_rules = set(config.severity.serious_rules)

    # Count how many distinct SERIOUS patterns are in this incident
    serious_count = len(patterns & serious_rules)
    total_count = len(patterns)

    # --- CRITICAL ---
    # Multi-stage attack chain: 3+ distinct serious detection types
    if serious_count >= config.severity.critical_min_detection_types:
        incident.severity = Severity.CRITICAL
        matched = sorted(patterns & serious_rules)
        incident.severity_rationale = (
            f"CRITICAL: Multi-stage attack chain detected with {serious_count} "
            f"serious detection types: {', '.join(matched)}. "
            f"This combination indicates a coordinated attack sequence."
        )
        incident.risk_score = min(95.0, 70.0 + serious_count * 10)
        return incident

    # --- HIGH ---
    # 2+ serious correlated detections
    if serious_count >= config.severity.high_min_detection_types:
        incident.severity = Severity.HIGH
        matched = sorted(patterns & serious_rules)
        incident.severity_rationale = (
            f"HIGH: {serious_count} serious detection types correlated: "
            f"{', '.join(matched)}. "
            f"Multiple high-risk indicators suggest a significant security event."
        )
        incident.risk_score = min(85.0, 55.0 + serious_count * 15)
        return incident

    # --- MEDIUM ---
    # Single serious detection (brute_force or suspicious_process)
    if serious_count == 1:
        matched_rule = next(iter(patterns & serious_rules))
        rule_descriptions = {
            "brute_force_login": "Confirmed brute-force login attempt exceeding threshold",
            "privilege_escalation": "Privilege escalation activity detected",
            "suspicious_process": "Suspicious process execution detected",
        }
        desc = rule_descriptions.get(matched_rule, matched_rule)
        incident.severity = Severity.MEDIUM
        incident.severity_rationale = (
            f"MEDIUM: {desc}. "
            f"Single serious indicator requires investigation but no correlated attack chain."
        )
        incident.risk_score = 45.0
        return incident

    # --- LOW ---
    # Only non-serious detections (e.g., unusual_login_time)
    incident.severity = Severity.LOW
    incident.severity_rationale = (
        f"LOW: Detected patterns ({', '.join(sorted(patterns))}) are low-risk indicators. "
        f"May warrant monitoring but do not indicate an active attack."
    )
    incident.risk_score = 20.0
    return incident


def classify_all(
    incidents: list[Incident],
    config: AegisConfig | None = None,
) -> list[Incident]:
    """Classify severity for all incidents.

    Args:
        incidents: List of incidents to classify.
        config: Configuration.

    Returns:
        The same list with severity assigned to each incident.
    """
    if config is None:
        config = AegisConfig()

    for incident in incidents:
        classify_severity(incident, config)

    return incidents
