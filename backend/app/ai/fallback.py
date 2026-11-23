"""
Deterministic fallback generator for AEGIS-X.

When Ollama is offline, unreachable, times out, or produces invalid/incomplete JSON,
this module generates robust, rule-grounded, schema-compliant explanations.

Crucial Guarantee:
Core incident triage, severity, and reporting NEVER depend on model availability.
"""

from datetime import datetime, timezone
from typing import Any
from app.ai.schemas import AIAnalysisOutput
from app.schemas.events import NormalizedEvent
from app.schemas.incidents import Incident, Detection


def _ensure_utc(dt: datetime) -> datetime:
    """Normalize datetime to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_deterministic_fallback(
    incident: Incident,
    events: list[NormalizedEvent] | None = None,
    detections: list[Detection] | None = None,
) -> AIAnalysisOutput:
    """Generate a high-quality deterministic incident explanation based on rule patterns.

    Args:
        incident: Correlated Incident instance.
        events: Optional list of supporting NormalizedEvent instances.
        detections: Optional list of triggering Detection instances.

    Returns:
        AIAnalysisOutput instance adhering to the rigid schema.
    """
    patterns = set(incident.detected_patterns)
    user = incident.user or "Unknown User"
    device = incident.device or "Unknown Device"
    severity = incident.severity.value

    # Build pattern-specific interpretation parts
    interpretations = []
    actions = []

    if "brute_force_login" in patterns:
        interpretations.append(
            f"Multiple repeated authentication failures were detected targeting account '{user}', "
            "consistent with potential credential guessing or brute-force attempts."
        )
        actions.extend([
            f"Review authentication failure logs and investigate source IP addresses associated with account '{user}'.",
            f"Consider protective controls for account '{user}', such as temporary account lockout or password reset with MFA enforcement.",
        ])

    if "unusual_login_time" in patterns:
        interpretations.append(
            f"Authentication for '{user}' occurred outside standard working hours, "
            "representing an anomalous access schedule that warrants verification with the account owner."
        )
        actions.extend([
            f"Verify with user '{user}' whether the off-hours access was legitimate.",
            f"Review surrounding authentication and access logs for anomalous activity during this time window.",
        ])

    if "privilege_escalation" in patterns:
        # Use evidence-grounded wording rather than premature claims of unauthorized escalation
        interpretations.append(
            f"Privilege escalation activity was detected involving account '{user}' (such as admin privileges granted or sudo elevation), "
            "which warrants verification of whether elevated access was authorized or indicates administrative privilege abuse."
        )
        actions.extend([
            f"Verify administrative authorization for elevated privileges assigned to '{user}'.",
            f"Audit privileged audit records and active sessions on device '{device}'.",
        ])

    if "suspicious_process" in patterns:
        interpretations.append(
            f"Execution of a suspicious command-line utility or process was detected on host '{device}', "
            "warranting investigation for potential credential access or remote execution activity."
        )
        actions.extend([
            f"Investigate process execution details, parent process lineage, and command-line arguments on host '{device}'.",
            f"Review endpoint activity surrounding the process execution window for signs of unauthorized actions.",
            f"If malicious activity is confirmed, isolate host '{device}' and terminate suspicious processes.",
        ])

    # If no specific recognized pattern matched
    if not interpretations:
        interpretations.append(
            f"Suspicious activity was identified across correlated events for user '{user}' on host '{device}'."
        )
        actions.append("Review relevant host and authentication logs for anomalous indicators.")

    # Always ensure baseline response actions exist
    actions.append("Document triage findings and update incident status in the SOC investigation log.")

    # Deduplicate actions while preserving order
    unique_actions = []
    for act in actions:
        if act not in unique_actions:
            unique_actions.append(act)

    # Executive summary with normalized UTC timestamps
    start_utc = _ensure_utc(incident.start_time)
    end_utc = _ensure_utc(incident.end_time)

    pattern_str = ", ".join(incident.detected_patterns) if incident.detected_patterns else "unusual activity"
    summary = (
        f"Deterministic security incident {incident.incident_id} classified as {severity}. "
        f"Identified {pattern_str} involving account '{user}' on device '{device}' between "
        f"{start_utc.strftime('%Y-%m-%d %H:%M:%S UTC')} and {end_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}."
    )

    # Impact assessment based on severity
    if severity == "CRITICAL":
        impact = (
            f"CRITICAL risk to enterprise confidentiality and system integrity. Correlated multi-stage indicators "
            f"involving account '{user}' on '{device}' warrant immediate investigation for potential system compromise."
        )
    elif severity == "HIGH":
        impact = (
            f"HIGH risk to administrative boundaries. Elevated privileges or correlated suspicious indicators "
            f"could allow unauthorized persistent access to '{device}' if malicious intent is verified."
        )
    elif severity == "MEDIUM":
        impact = (
            f"MEDIUM risk. Detected suspicious patterns (such as repeated authentication failures or unusual process execution) "
            f"pose a risk to credential security and host '{device}' integrity if unaddressed."
        )
    else:
        impact = (
            f"LOW risk. Isolated anomalous activity detected for '{user}'. Minimal immediate operational impact "
            "if credential integrity remains intact."
        )

    # Cited event IDs (strictly from supporting evidence records)
    cited_ids = list(incident.evidence_event_ids)

    return AIAnalysisOutput(
        summary=summary,
        attack_interpretation=" ".join(interpretations),
        potential_impact=impact,
        recommended_actions=unique_actions,
        cited_event_ids=cited_ids,
    )
