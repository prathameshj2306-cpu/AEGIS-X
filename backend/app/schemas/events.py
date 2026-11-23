"""
Normalized event schema — the core data contract for AEGIS-X.

Every ingested log line (CSV row or JSON object) is validated and normalized
into a NormalizedEvent. This is the single source of truth that all downstream
modules (detection, correlation, severity) operate on.

Key design decisions:
- event_id is a stable string (E000001) assigned during ingestion.
- timestamp is always stored as UTC datetime for consistent time-window math.
- user, device, ip, process are nullable — not all log sources have all fields.
- event_type is normalized to a controlled vocabulary.
- source tracks whether the log came from auth or endpoint data.
- raw_data preserves the original record for evidence traceability.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EventSource(str, Enum):
    """Where the event originated."""
    AUTHENTICATION = "authentication"
    ENDPOINT = "endpoint"


class NormalizedEvent(BaseModel):
    """A single security event, normalized to the AEGIS-X schema.

    Fields:
        event_id: Stable unique identifier, e.g. "E000001".
        timestamp: UTC datetime from the original log.
        user: Username/identity, if available.
        device: Device/hostname, if available.
        ip: IP address, if available.
        event_type: Normalized event type (e.g., "login_success", "privilege_escalation").
        process: Process name or command line, if available.
        source: Whether this came from authentication or endpoint logs.
        raw_data: Original log record preserved for evidence.
    """
    event_id: str = Field(..., description="Stable unique ID, e.g. E000001")
    timestamp: datetime = Field(..., description="UTC-normalized timestamp")
    user: Optional[str] = Field(None, description="User identity")
    device: Optional[str] = Field(None, description="Device or hostname")
    ip: Optional[str] = Field(None, description="Source IP address")
    event_type: str = Field(..., description="Normalized event type")
    process: Optional[str] = Field(None, description="Process name or command line")
    source: EventSource = Field(..., description="Log source category")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Original log record for evidence traceability"
    )

    model_config = {"frozen": False, "extra": "forbid"}


# --- Controlled vocabulary for event_type ---
# These are the normalized types the detection engine understands.
# Ingestion maps raw log values to these.

KNOWN_EVENT_TYPES: set[str] = {
    # Authentication events
    "login_success",
    "login_failure",
    "logout",
    "password_change",
    "mfa_success",
    "mfa_failure",
    "account_lockout",

    # Privilege events
    "privilege_change",
    "privilege_escalation",
    "role_granted",
    "admin_privileges_granted",
    "sudo_elevation",

    # Endpoint / process events
    "process_start",
    "process_stop",
    "file_access",
    "file_modify",
    "network_connection",
    "service_start",
    "service_stop",
    "registry_modify",

    # Generic
    "other",
}

# --- Mapping from common raw log values to normalized event_type ---
# Ingestion uses this to handle alternative column names and values.

EVENT_TYPE_MAPPINGS: dict[str, str] = {
    # Login variants
    "login_success": "login_success",
    "logon_success": "login_success",
    "successful_login": "login_success",
    "authentication_success": "login_success",
    "login_ok": "login_success",
    "logon": "login_success",

    "login_failure": "login_failure",
    "logon_failure": "login_failure",
    "failed_login": "login_failure",
    "authentication_failure": "login_failure",
    "login_failed": "login_failure",
    "invalid_password": "login_failure",
    "bad_password": "login_failure",

    "logout": "logout",
    "logoff": "logout",
    "session_end": "logout",

    "password_change": "password_change",
    "password_reset": "password_change",

    "mfa_success": "mfa_success",
    "mfa_failure": "mfa_failure",
    "mfa_failed": "mfa_failure",

    "account_lockout": "account_lockout",
    "account_locked": "account_lockout",

    # Privilege variants
    "privilege_change": "privilege_change",
    "privilege_escalation": "privilege_escalation",
    "priv_esc": "privilege_escalation",
    "role_granted": "role_granted",
    "role_assigned": "role_granted",
    "admin_privileges_granted": "admin_privileges_granted",
    "admin_grant": "admin_privileges_granted",
    "sudo_elevation": "sudo_elevation",
    "sudo": "sudo_elevation",
    "runas": "sudo_elevation",

    # Process variants
    "process_start": "process_start",
    "process_created": "process_start",
    "process_create": "process_start",
    "process_execution": "process_start",
    "process_stop": "process_stop",
    "process_terminated": "process_stop",

    # File variants
    "file_access": "file_access",
    "file_read": "file_access",
    "file_modify": "file_modify",
    "file_write": "file_modify",
    "file_delete": "file_modify",

    # Network variants
    "network_connection": "network_connection",
    "network_connect": "network_connection",
    "outbound_connection": "network_connection",

    # Service variants
    "service_start": "service_start",
    "service_started": "service_start",
    "service_stop": "service_stop",
    "service_stopped": "service_stop",

    # Registry
    "registry_modify": "registry_modify",
    "registry_change": "registry_modify",
}
