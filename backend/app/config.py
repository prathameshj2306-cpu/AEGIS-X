"""
Central configuration for AEGIS-X detection engine.

All detection thresholds, schedules, and allowlists are configured here.
This keeps magic numbers out of detection code and makes tuning transparent.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BruteForceConfig:
    """Brute-force login detection parameters."""
    threshold: int = 5                  # Minimum failed attempts to trigger
    window_minutes: int = 10            # Time window for counting failures
    # Note: 2-4 failures within the window must NOT trigger this rule.


@dataclass
class WorkHoursConfig:
    """Normal working hours definition for unusual-login-time detection."""
    start: str = "08:00"                # HH:MM format
    end: str = "20:00"                  # HH:MM format
    timezone: str = "UTC"               # IANA timezone name


@dataclass
class AuthorizedSchedule:
    """An authorized login schedule exception for a specific user.

    Example: an admin authorized to work at any hour on weekdays would have:
        user="admin", days=["MON","TUE","WED","THU","FRI"],
        start="00:00", end="23:59", timezone="Asia/Kolkata"
    """
    user: str
    days: list[str]                     # MON, TUE, WED, THU, FRI, SAT, SUN
    start: str = "00:00"                # HH:MM
    end: str = "23:59"                  # HH:MM
    timezone: Optional[str] = None      # Defaults to work_hours timezone if None


@dataclass
class PrivilegeEscalationConfig:
    """Event types that indicate privilege escalation."""
    trigger_event_types: list[str] = field(default_factory=lambda: [
        "privilege_change",
        "privilege_escalation",
        "role_granted",
        "admin_privileges_granted",
        "sudo_elevation",
    ])


@dataclass
class SuspiciousProcessConfig:
    """Suspicious process detection configuration."""
    # Processes that are always suspicious
    suspicious_processes: list[str] = field(default_factory=lambda: [
        "mimikatz.exe",
        "mimikatz",
        "psexec.exe",
        "psexec",
        "procdump.exe",
        "procdump",
        "nc.exe",
        "nc",
        "netcat",
        "netcat.exe",
    ])

    # Command-line argument patterns that are suspicious
    suspicious_arguments: list[str] = field(default_factory=lambda: [
        "-enc",
        "-encodedcommand",
        "downloadstring",
        "invoke-expression",
        "iex(",
        "iex ",
        "frombase64string",
        "net user /add",
        "net localgroup administrators",
    ])

    # Processes that are allowed even if they match patterns above
    allowed_processes: list[str] = field(default_factory=lambda: [
        # e.g., "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        # Add specific allowed paths or names here
    ])

    # Allowed command-line patterns (won't trigger even if args match)
    allowed_commands: list[str] = field(default_factory=lambda: [
        # e.g., "Get-Process", "Get-Service" — normal admin commands
    ])


@dataclass
class CorrelationConfig:
    """Event correlation parameters."""
    window_minutes: int = 30            # Max time gap between correlated events


@dataclass
class SeverityConfig:
    """Severity classification thresholds.

    Severity is assigned by deterministic rules:
    - CRITICAL: Multi-stage attack chain (e.g., brute_force + priv_escalation + suspicious_process)
    - HIGH: Privilege escalation with suspicious access, or 2+ serious correlated detections
    - MEDIUM: Confirmed brute-force threshold, or suspicious process execution
    - LOW: Isolated unusual login time, or single low-confidence indicator
    """
    # Minimum distinct detection types for CRITICAL
    critical_min_detection_types: int = 3
    # Minimum distinct detection types for HIGH
    high_min_detection_types: int = 2
    # These rule names are considered "serious" for escalation
    serious_rules: list[str] = field(default_factory=lambda: [
        "brute_force_login",
        "privilege_escalation",
        "suspicious_process",
    ])


@dataclass
class AegisConfig:
    """Top-level configuration container for the AEGIS-X engine."""
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    work_hours: WorkHoursConfig = field(default_factory=WorkHoursConfig)
    authorized_schedules: list[AuthorizedSchedule] = field(default_factory=list)
    privilege_escalation: PrivilegeEscalationConfig = field(
        default_factory=PrivilegeEscalationConfig
    )
    suspicious_process: SuspiciousProcessConfig = field(
        default_factory=SuspiciousProcessConfig
    )
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    severity: SeverityConfig = field(default_factory=SeverityConfig)

    # Ollama settings (used in Phase 2+)
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:1.5b-instruct"
    ollama_timeout: int = 60

    # Upload limits
    max_upload_size_mb: int = 10
