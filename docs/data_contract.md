# AEGIS-X Data Contract

This document defines the data structures shared across the entire AEGIS-X pipeline.
Frontend and backend implementations must conform to these schemas.

## Normalized Event Schema

Every ingested log line is normalized to this format before analysis.

| Field | Type | Required | Description |
|---|---|---|---|
| `event_id` | string | Yes | Stable unique ID, e.g. `E000001` |
| `timestamp` | datetime (ISO 8601) | Yes | UTC-normalized timestamp |
| `user` | string \| null | No | User identity |
| `device` | string \| null | No | Device or hostname |
| `ip` | string \| null | No | Source IP address |
| `event_type` | string | Yes | Normalized event type (controlled vocabulary) |
| `process` | string \| null | No | Process name or command line |
| `source` | enum | Yes | `authentication` or `endpoint` |
| `raw_data` | object | Yes | Original log record preserved for evidence |

### Controlled Event Types

**Authentication:** `login_success`, `login_failure`, `logout`, `password_change`, `mfa_success`, `mfa_failure`, `account_lockout`

**Privilege:** `privilege_change`, `privilege_escalation`, `role_granted`, `admin_privileges_granted`, `sudo_elevation`

**Endpoint:** `process_start`, `process_stop`, `file_access`, `file_modify`, `network_connection`, `service_start`, `service_stop`, `registry_modify`

**Fallback:** `other`

Ingestion maps alternative values (e.g., `logon_failure` → `login_failure`) automatically.

## Detection Schema

| Field | Type | Description |
|---|---|---|
| `detection_id` | string | Unique ID, e.g. `D000001` |
| `rule_name` | string | Rule that triggered |
| `explanation` | string | Human-readable description |
| `event_ids` | string[] | Triggering event IDs |
| `timestamp` | datetime | Detection creation time (UTC) |
| `user` | string \| null | User involved |
| `device` | string \| null | Device involved |
| `confidence` | string | Confidence or rationale tag |
| `metadata` | object | Additional context |

## Incident Schema

| Field | Type | Description |
|---|---|---|
| `incident_id` | string | Unique ID, e.g. `INC000001` |
| `title` | string | Short incident title |
| `severity` | enum | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `status` | enum | `OPEN`, `UNDER_REVIEW`, `CLOSED` |
| `detected_patterns` | string[] | Rule names involved |
| `user` | string \| null | Primary user |
| `device` | string \| null | Primary device |
| `start_time` | datetime | Earliest event time |
| `end_time` | datetime | Latest event time |
| `evidence_event_ids` | string[] | All supporting event IDs |
| `detection_ids` | string[] | All grouped detection IDs |
| `risk_score` | float \| null | Optional risk score (0–100) |
| `severity_rationale` | string | Why this severity was assigned |
| `created_at` | datetime | Incident creation time (UTC) |
| `ai_analysis` | object \| null | SLM analysis (Phase 2+) |
| `ai_status` | string \| null | `SUCCESS`, `FALLBACK`, `UNAVAILABLE` |
| `ai_verification` | object \| null | Evidence verification results |

## Severity Rules

| Severity | Criteria |
|---|---|
| **CRITICAL** | Multi-stage attack chain: 3+ distinct serious detection types (e.g., brute_force + privilege_escalation + suspicious_process) |
| **HIGH** | 2+ serious correlated detections, or privilege escalation with suspicious access |
| **MEDIUM** | Confirmed brute-force threshold, or suspicious process execution |
| **LOW** | Isolated unusual login time, or single low-confidence indicator |

> **The SLM never modifies severity.** Severity is always deterministic.
