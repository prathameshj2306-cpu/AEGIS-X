"""
Evaluation Framework for AEGIS-X.

Evaluates the threat detection engine against synthetic scenarios at the
scenario level (not by treating each raw log line as an independent incident).

Computes:
- True Positives (TP)
- False Positives (FP)
- False Negatives (FN)
- True Negatives (TN)
- Precision, Recall, F1 Score, and False Positive Rate (FPR)
With safe zero-denominator handling and fail-closed association validation.

INTEGRITY & ASSOCIATION PRINCIPLES:
1. Evaluates against pre-generated benchmark datasets (e.g. data/evaluation/).
2. Never mutates, regenerates, or overwrites dataset files.
3. Strict explicit event-ID resolution: detects missing, duplicate, or cross-assigned IDs.
4. Strict UTC-aware timestamp validation: normalizes aware timestamps, rejects naive timestamps,
   validates start_time <= end_time, and verifies declared user windows do not overlap.
5. Fails closed: association errors cause validation to fail, marking association_integrity="FAILED".
   Unassociated scenarios are never counted in TP/FP/FN/TN.
"""

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import AegisConfig, AuthorizedSchedule
from app.detection.engine import run_detection
from app.ingestion.ingestor import ingest_csv, ingest_json
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Detection


# =============================================================================
# AUDITED SCENARIO TIME-BOUNDS FOR PRE-EXISTING BENCHMARK DATASETS
# =============================================================================

EVALUATION_SCENARIO_BOUNDS: dict[str, tuple[str, str, str]] = {
    # scenario_id: (user, start_time_iso, end_time_iso)
    "S001_MAL_BF_001": ("bob", "2024-11-21T09:26:26+00:00", "2024-11-21T09:31:26+00:00"),
    "S002_MAL_BFS_001": ("admin", "2024-11-20T15:05:28+00:00", "2024-11-20T15:09:28+00:00"),
    "S003_MAL_PE_001": ("charlie", "2024-11-18T11:44:26+00:00", "2024-11-18T11:52:26+00:00"),
    "S004_MAL_SP_001": ("admin", "2024-11-18T13:30:58+00:00", "2024-11-18T13:38:58+00:00"),
    "S005_MAL_MSA_001": ("bob", "2024-11-22T09:20:55+00:00", "2024-11-22T09:32:55+00:00"),
    "S006_BEN_FP_001": ("operator_lee", "2024-11-20T14:20:58+00:00", "2024-11-20T14:21:58+00:00"),
    "S007_BEN_NL_001": ("admin", "2024-11-19T02:00:00+00:00", "2024-11-19T02:00:00+00:00"),
    "S008_BEN_PS_001": ("developer1", "2024-11-21T14:58:10+00:00", "2024-11-21T15:03:10+00:00"),
    "S009_BEN_SF_001": ("alice", "2024-11-19T15:18:15+00:00", "2024-11-19T15:18:45+00:00"),
    "S010_BEN_NA_001": ("developer1", "2024-11-19T08:04:54+00:00", "2024-11-19T15:04:54+00:00"),
}

DEVELOPMENT_SCENARIO_BOUNDS: dict[str, tuple[str, str, str]] = {
    "S001_MAL_BF_001": ("alice", "2024-11-19T11:08:47+00:00", "2024-11-19T11:12:35+00:00"),
    "S002_MAL_BFS_001": ("admin", "2024-11-18T11:14:32+00:00", "2024-11-18T11:18:32+00:00"),
    "S003_MAL_PE_001": ("admin", "2024-11-22T12:51:55+00:00", "2024-11-22T12:55:55+00:00"),
    "S004_MAL_SP_001": ("admin", "2024-11-19T11:48:21+00:00", "2024-11-19T11:54:21+00:00"),
    "S005_MAL_MSA_001": ("bob", "2024-11-20T17:16:51+00:00", "2024-11-20T17:28:51+00:00"),
    "S006_BEN_FP_001": ("bob", "2024-11-22T11:45:04+00:00", "2024-11-22T11:46:04+00:00"),
    "S007_BEN_NL_001": ("admin", "2024-11-19T02:00:00+00:00", "2024-11-19T02:00:00+00:00"),
    "S008_BEN_PS_001": ("admin", "2024-11-20T15:40:53+00:00", "2024-11-20T15:45:53+00:00"),
    "S009_BEN_SF_001": ("developer1", "2024-11-20T11:42:17+00:00", "2024-11-20T11:42:47+00:00"),
    "S010_BEN_NA_001": ("svc_backup", "2024-11-19T15:24:17+00:00", "2024-11-19T22:24:17+00:00"),
}


class AssociationValidationError(Exception):
    """Raised when scenario-to-event association validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Scenario association validation failed with {len(errors)} error(s): " + "; ".join(errors))


@dataclass
class ScenarioEvaluationResult:
    """Evaluation outcome for a single scenario."""
    scenario_id: str
    name: str
    is_malicious: bool
    expected_rules: list[str]
    triggered_rules: list[str]
    classification: str  # "TP", "FP", "FN", "TN", "UNASSOCIATED"
    matched_events_count: int
    rule_coverage: float  # Fraction of expected rules that were triggered
    description: str
    association_notes: str = ""


@dataclass
class EvaluationMetrics:
    """Aggregate metrics with safe zero-denominator handling and validation status."""
    total_scenarios: int
    evaluated_scenarios: int
    unassociated_scenarios: int
    malicious_scenarios: int
    benign_scenarios: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    accuracy: float
    association_integrity: str  # "PASSED" or "FAILED"
    validation_errors: list[str] = field(default_factory=list)
    evaluated_at: str = ""
    dataset_name: str = ""
    data_dir: str = ""
    scenario_results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def calculate_metrics(
    tp: int, fp: int, fn: int, tn: int,
    total_scenarios: int,
    unassociated_scenarios: int = 0,
    validation_errors: list[str] | None = None,
    dataset_name: str = "evaluation",
    data_dir: str = "",
    scenario_results: list[ScenarioEvaluationResult] | None = None,
) -> EvaluationMetrics:
    """Calculate aggregate classification metrics with safe zero-denominator handling.

    Mathematical formulas:
        Precision = TP / (TP + FP)  -> 0.0 if TP + FP == 0
        Recall    = TP / (TP + FN)  -> 0.0 if TP + FN == 0
        F1        = 2 * (P * R) / (P + R) -> 0.0 if P + R == 0
        FPR       = FP / (FP + TN)  -> 0.0 if FP + TN == 0
        Accuracy  = (TP + TN) / EvaluatedTotal -> 0.0 if EvaluatedTotal == 0

    If validation_errors exist, association_integrity is strictly 'FAILED'.
    """
    evaluated = tp + fp + fn + tn
    malicious = tp + fn
    benign = fp + tn
    val_errors = validation_errors or []

    precision = float(tp) / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = float(tp) / (tp + fn) if (tp + fn) > 0 else 0.0
    
    if (precision + recall) > 0.0:
        f1_score = 2.0 * (precision * recall) / (precision + recall)
    else:
        f1_score = 0.0

    false_positive_rate = float(fp) / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = float(tp + tn) / evaluated if evaluated > 0 else 0.0

    raw_results = [asdict(r) for r in (scenario_results or [])]
    
    # Strict integrity status: must have zero validation errors, zero unassociated scenarios, and total > 0
    if not val_errors and unassociated_scenarios == 0 and total_scenarios > 0:
        integrity_status = "PASSED"
    else:
        integrity_status = "FAILED"

    return EvaluationMetrics(
        total_scenarios=total_scenarios,
        evaluated_scenarios=evaluated,
        unassociated_scenarios=unassociated_scenarios,
        malicious_scenarios=malicious,
        benign_scenarios=benign,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1_score, 4),
        false_positive_rate=round(false_positive_rate, 4),
        accuracy=round(accuracy, 4),
        association_integrity=integrity_status,
        validation_errors=val_errors,
        evaluated_at=datetime.now(timezone.utc).isoformat(),
        dataset_name=dataset_name,
        data_dir=data_dir,
        scenario_results=raw_results,
    )


def _is_timezone_aware(dt: datetime) -> bool:
    """Check if a datetime object is strictly timezone-aware.

    Requires dt.tzinfo is not None and dt.utcoffset() is not None.
    """
    if dt is None:
        return False
    return dt.tzinfo is not None and dt.utcoffset() is not None


def _parse_and_validate_utc_dt(value: Any, field_name: str, scenario_id: str) -> datetime:
    """Parse a timestamp string, reject naive timestamps, and normalize aware timestamps to UTC."""
    if isinstance(value, datetime):
        if not _is_timezone_aware(value):
            raise ValueError(f"Scenario '{scenario_id}': {field_name} '{value}' is a naive datetime (tzinfo or utcoffset is None; must be UTC-aware).")
        return value.astimezone(timezone.utc)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Scenario '{scenario_id}': {field_name} is empty or not a string.")

    v = value.strip()
    # Reject strings without explicit timezone offsets (+, -, Z)
    if not (v.endswith("Z") or v.endswith("z") or "+" in v[10:] or "-" in v[10:]):
        raise ValueError(f"Scenario '{scenario_id}': {field_name} '{value}' lacks a timezone offset (naive timestamps are rejected).")

    dt = datetime.fromisoformat(v)
    if not _is_timezone_aware(dt):
        raise ValueError(f"Scenario '{scenario_id}': {field_name} '{value}' parsed as naive datetime (tzinfo or utcoffset is None).")
    return dt.astimezone(timezone.utc)


def match_scenario_events(
    scenarios: list[dict[str, Any]],
    events: list[NormalizedEvent],
    dataset_name: str = "evaluation",
    custom_bounds: Optional[dict[str, tuple[str, str, str]]] = None,
) -> tuple[dict[str, list[NormalizedEvent]], dict[str, str], list[str]]:
    """Associate normalized events with their respective scenarios strictly and explicitly.

    Resolution order:
    1. Explicit event IDs: if scenario dict contains `event_ids`.
       - Validates event_ids structure (list of non-empty strings).
       - Validates that every ID exists.
       - Validates no duplicates within scenario.
       - Validates no ID was already assigned to another scenario.
       - Validates matched events against declared structured bounds, OR audited bounds if available.
    2. Structured scenario metadata: if scenario contains `user`, `start_time`, `end_time`.
       - Rejects partial or invalid metadata.
    3. Custom or audited ground-truth time boundaries (allowed ONLY if all three structured metadata keys are genuinely absent).

    Returns:
        tuple of (scenario_to_events_dict, scenario_notes_dict, matching_errors_list)
    """
    scenario_events: dict[str, list[NormalizedEvent]] = {}
    scenario_notes: dict[str, str] = {}
    matching_errors: list[str] = []
    assigned_event_ids: dict[str, str] = {}  # event_id -> scenario_id

    # 1. Pre-validate scenario IDs (no missing, empty, non-string, or duplicate IDs)
    seen_scenario_ids: set[str] = set()
    for idx, s in enumerate(scenarios):
        if not isinstance(s, dict):
            matching_errors.append(f"Scenario at index {idx} is not a dictionary.")
            continue
        if "scenario_id" not in s:
            matching_errors.append(f"Scenario at index {idx} is missing mandatory 'scenario_id' key.")
            continue
        s_id_val = s["scenario_id"]
        if not isinstance(s_id_val, str) or not s_id_val.strip():
            matching_errors.append(f"Scenario at index {idx} has invalid scenario_id '{s_id_val}' (must be a non-empty string).")
            continue
        if s_id_val in seen_scenario_ids:
            matching_errors.append(f"Duplicate scenario_id detected: '{s_id_val}' appears multiple times.")
            continue
        seen_scenario_ids.add(s_id_val)

    # Determine audited bounds if applicable
    bounds_map: dict[str, tuple[str, str, str]] = {}
    if custom_bounds:
        bounds_map = custom_bounds
    elif "eval" in dataset_name.lower():
        bounds_map = EVALUATION_SCENARIO_BOUNDS
    elif "dev" in dataset_name.lower():
        bounds_map = DEVELOPMENT_SCENARIO_BOUNDS

    # Detect duplicate event IDs in the complete ingested event list
    seen_source_ids: set[str] = set()
    dup_source_ids: list[str] = []
    events_by_id: dict[str, NormalizedEvent] = {}
    for e in events:
        if e.event_id in seen_source_ids:
            dup_source_ids.append(e.event_id)
        seen_source_ids.add(e.event_id)
        events_by_id[e.event_id] = e

    if dup_source_ids:
        err = f"Ingested dataset contains duplicate event IDs: {sorted(list(set(dup_source_ids)))}"
        matching_errors.append(err)

    for idx, s in enumerate(scenarios):
        if not isinstance(s, dict):
            continue
        s_id = s.get("scenario_id")
        if not isinstance(s_id, str) or not s_id.strip():
            # Already flagged in pre-validation
            continue

        matched: list[NormalizedEvent] = []

        # Validate event_ids structure if key is present
        if "event_ids" in s:
            raw_eids = s["event_ids"]
            is_malformed = False
            malformed_reason = ""

            if not isinstance(raw_eids, list):
                is_malformed = True
                malformed_reason = f"event_ids must be a list of non-empty strings, got {type(raw_eids).__name__}"
            elif len(raw_eids) == 0:
                is_malformed = True
                malformed_reason = "event_ids list is empty"
            else:
                for item in raw_eids:
                    if not isinstance(item, str) or not item.strip():
                        is_malformed = True
                        malformed_reason = f"event_ids contains invalid item '{item}' (must be a non-empty string)"
                        break

            if is_malformed:
                err = f"Scenario '{s_id}': malformed event_ids: {malformed_reason}. Cannot associate scenario."
                matching_errors.append(err)
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: {err}"
                continue

            # Detect duplicate IDs within the same scenario
            seen_in_scenario: set[str] = set()
            dup_in_scenario: list[str] = []
            for eid in raw_eids:
                if eid in seen_in_scenario:
                    dup_in_scenario.append(eid)
                seen_in_scenario.add(eid)

            if dup_in_scenario:
                err = f"Scenario '{s_id}': duplicate event_ids specified in metadata: {sorted(list(set(dup_in_scenario)))}"
                matching_errors.append(err)
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: {err}"
                continue

            # Check existence of every ID
            missing_ids = [eid for eid in raw_eids if eid not in events_by_id]
            if missing_ids:
                err = f"Scenario '{s_id}': explicit event_ids do not exist in dataset: {missing_ids}"
                matching_errors.append(err)
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: {err}"
                continue

            # Check if any ID is already assigned to another scenario
            already_assigned = [eid for eid in raw_eids if eid in assigned_event_ids]
            if already_assigned:
                conflicts = [f"{eid} (assigned to '{assigned_event_ids[eid]}')" for eid in already_assigned]
                err = f"Scenario '{s_id}': event_ids already assigned to another scenario: {conflicts}"
                matching_errors.append(err)
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: {err}"
                continue

            # Determine bounds to validate explicit event IDs against:
            # Check structured metadata first, or audited bounds if structured metadata is absent
            u_check = s.get("user")
            start_check = s.get("start_time")
            end_check = s.get("end_time")

            has_u = bool(isinstance(u_check, str) and u_check.strip())
            has_st = bool(isinstance(start_check, str) and start_check.strip())
            has_et = bool(isinstance(end_check, str) and end_check.strip())

            val_user = None
            val_start = None
            val_end = None
            bounds_source = ""

            if has_u and has_st and has_et:
                val_user, val_start, val_end = u_check, start_check, end_check
                bounds_source = "declared structured bounds"
            elif not has_u and not has_st and not has_et and s_id in bounds_map:
                val_user, val_start, val_end = bounds_map[s_id]
                bounds_source = "audited bounds"

            explicit_val_failed = False
            if val_user and val_start and val_end:
                try:
                    start_dt = _parse_and_validate_utc_dt(val_start, "start_time", s_id)
                    end_dt = _parse_and_validate_utc_dt(val_end, "end_time", s_id)
                    if start_dt > end_dt:
                        err = f"Scenario '{s_id}': start_time ({val_start}) is later than end_time ({val_end})."
                        matching_errors.append(err)
                        explicit_val_failed = True
                    else:
                        u_lower = val_user.lower()
                        for eid in raw_eids:
                            ev = events_by_id[eid]
                            if (ev.user or "").lower() != u_lower:
                                err = f"Scenario '{s_id}': explicit event '{eid}' user '{ev.user}' does not match {bounds_source} user '{val_user}'."
                                matching_errors.append(err)
                                explicit_val_failed = True
                            if not _is_timezone_aware(ev.timestamp):
                                err = f"Scenario '{s_id}': explicit event '{eid}' has naive timestamp (tzinfo or utcoffset is None)."
                                matching_errors.append(err)
                                explicit_val_failed = True
                            else:
                                ev_utc = ev.timestamp.astimezone(timezone.utc)
                                if not (start_dt <= ev_utc <= end_dt):
                                    err = f"Scenario '{s_id}': explicit event '{eid}' timestamp {ev_utc.isoformat()} falls outside {bounds_source} window {start_dt.isoformat()}..{end_dt.isoformat()}."
                                    matching_errors.append(err)
                                    explicit_val_failed = True
                except Exception as ex:
                    err = f"Scenario '{s_id}': explicit window validation error against {bounds_source}: {str(ex)}"
                    matching_errors.append(err)
                    explicit_val_failed = True

            if explicit_val_failed:
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: validation against {bounds_source} failed"
                continue

            # All explicit IDs valid, exclusive, and verified against bounds
            for eid in raw_eids:
                matched.append(events_by_id[eid])
                assigned_event_ids[eid] = s_id

            scenario_events[s_id] = matched
            scenario_notes[s_id] = f"Matched via explicit event IDs ({len(matched)} events, validated against {bounds_source or 'no bounds'})"
            continue

        # Strategy 2 & 3: Structured metadata vs Audited bounds
        # Requirement 3: Distinguish genuinely absent keys from supplied empty or invalid values
        keys_present = ("user" in s, "start_time" in s, "end_time" in s)
        all_keys_absent = not any(keys_present)

        if all_keys_absent:
            # Audited bounds fallback is allowed ONLY when all three keys are genuinely absent
            if s_id in bounds_map:
                user, start_str, end_str = bounds_map[s_id]
                method_label = "audited bounds"
            else:
                scenario_events[s_id] = []
                scenario_notes[s_id] = "Unassociated: missing structured bounds or explicit event IDs (no heuristics used)"
                continue
        else:
            # One or more keys were supplied. Check validity of supplied values.
            raw_user = s.get("user")
            raw_start = s.get("start_time")
            raw_end = s.get("end_time")

            valid_user = isinstance(raw_user, str) and bool(raw_user.strip())
            valid_start = isinstance(raw_start, str) and bool(raw_start.strip())
            valid_end = isinstance(raw_end, str) and bool(raw_end.strip())

            if not (valid_user and valid_start and valid_end):
                missing_fields = []
                if not valid_user:
                    missing_fields.append("user (missing or empty/non-string)")
                if not valid_start:
                    missing_fields.append("start_time (missing or empty/non-string)")
                if not valid_end:
                    missing_fields.append("end_time (missing or empty/non-string)")
                err = f"Scenario '{s_id}': incomplete or invalid supplied structured metadata (issues: {', '.join(missing_fields)}). Partial or empty metadata is rejected."
                matching_errors.append(err)
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: {err}"
                continue

            user = raw_user
            start_str = raw_start
            end_str = raw_end
            method_label = "structured metadata"

        try:
            start_dt = _parse_and_validate_utc_dt(start_str, "start_time", s_id)
            end_dt = _parse_and_validate_utc_dt(end_str, "end_time", s_id)

            if start_dt > end_dt:
                err = f"Scenario '{s_id}': start_time ({start_str}) is later than end_time ({end_str})."
                matching_errors.append(err)
                scenario_events[s_id] = []
                scenario_notes[s_id] = f"Association failed: {err}"
                continue

            user_lower = user.lower()
            for e in events:
                if (e.user or "").lower() == user_lower:
                    # Normalize event timestamp to UTC
                    if not _is_timezone_aware(e.timestamp):
                        matching_errors.append(f"Event '{e.event_id}' has naive timestamp (tzinfo or utcoffset is None).")
                        continue
                    e_dt = e.timestamp.astimezone(timezone.utc)

                    if start_dt <= e_dt <= end_dt:
                        if e.event_id in assigned_event_ids:
                            err = (
                                f"Scenario '{s_id}': event '{e.event_id}' falls within window but "
                                f"was already assigned to '{assigned_event_ids[e.event_id]}'."
                            )
                            matching_errors.append(err)
                        else:
                            matched.append(e)
                            assigned_event_ids[e.event_id] = s_id

            scenario_events[s_id] = matched
            scenario_notes[s_id] = (
                f"Matched via {method_label} (user={user}, "
                f"window={start_dt.isoformat()}..{end_dt.isoformat()}, count={len(matched)})"
            )
        except Exception as ex:
            err = f"Scenario '{s_id}': timestamp/bounds parsing error: {str(ex)}"
            matching_errors.append(err)
            scenario_events[s_id] = []
            scenario_notes[s_id] = f"Association failed: {err}"

    return scenario_events, scenario_notes, matching_errors


def validate_scenario_mappings(
    mappings: dict[str, list[NormalizedEvent]],
    scenarios: list[dict[str, Any]],
    events: list[NormalizedEvent],
    bounds_map: Optional[dict[str, tuple[str, str, str]]] = None,
) -> list[str]:
    """Validate scenario-to-event association integrity with fail-closed checks.

    Verifies:
    1. Valid UTC-aware timestamps on all matched events.
    2. Start_time is not later than end_time.
    3. User identity matches matched events.
    4. Declared scenario time windows do not overlap between scenarios sharing a user.
    5. No event is assigned to multiple scenarios.
    6. Every scenario has matching events.

    Returns:
        List of validation error strings.
    """
    issues: list[str] = []
    seen_event_ids: dict[str, str] = {}
    declared_user_windows: dict[str, list[tuple[datetime, datetime, str]]] = {}

    for s in scenarios:
        s_id = s.get("scenario_id", "")
        if not s_id or not isinstance(s_id, str):
            issues.append(f"Scenario has missing or invalid scenario_id: '{s_id}'")
            continue

        matched_events = mappings.get(s_id, [])

        # Check declared window overlaps
        # Only use audited bounds if all three metadata keys were absent
        all_keys_absent = ("user" not in s and "start_time" not in s and "end_time" not in s)
        user = s.get("user")
        start_str = s.get("start_time")
        end_str = s.get("end_time")

        if all_keys_absent and bounds_map and s_id in bounds_map:
            user, start_str, end_str = bounds_map[s_id]

        if user and start_str and end_str:
            try:
                start_dt = _parse_and_validate_utc_dt(start_str, "start_time", s_id)
                end_dt = _parse_and_validate_utc_dt(end_str, "end_time", s_id)

                if start_dt > end_dt:
                    issues.append(f"Scenario '{s_id}': declared start_time is later than end_time.")

                u_key = user.lower()
                if u_key not in declared_user_windows:
                    declared_user_windows[u_key] = []

                for prev_start, prev_end, prev_sid in declared_user_windows[u_key]:
                    # Check interval overlap
                    if not (end_dt < prev_start or start_dt > prev_end):
                        issues.append(
                            f"Overlapping declared windows for user '{user}': scenario '{s_id}' "
                            f"({start_dt.isoformat()} to {end_dt.isoformat()}) overlaps with '{prev_sid}' "
                            f"({prev_start.isoformat()} to {prev_end.isoformat()})."
                        )
                declared_user_windows[u_key].append((start_dt, end_dt, s_id))
            except Exception as ex:
                issues.append(f"Scenario '{s_id}': window validation error: {str(ex)}")

        if not matched_events:
            issues.append(f"Scenario '{s_id}' has zero associated events.")
            continue

        # Check user identity match and event timestamp validity
        expected_user = (user or "").lower() if user else None
        for e in matched_events:
            if not _is_timezone_aware(e.timestamp):
                issues.append(f"Event '{e.event_id}' in scenario '{s_id}' has naive timestamp (tzinfo or utcoffset is None).")

            if expected_user and (e.user or "").lower() != expected_user:
                issues.append(
                    f"Scenario '{s_id}': event '{e.event_id}' user '{e.user}' does not match "
                    f"declared scenario user '{user}'."
                )

            if e.event_id in seen_event_ids:
                prev_s = seen_event_ids[e.event_id]
                issues.append(f"Duplicate assignment: event '{e.event_id}' assigned to both '{prev_s}' and '{s_id}'.")
            else:
                seen_event_ids[e.event_id] = s_id

    return issues


def evaluate_scenarios(
    scenarios: list[dict[str, Any]],
    events: list[NormalizedEvent],
    detections: list[Detection],
    scenario_to_events: dict[str, list[NormalizedEvent]],
    scenario_notes: dict[str, str],
    validation_errors: list[str],
    dataset_name: str = "evaluation",
    data_dir: str = "",
) -> EvaluationMetrics:
    """Classifies scenarios and computes metrics using the validated mappings.

    Guarantees the exact mapping that passed validation is the mapping used for scoring.
    """
    event_to_rules: dict[str, set[str]] = {}
    for d in detections:
        for eid in d.event_ids:
            event_to_rules.setdefault(eid, set()).add(d.rule_name)

    tp = fp = fn = tn = 0
    unassociated_count = 0
    scenario_results: list[ScenarioEvaluationResult] = []

    for s in scenarios:
        s_id = s.get("scenario_id", "")
        name = s.get("name", s_id or "unnamed_scenario")
        is_malicious = bool(s.get("is_malicious", False))
        expected_rules = s.get("expected_rules", [])
        description = s.get("description", "")

        matched_events = scenario_to_events.get(s_id, [])
        note = scenario_notes.get(s_id, "")

        if not matched_events:
            unassociated_count += 1
            scenario_results.append(ScenarioEvaluationResult(
                scenario_id=s_id,
                name=name,
                is_malicious=is_malicious,
                expected_rules=expected_rules,
                triggered_rules=[],
                classification="UNASSOCIATED",
                matched_events_count=0,
                rule_coverage=0.0,
                description=description,
                association_notes=note,
            ))
            continue

        matched_eids = {e.event_id for e in matched_events}

        triggered_rules_set: set[str] = set()
        for eid in matched_eids:
            if eid in event_to_rules:
                triggered_rules_set.update(event_to_rules[eid])

        triggered_rules = sorted(list(triggered_rules_set))
        expected_rules_set = set(expected_rules)

        if is_malicious:
            if expected_rules_set:
                detected = bool(triggered_rules_set & expected_rules_set)
            else:
                detected = bool(triggered_rules_set)

            if detected:
                tp += 1
                classification = "TP"
            else:
                fn += 1
                classification = "FN"

            if expected_rules:
                coverage = len(triggered_rules_set & expected_rules_set) / float(len(expected_rules))
            else:
                coverage = 1.0 if triggered_rules else 0.0
        else:
            if triggered_rules_set:
                fp += 1
                classification = "FP"
            else:
                tn += 1
                classification = "TN"
            coverage = 1.0 if not triggered_rules_set else 0.0

        scenario_results.append(ScenarioEvaluationResult(
            scenario_id=s_id,
            name=name,
            is_malicious=is_malicious,
            expected_rules=expected_rules,
            triggered_rules=triggered_rules,
            classification=classification,
            matched_events_count=len(matched_events),
            rule_coverage=round(coverage, 2),
            description=description,
            association_notes=note,
        ))

    return calculate_metrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        total_scenarios=len(scenarios),
        unassociated_scenarios=unassociated_count,
        validation_errors=validation_errors,
        dataset_name=dataset_name,
        data_dir=data_dir,
        scenario_results=scenario_results,
    )


class ScenarioEvaluator:
    """Evaluates the AEGIS-X detection engine against a scenario dataset."""

    def __init__(self, data_dir: str, config: Optional[AegisConfig] = None):
        self.data_dir = data_dir
        if config is None:
            self.config = AegisConfig()
            self.config.authorized_schedules.append(AuthorizedSchedule(
                user="admin",
                days=["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
                start="00:00",
                end="23:59",
                timezone="UTC",
            ))
        else:
            self.config = config

    def load_dataset(self) -> tuple[list[dict[str, Any]], list[NormalizedEvent], str]:
        scenarios_file = os.path.join(self.data_dir, "scenarios.json")
        if not os.path.exists(scenarios_file):
            raise FileNotFoundError(f"Scenarios file not found: {scenarios_file}")

        with open(scenarios_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        dataset_name = meta.get("dataset_name", "unknown")
        scenarios = meta.get("scenarios", [])

        events: list[NormalizedEvent] = []

        auth_csv = os.path.join(self.data_dir, "auth_events.csv")
        auth_json = os.path.join(self.data_dir, "auth_events.json")
        if os.path.exists(auth_csv):
            res = ingest_csv(auth_csv, default_source=EventSource.AUTHENTICATION, id_offset=1)
            events.extend(res.events)
        elif os.path.exists(auth_json):
            res = ingest_json(auth_json, default_source=EventSource.AUTHENTICATION, id_offset=1)
            events.extend(res.events)

        offset = len(events) + 1
        ep_csv = os.path.join(self.data_dir, "endpoint_events.csv")
        ep_json = os.path.join(self.data_dir, "endpoint_events.json")
        if os.path.exists(ep_csv):
            res = ingest_csv(ep_csv, default_source=EventSource.ENDPOINT, id_offset=offset)
            events.extend(res.events)
        elif os.path.exists(ep_json):
            res = ingest_json(ep_json, default_source=EventSource.ENDPOINT, id_offset=offset)
            events.extend(res.events)

        return scenarios, events, dataset_name

    def evaluate(self, fail_closed: bool = False) -> EvaluationMetrics:
        """Run complete scenario-level evaluation without tuning or data alteration.

        Args:
            fail_closed: If True and validation errors exist, raises AssociationValidationError.

        Returns:
            EvaluationMetrics object.
        """
        scenarios, events, dataset_name = self.load_dataset()

        # Step 1: Explicit mapping (single computation)
        bounds_map = EVALUATION_SCENARIO_BOUNDS if "eval" in dataset_name.lower() else DEVELOPMENT_SCENARIO_BOUNDS
        scenario_to_events, scenario_notes, matching_errors = match_scenario_events(
            scenarios=scenarios,
            events=events,
            dataset_name=dataset_name,
            custom_bounds=bounds_map,
        )

        # Step 2: Validate the exact mapping
        validation_errors = validate_scenario_mappings(
            mappings=scenario_to_events,
            scenarios=scenarios,
            events=events,
            bounds_map=bounds_map,
        )
        all_errors = matching_errors + validation_errors

        if fail_closed and all_errors:
            raise AssociationValidationError(all_errors)

        # Step 3: Run Phase 1 detection engine
        detections = run_detection(events, self.config)

        # Step 4: Score using the exact validated mapping
        return evaluate_scenarios(
            scenarios=scenarios,
            events=events,
            detections=detections,
            scenario_to_events=scenario_to_events,
            scenario_notes=scenario_notes,
            validation_errors=all_errors,
            dataset_name=dataset_name,
            data_dir=self.data_dir,
        )


def compute_file_sha256(file_path: str) -> str:
    """Compute the SHA-256 cryptographic hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()
