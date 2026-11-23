"""
Unit tests for the Evaluation Framework (Phase 2 Checkpoint 1 - Refined & Hardened).

Tests cover:
- Metric calculation formulas with standard values and safe zero-denominator handling.
- Full functional tests for TP, FP, FN, TN classifications exercising actual evaluate_scenarios() logic.
- Same-user scenario isolation (preventing cross-contamination between scenarios sharing a user).
- Strict explicit event-ID resolution:
    • missing event IDs
    • duplicate IDs within the same scenario
    • IDs already assigned to another scenario
- Strict timestamp and mapping validation:
    • naive timestamp rejection
    • start_time later than end_time rejection
    • user identity mismatch rejection
    • overlapping declared windows rejection
- Fail-closed CLI behavior on validation errors.
- Real subprocess test of CLI containment guard using os.path.commonpath().
- Dataset immutability verifying SHA-256 hashes of all three held-out files before and after evaluation.
- Development dataset evaluation verifying all 10 scenarios associate with zero mutation.
- Complete ScenarioEvaluator run on the held-out evaluation dataset.
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.evaluation.evaluator import (
    AssociationValidationError,
    ScenarioEvaluator,
    calculate_metrics,
    compute_file_sha256,
    evaluate_scenarios,
    match_scenario_events,
    validate_scenario_mappings,
)
from app.schemas.events import EventSource, NormalizedEvent
from app.schemas.incidents import Detection


def _make_event(
    event_id: str,
    user: str,
    timestamp_iso: str,
    event_type: str = "login_success",
    device: str = "WS-001",
) -> NormalizedEvent:
    """Helper to create UTC-aware test events."""
    dt = datetime.fromisoformat(timestamp_iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=dt,
        user=user,
        device=device,
        ip="192.168.1.10",
        event_type=event_type,
        source=EventSource.AUTHENTICATION,
        raw_data={"test": True},
    )


def _make_detection(
    detection_id: str,
    rule_name: str,
    user: str,
    event_ids: list[str],
) -> Detection:
    """Helper to create test detections."""
    return Detection(
        detection_id=detection_id,
        rule_name=rule_name,
        explanation=f"Test detection {rule_name}",
        event_ids=event_ids,
        timestamp=datetime.now(timezone.utc),
        user=user,
        device="WS-001",
        confidence="high",
    )


# =============================================================================
# 1. METRIC CALCULATION TESTS (WITH ZERO-DENOMINATOR SAFETY)
# =============================================================================

class TestMetricCalculations:
    def test_standard_metrics(self):
        """Standard scenario where TP=4, FP=1, FN=1, TN=4."""
        metrics = calculate_metrics(tp=4, fp=1, fn=1, tn=4, total_scenarios=10)
        assert metrics.precision == 0.8
        assert metrics.recall == 0.8
        assert metrics.f1_score == 0.8
        assert metrics.false_positive_rate == 0.2
        assert metrics.accuracy == 0.8
        assert metrics.association_integrity == "PASSED"

    def test_zero_denominator_no_detections(self):
        """Zero detections triggered: TP=0, FP=0, FN=5, TN=5 (TP+FP=0)."""
        metrics = calculate_metrics(tp=0, fp=0, fn=5, tn=5, total_scenarios=10)
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0
        assert metrics.false_positive_rate == 0.0
        assert metrics.accuracy == 0.5

    def test_zero_denominator_all_benign(self):
        """Only benign scenarios: TP=0, FN=0, FP=1, TN=4 (TP+FN=0)."""
        metrics = calculate_metrics(tp=0, fp=1, fn=0, tn=4, total_scenarios=5)
        assert metrics.recall == 0.0
        assert metrics.precision == 0.0
        assert metrics.f1_score == 0.0
        assert metrics.false_positive_rate == 0.2
        assert metrics.accuracy == 0.8

    def test_zero_denominator_all_malicious(self):
        """Only malicious scenarios: TP=5, FN=0, FP=0, TN=0 (FP+TN=0)."""
        metrics = calculate_metrics(tp=5, fp=0, fn=0, tn=0, total_scenarios=5)
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0
        assert metrics.false_positive_rate == 0.0
        assert metrics.accuracy == 1.0

    def test_zero_denominator_all_zeroes(self):
        """Empty scenario pool: total=0."""
        metrics = calculate_metrics(tp=0, fp=0, fn=0, tn=0, total_scenarios=0)
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0
        assert metrics.false_positive_rate == 0.0
        assert metrics.accuracy == 0.0
        assert metrics.association_integrity == "FAILED"


# =============================================================================
# 2. FUNCTIONAL CLASSIFICATION TESTS (TP, FP, FN, TN, ISOLATION)
# =============================================================================

class TestFunctionalScenarioEvaluation:
    """Tests exercising actual evaluate_scenarios() logic using controlled inputs."""

    def test_functional_true_positive(self):
        """Malicious scenario with expected rule triggered -> TP."""
        scenarios = [{
            "scenario_id": "TEST_S01",
            "name": "Controlled BF Attack",
            "is_malicious": True,
            "expected_rules": ["brute_force_login"],
            "user": "victim1",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:10:00+00:00",
        }]
        events = [
            _make_event("E001", "victim1", "2024-11-20T10:02:00+00:00", "login_failure"),
            _make_event("E002", "victim1", "2024-11-20T10:04:00+00:00", "login_failure"),
        ]
        detections = [_make_detection("D001", "brute_force_login", "victim1", ["E001", "E002"])]

        mappings, notes, errs = match_scenario_events(scenarios, events)
        assert not errs
        metrics = evaluate_scenarios(scenarios, events, detections, mappings, notes, errs)
        assert metrics.true_positives == 1
        assert metrics.false_negatives == 0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.scenario_results[0]["classification"] == "TP"
        assert metrics.scenario_results[0]["rule_coverage"] == 1.0

    def test_functional_false_negative(self):
        """Malicious scenario without expected rule triggered -> FN."""
        scenarios = [{
            "scenario_id": "TEST_S02",
            "name": "Controlled Priv Esc Missed",
            "is_malicious": True,
            "expected_rules": ["privilege_escalation"],
            "user": "victim2",
            "start_time": "2024-11-20T11:00:00+00:00",
            "end_time": "2024-11-20T11:10:00+00:00",
        }]
        events = [_make_event("E010", "victim2", "2024-11-20T11:05:00+00:00", "login_success")]
        detections = []  # No detections triggered

        mappings, notes, errs = match_scenario_events(scenarios, events)
        assert not errs
        metrics = evaluate_scenarios(scenarios, events, detections, mappings, notes, errs)
        assert metrics.true_positives == 0
        assert metrics.false_negatives == 1
        assert metrics.recall == 0.0
        assert metrics.scenario_results[0]["classification"] == "FN"
        assert metrics.scenario_results[0]["rule_coverage"] == 0.0

    def test_functional_true_negative(self):
        """Benign scenario with zero detections triggered -> TN."""
        scenarios = [{
            "scenario_id": "TEST_S03",
            "name": "Controlled Benign Activity",
            "is_malicious": False,
            "expected_rules": [],
            "user": "worker1",
            "start_time": "2024-11-20T12:00:00+00:00",
            "end_time": "2024-11-20T12:10:00+00:00",
        }]
        events = [_make_event("E020", "worker1", "2024-11-20T12:05:00+00:00", "login_success")]
        detections = []

        mappings, notes, errs = match_scenario_events(scenarios, events)
        assert not errs
        metrics = evaluate_scenarios(scenarios, events, detections, mappings, notes, errs)
        assert metrics.true_negatives == 1
        assert metrics.false_positives == 0
        assert metrics.false_positive_rate == 0.0
        assert metrics.scenario_results[0]["classification"] == "TN"

    def test_functional_false_positive(self):
        """Benign scenario triggering an unexpected detection -> FP."""
        scenarios = [{
            "scenario_id": "TEST_S04",
            "name": "Controlled Benign Flagged",
            "is_malicious": False,
            "expected_rules": [],
            "user": "worker2",
            "start_time": "2024-11-20T13:00:00+00:00",
            "end_time": "2024-11-20T13:10:00+00:00",
        }]
        events = [_make_event("E030", "worker2", "2024-11-20T13:05:00+00:00", "login_success")]
        detections = [_make_detection("D002", "unusual_login_time", "worker2", ["E030"])]

        mappings, notes, errs = match_scenario_events(scenarios, events)
        assert not errs
        metrics = evaluate_scenarios(scenarios, events, detections, mappings, notes, errs)
        assert metrics.true_negatives == 0
        assert metrics.false_positives == 1
        assert metrics.false_positive_rate == 1.0
        assert metrics.scenario_results[0]["classification"] == "FP"

    def test_functional_same_user_scenario_isolation(self):
        """Two scenarios for the same user (e.g. admin) at different times.

        Scenario A (10:00) is malicious and triggered a detection.
        Scenario B (14:00) is benign and clean.
        Verifies that detections from Scenario A do NOT bleed into Scenario B.
        """
        scenarios = [
            {
                "scenario_id": "SCENARIO_A",
                "name": "Admin Malicious Morning",
                "is_malicious": True,
                "expected_rules": ["brute_force_login"],
                "user": "admin",
                "start_time": "2024-11-20T10:00:00+00:00",
                "end_time": "2024-11-20T10:30:00+00:00",
            },
            {
                "scenario_id": "SCENARIO_B",
                "name": "Admin Benign Afternoon",
                "is_malicious": False,
                "expected_rules": [],
                "user": "admin",
                "start_time": "2024-11-20T14:00:00+00:00",
                "end_time": "2024-11-20T14:30:00+00:00",
            },
        ]
        events = [
            _make_event("E100", "admin", "2024-11-20T10:15:00+00:00", "login_failure"),
            _make_event("E200", "admin", "2024-11-20T14:15:00+00:00", "login_success"),
        ]
        detections = [_make_detection("D100", "brute_force_login", "admin", ["E100"])]

        mappings, notes, errs = match_scenario_events(scenarios, events)
        assert not errs
        metrics = evaluate_scenarios(scenarios, events, detections, mappings, notes, errs)
        assert metrics.true_positives == 1
        assert metrics.true_negatives == 1
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.scenario_results[0]["classification"] == "TP"
        assert metrics.scenario_results[1]["classification"] == "TN"


# =============================================================================
# 3. STRICT EXPLICIT EVENT-ID RESOLUTION TESTS
# =============================================================================

class TestStrictEventIDResolution:
    def test_missing_event_id_fails_and_unassociates(self):
        """Scenario specifying non-existent event IDs fails association and reports offending ID."""
        scenarios = [{
            "scenario_id": "S_MISSING",
            "name": "Missing Event Scenario",
            "is_malicious": True,
            "expected_rules": ["brute_force_login"],
            "event_ids": ["E001", "NON_EXISTENT_ID"],
        }]
        events = [_make_event("E001", "victim", "2024-11-20T10:00:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "NON_EXISTENT_ID" in errors[0]
        assert len(mappings["S_MISSING"]) == 0
        assert "Association failed" in notes["S_MISSING"]

    def test_duplicate_event_id_within_scenario_detected(self):
        """Scenario specifying duplicate event IDs in its own metadata fails association."""
        scenarios = [{
            "scenario_id": "S_DUP",
            "name": "Duplicate ID Scenario",
            "is_malicious": True,
            "expected_rules": ["brute_force_login"],
            "event_ids": ["E001", "E001"],
        }]
        events = [_make_event("E001", "victim", "2024-11-20T10:00:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "duplicate event_ids specified in metadata" in errors[0]
        assert len(mappings["S_DUP"]) == 0

    def test_event_id_already_assigned_to_another_scenario_detected(self):
        """Two scenarios claiming the same event_id fail with explicit conflict reporting."""
        scenarios = [
            {"scenario_id": "S1", "event_ids": ["E001"]},
            {"scenario_id": "S2", "event_ids": ["E001"]},
        ]
        events = [_make_event("E001", "victim", "2024-11-20T10:00:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "event_ids already assigned to another scenario" in errors[0]
        assert "S1" in errors[0]
        assert len(mappings["S2"]) == 0

    def test_explicit_event_id_outside_declared_time_window_fails(self):
        """Explicit event ID belonging to correct user but outside declared window fails validation."""
        scenarios = [{
            "scenario_id": "S_TIME_MISMATCH",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
            "event_ids": ["E001"],
        }]
        # Event is at 10:45 (outside window)
        events = [_make_event("E001", "alice", "2024-11-20T10:45:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "falls outside declared structured bounds window" in errors[0]
        assert len(mappings["S_TIME_MISMATCH"]) == 0
        assert "Association failed" in notes["S_TIME_MISMATCH"]

    def test_explicit_event_id_with_wrong_user_fails(self):
        """Explicit event ID belonging to a different user fails user identity validation."""
        scenarios = [{
            "scenario_id": "S_USER_MISMATCH_EXPLICIT",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
            "event_ids": ["E001"],
        }]
        events = [_make_event("E001", "mallory", "2024-11-20T10:15:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "does not match declared structured bounds user 'alice'" in errors[0]
        assert len(mappings["S_USER_MISMATCH_EXPLICIT"]) == 0

    def test_explicit_event_id_with_naive_timestamp_fails(self):
        """Explicit event ID with naive timestamp fails validation."""
        scenarios = [{
            "scenario_id": "S_NAIVE_EXPLICIT",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
            "event_ids": ["E001"],
        }]
        naive_dt = datetime.fromisoformat("2024-11-20T10:15:00")  # No tzinfo
        e_naive = NormalizedEvent(
            event_id="E001",
            timestamp=naive_dt,
            user="alice",
            device="WS-001",
            ip="192.168.1.10",
            event_type="login_success",
            source=EventSource.AUTHENTICATION,
            raw_data={},
        )

        mappings, notes, errors = match_scenario_events(scenarios, [e_naive])
        assert len(errors) == 1
        assert "has naive timestamp" in errors[0]
        assert len(mappings["S_NAIVE_EXPLICIT"]) == 0

    def test_explicit_event_id_with_valid_non_utc_offset_normalized_correctly(self):
        """Explicit event ID with valid non-UTC offset (e.g. +05:30) is normalized and succeeds."""
        scenarios = [{
            "scenario_id": "S_NON_UTC_EXPLICIT",
            "user": "alice",
            "start_time": "2024-11-20T04:30:00+00:00",
            "end_time": "2024-11-20T05:30:00+00:00",
            "event_ids": ["E001"],
        }]
        # 10:30 +05:30 equals 05:00 UTC (inside window)
        e = _make_event("E001", "alice", "2024-11-20T10:30:00+05:30")

        mappings, notes, errors = match_scenario_events(scenarios, [e])
        assert len(errors) == 0
        assert len(mappings["S_NON_UTC_EXPLICIT"]) == 1
        assert mappings["S_NON_UTC_EXPLICIT"][0].event_id == "E001"

    def test_explicit_event_id_outside_audited_bounds_when_structured_metadata_absent_fails(self):
        """When structured metadata is absent, explicit event IDs must fall within audited bounds."""
        scenarios = [{
            "scenario_id": "S001_MAL_BF_001",
            "event_ids": ["E_OUTSIDE"],
        }]
        # S001 audited bounds are user='bob', window='2024-11-21T09:26:26+00:00'..'2024-11-21T09:31:26+00:00'
        # Provide event for 'bob' on 2024-11-22 (outside audited window)
        events = [_make_event("E_OUTSIDE", "bob", "2024-11-22T10:00:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events, dataset_name="evaluation")
        assert len(errors) == 1
        assert "falls outside audited bounds window" in errors[0]
        assert len(mappings["S001_MAL_BF_001"]) == 0
        assert "Association failed" in notes["S001_MAL_BF_001"]

    def test_explicit_event_id_wrong_user_against_audited_bounds_fails(self):
        """When structured metadata is absent, explicit event IDs must match audited bounds user."""
        scenarios = [{
            "scenario_id": "S001_MAL_BF_001",
            "event_ids": ["E_WRONG_USER"],
        }]
        # S001 expects user 'bob' in audited bounds; provide event for 'alice' inside the timestamp window
        events = [_make_event("E_WRONG_USER", "alice", "2024-11-21T09:28:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events, dataset_name="evaluation")
        assert len(errors) == 1
        assert "does not match audited bounds user 'bob'" in errors[0]
        assert len(mappings["S001_MAL_BF_001"]) == 0

    @pytest.mark.parametrize("bad_val", [
        "not_a_list",
        {"id": "E001"},
        None,
        [],
        [""],
        ["   "],
        [123],
        ["E001", None],
    ])
    def test_malformed_event_ids_rejected(self, bad_val):
        """If event_ids key exists, reject malformed values and do not fall back silently."""
        scenarios = [{
            "scenario_id": "S_BAD_EIDS",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
            "event_ids": bad_val,
        }]
        events = [_make_event("E001", "alice", "2024-11-20T10:15:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "malformed event_ids" in errors[0]
        assert len(mappings["S_BAD_EIDS"]) == 0
        assert "Association failed" in notes["S_BAD_EIDS"]

    def test_duplicate_event_ids_in_ingested_dataset_fails_closed(self):
        """Duplicate event_ids in the source dataset are detected and cause association integrity failure."""
        scenarios = [{
            "scenario_id": "S1",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
            "event_ids": ["E001"],
        }]
        events = [
            _make_event("E001", "alice", "2024-11-20T10:05:00+00:00"),
            _make_event("E001", "alice", "2024-11-20T10:10:00+00:00"),  # Duplicate E001!
        ]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) >= 1
        assert any("Ingested dataset contains duplicate event IDs: ['E001']" in err for err in errors)

        # Confirm calculate_metrics reports FAILED association integrity
        metrics = calculate_metrics(
            tp=1, fp=0, fn=0, tn=0,
            total_scenarios=1,
            validation_errors=errors,
        )
        assert metrics.association_integrity == "FAILED"


# =============================================================================
# 4. STRICT TIMESTAMP AND MAPPING VALIDATION TESTS
# =============================================================================

class TestStrictTimestampAndMappingValidation:
    def test_naive_timestamp_rejected(self):
        """Naive timestamp without timezone offset is rejected with validation error."""
        scenarios = [{
            "scenario_id": "S_NAIVE",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00",  # No timezone!
            "end_time": "2024-11-20T10:30:00+00:00",
        }]
        events = [_make_event("E001", "alice", "2024-11-20T10:15:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "lacks a timezone offset" in errors[0]
        assert len(mappings["S_NAIVE"]) == 0

    def test_start_time_after_end_time_rejected(self):
        """start_time later than end_time is rejected with validation error."""
        scenarios = [{
            "scenario_id": "S_INVERTED",
            "user": "alice",
            "start_time": "2024-11-20T11:00:00+00:00",
            "end_time": "2024-11-20T10:00:00+00:00",  # Earlier than start!
        }]
        events = [_make_event("E001", "alice", "2024-11-20T10:15:00+00:00")]

        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "is later than end_time" in errors[0]

    def test_user_identity_mismatch_rejected(self):
        """Event with user differing from scenario's declared user fails mapping validation."""
        scenarios = [{
            "scenario_id": "S_USER_MISMATCH",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
        }]
        # Event has user 'mallory'
        e_wrong_user = _make_event("E001", "mallory", "2024-11-20T10:15:00+00:00")
        mappings = {"S_USER_MISMATCH": [e_wrong_user]}

        issues = validate_scenario_mappings(mappings, scenarios, [e_wrong_user])
        assert any("does not match declared scenario user" in issue for issue in issues)

    def test_overlapping_declared_windows_for_same_user_rejected(self):
        """Declared windows for the same user overlapping in time fail mapping validation."""
        scenarios = [
            {
                "scenario_id": "S1",
                "user": "admin",
                "start_time": "2024-11-20T10:00:00+00:00",
                "end_time": "2024-11-20T11:00:00+00:00",
            },
            {
                "scenario_id": "S2",
                "user": "admin",
                "start_time": "2024-11-20T10:30:00+00:00",  # Overlaps with S1!
                "end_time": "2024-11-20T11:30:00+00:00",
            },
        ]
        e1 = _make_event("E1", "admin", "2024-11-20T10:15:00+00:00")
        e2 = _make_event("E2", "admin", "2024-11-20T11:15:00+00:00")
        mappings = {"S1": [e1], "S2": [e2]}

        issues = validate_scenario_mappings(mappings, scenarios, [e1, e2])
        assert any("Overlapping declared windows for user" in issue for issue in issues)

    def test_partial_metadata_missing_user_rejected(self):
        """Scenario providing start_time and end_time but missing user is rejected and unassociated."""
        scenarios = [{
            "scenario_id": "S_NO_USER",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
        }]
        events = [_make_event("E1", "admin", "2024-11-20T10:15:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "incomplete or invalid supplied structured metadata" in errors[0]
        assert "user (missing or empty/non-string)" in errors[0]
        assert len(mappings["S_NO_USER"]) == 0
        assert "Association failed" in notes["S_NO_USER"]

    def test_partial_metadata_missing_start_time_rejected(self):
        """Scenario providing user and end_time but missing start_time is rejected and unassociated."""
        scenarios = [{
            "scenario_id": "S_NO_START",
            "user": "admin",
            "end_time": "2024-11-20T10:30:00+00:00",
        }]
        events = [_make_event("E1", "admin", "2024-11-20T10:15:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "incomplete or invalid supplied structured metadata" in errors[0]
        assert "start_time (missing or empty/non-string)" in errors[0]
        assert len(mappings["S_NO_START"]) == 0
        assert "Association failed" in notes["S_NO_START"]

    def test_partial_metadata_missing_end_time_rejected(self):
        """Scenario providing user and start_time but missing end_time is rejected and unassociated."""
        scenarios = [{
            "scenario_id": "S_NO_END",
            "user": "admin",
            "start_time": "2024-11-20T10:00:00+00:00",
        }]
        events = [_make_event("E1", "admin", "2024-11-20T10:15:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) == 1
        assert "incomplete or invalid supplied structured metadata" in errors[0]
        assert "end_time (missing or empty/non-string)" in errors[0]
        assert len(mappings["S_NO_END"]) == 0
        assert "Association failed" in notes["S_NO_END"]

    def test_empty_string_metadata_rejected(self):
        """Scenario providing empty string metadata fields is rejected rather than falling back to audited bounds."""
        scenarios = [{
            "scenario_id": "S001_MAL_BF_001",
            "user": "   ",
            "start_time": "2024-11-21T09:26:26+00:00",
            "end_time": "2024-11-21T09:31:26+00:00",
        }]
        events = [_make_event("E1", "bob", "2024-11-21T09:28:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events, dataset_name="evaluation")
        assert len(errors) == 1
        assert "incomplete or invalid supplied structured metadata" in errors[0]
        assert len(mappings["S001_MAL_BF_001"]) == 0
        assert "Association failed" in notes["S001_MAL_BF_001"]

    def test_all_keys_absent_falls_back_to_audited_bounds(self):
        """When all three keys (user, start_time, end_time) are genuinely absent, audited bounds are used."""
        scenarios = [{
            "scenario_id": "S001_MAL_BF_001",
            "name": "BF attack without explicit or structured bounds",
            "is_malicious": True,
            "expected_rules": ["brute_force_login"],
            # user, start_time, end_time genuinely omitted
        }]
        events = [_make_event("E1", "bob", "2024-11-21T09:28:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events, dataset_name="evaluation")
        assert len(errors) == 0
        assert len(mappings["S001_MAL_BF_001"]) == 1
        assert "Matched via audited bounds" in notes["S001_MAL_BF_001"]

    def test_duplicate_scenario_id_fails_validation(self):
        """Duplicate scenario IDs in scenarios list are rejected and fail validation."""
        scenarios = [
            {"scenario_id": "S_SAME", "user": "alice", "start_time": "2024-11-20T10:00:00+00:00", "end_time": "2024-11-20T10:30:00+00:00"},
            {"scenario_id": "S_SAME", "user": "bob", "start_time": "2024-11-20T11:00:00+00:00", "end_time": "2024-11-20T11:30:00+00:00"},
        ]
        events = [_make_event("E1", "alice", "2024-11-20T10:15:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) >= 1
        assert any("Duplicate scenario_id detected: 'S_SAME'" in err for err in errors)

    @pytest.mark.parametrize("bad_sid", [
        None,
        "",
        "   ",
        123,
    ])
    def test_missing_or_invalid_scenario_id_fails(self, bad_sid):
        """Missing, empty, or non-string scenario IDs fail validation."""
        scenarios = [{"scenario_id": bad_sid, "user": "alice", "start_time": "2024-11-20T10:00:00+00:00", "end_time": "2024-11-20T10:30:00+00:00"}]
        events = [_make_event("E1", "alice", "2024-11-20T10:15:00+00:00")]
        mappings, notes, errors = match_scenario_events(scenarios, events)
        assert len(errors) >= 1
        assert any("invalid scenario_id" in err or "missing mandatory 'scenario_id'" in err for err in errors)

    def test_datetime_with_tzinfo_but_utcoffset_none_fails(self):
        """A datetime object with non-None tzinfo but utcoffset() returning None must be rejected."""
        from datetime import tzinfo, timedelta

        class BogusTz(tzinfo):
            def utcoffset(self, dt):
                return None
            def dst(self, dt):
                return timedelta(0)
            def tzname(self, dt):
                return "BOGUS"

        bogus_tz = BogusTz()
        bogus_dt = datetime(2024, 11, 20, 10, 15, tzinfo=bogus_tz)
        assert bogus_dt.tzinfo is not None
        assert bogus_dt.utcoffset() is None

        e_bogus = NormalizedEvent(
            event_id="E_BOGUS",
            timestamp=bogus_dt,
            user="alice",
            device="WS-001",
            ip="192.168.1.10",
            event_type="login_success",
            source=EventSource.AUTHENTICATION,
            raw_data={},
        )
        scenarios = [{
            "scenario_id": "S_BOGUS_TZ",
            "user": "alice",
            "start_time": "2024-11-20T10:00:00+00:00",
            "end_time": "2024-11-20T10:30:00+00:00",
            "event_ids": ["E_BOGUS"],
        }]
        mappings, notes, errors = match_scenario_events(scenarios, [e_bogus])
        assert len(errors) >= 1
        assert any("tzinfo or utcoffset is None" in err for err in errors)
        assert len(mappings["S_BOGUS_TZ"]) == 0


# =============================================================================
# 5. CLI FAIL-CLOSED & OUTPUT GUARD SUBPROCESS TESTS
# =============================================================================

class TestCLIFailClosedAndOutputGuard:
    def test_cli_rejects_json_output_inside_evaluation_dir(self):
        """Actual subprocess execution verifying CLI aborts when writing into data/evaluation/ while evaluating evaluation."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        eval_dir = os.path.join(project_root, "data", "evaluation")
        cli_path = os.path.join(project_root, "backend", "evaluate.py")
        forbidden_out = os.path.join(eval_dir, "test_forbidden_output.json")

        if os.path.exists(forbidden_out):
            os.remove(forbidden_out)

        proc = subprocess.run(
            [sys.executable, cli_path, "--data-dir", eval_dir, "--json-output", forbidden_out],
            capture_output=True,
            text=True,
        )

        assert proc.returncode != 0, "CLI must exit with non-zero status on directory containment violation!"
        combined_output = proc.stdout + proc.stderr
        assert "cannot be written inside benchmark dataset directory" in combined_output
        assert not os.path.exists(forbidden_out), "No output file must be created on containment error!"

    def test_cli_rejects_json_output_inside_development_when_evaluating_evaluation(self):
        """Subprocess verifying CLI aborts when evaluating evaluation while targeting JSON output inside development/."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        eval_dir = os.path.join(project_root, "data", "evaluation")
        dev_dir = os.path.join(project_root, "data", "development")
        cli_path = os.path.join(project_root, "backend", "evaluate.py")
        forbidden_out = os.path.join(dev_dir, "test_forbidden_in_dev.json")

        if os.path.exists(forbidden_out):
            os.remove(forbidden_out)

        proc = subprocess.run(
            [sys.executable, cli_path, "--data-dir", eval_dir, "--json-output", forbidden_out],
            capture_output=True,
            text=True,
        )

        assert proc.returncode != 0, "CLI must exit with non-zero status on directory containment violation!"
        combined_output = proc.stdout + proc.stderr
        assert "cannot be written inside benchmark dataset directory" in combined_output
        assert not os.path.exists(forbidden_out), "No output file must be created on containment error!"

    def test_cli_rejects_json_output_inside_evaluation_when_evaluating_development(self):
        """Subprocess verifying CLI aborts when evaluating development while targeting JSON output inside evaluation/."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        eval_dir = os.path.join(project_root, "data", "evaluation")
        dev_dir = os.path.join(project_root, "data", "development")
        cli_path = os.path.join(project_root, "backend", "evaluate.py")
        forbidden_out = os.path.join(eval_dir, "test_forbidden_in_eval.json")

        if os.path.exists(forbidden_out):
            os.remove(forbidden_out)

        proc = subprocess.run(
            [sys.executable, cli_path, "--data-dir", dev_dir, "--json-output", forbidden_out],
            capture_output=True,
            text=True,
        )

        assert proc.returncode != 0, "CLI must exit with non-zero status on directory containment violation!"
        combined_output = proc.stdout + proc.stderr
        assert "cannot be written inside benchmark dataset directory" in combined_output
        assert not os.path.exists(forbidden_out), "No output file must be created on containment error!"

    def test_cli_rejects_json_output_inside_selected_dir(self):
        """Subprocess verifying CLI aborts when targeting JSON output inside an arbitrary custom dataset dir."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cli_path = os.path.join(project_root, "backend", "evaluate.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create minimal valid dataset structure
            minimal_scenarios = {"dataset_name": "custom", "scenarios": []}
            with open(os.path.join(tmpdir, "scenarios.json"), "w") as f:
                json.dump(minimal_scenarios, f)
            with open(os.path.join(tmpdir, "auth_events.csv"), "w") as f:
                f.write("timestamp,user,device,ip,event_type,source,process\n")

            forbidden_out = os.path.join(tmpdir, "out.json")
            proc = subprocess.run(
                [sys.executable, cli_path, "--data-dir", tmpdir, "--json-output", forbidden_out],
                capture_output=True,
                text=True,
            )

            assert proc.returncode != 0
            assert "cannot be written inside benchmark dataset directory" in (proc.stdout + proc.stderr)
            assert not os.path.exists(forbidden_out)

    def test_cli_fails_closed_when_validation_fails(self):
        """CLI returns exit code 2 and aborts when scenario association integrity fails."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cli_path = os.path.join(project_root, "backend", "evaluate.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a corrupted scenarios.json with an unmatchable user
            corrupted_scenarios = {
                "dataset_name": "corrupted_test",
                "scenarios": [{
                    "scenario_id": "S_CORRUPT",
                    "name": "Corrupt",
                    "is_malicious": True,
                    "expected_rules": ["brute_force_login"],
                    "user": "non_existent_user",
                    "start_time": "2024-11-20T10:00:00+00:00",
                    "end_time": "2024-11-20T10:10:00+00:00",
                }],
            }
            with open(os.path.join(tmpdir, "scenarios.json"), "w") as f:
                json.dump(corrupted_scenarios, f)

            with open(os.path.join(tmpdir, "auth_events.csv"), "w") as f:
                f.write("timestamp,user,device,ip,event_type,source,process\n")
                f.write("2024-11-20T10:05:00+00:00,someone_else,WS-01,10.0.0.1,login_success,authentication,\n")

            proc = subprocess.run(
                [sys.executable, cli_path, "--data-dir", tmpdir],
                capture_output=True,
                text=True,
            )

            assert proc.returncode == 2, f"CLI must exit with code 2 on validation failure! Got: {proc.returncode}"
            assert "SCENARIO ASSOCIATION INTEGRITY FAILED" in proc.stderr


# =============================================================================
# 6. DATASET IMMUTABILITY TESTS (SHA-256 HASH VERIFICATION ON ALL 3 FILES)
# =============================================================================

class TestDatasetImmutability:
    def test_held_out_evaluation_dataset_immutability(self):
        """Verifies that data/evaluation/ files retain identical SHA-256 hashes before and after evaluation."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        eval_dir = os.path.join(project_root, "data", "evaluation")

        files_to_verify = [
            os.path.join(eval_dir, "scenarios.json"),
            os.path.join(eval_dir, "auth_events.csv"),
            os.path.join(eval_dir, "endpoint_events.csv"),
        ]

        hashes_before = {f: compute_file_sha256(f) for f in files_to_verify}

        evaluator = ScenarioEvaluator(data_dir=eval_dir)
        metrics = evaluator.evaluate()

        hashes_after = {f: compute_file_sha256(f) for f in files_to_verify}

        for f in files_to_verify:
            filename = os.path.basename(f)
            assert hashes_before[f] == hashes_after[f], (
                f"Held-out file '{filename}' was mutated! Before: {hashes_before[f]}, After: {hashes_after[f]}"
            )

        assert metrics.association_integrity == "PASSED"

    def test_development_dataset_evaluation_and_immutability(self):
        """Verifies ScenarioEvaluator against data/development/: all 10 scenarios associate and files are not mutated."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        dev_dir = os.path.join(project_root, "data", "development")

        files_to_verify = [
            os.path.join(dev_dir, "scenarios.json"),
            os.path.join(dev_dir, "auth_events.csv"),
            os.path.join(dev_dir, "endpoint_events.csv"),
        ]

        hashes_before = {f: compute_file_sha256(f) for f in files_to_verify}

        evaluator = ScenarioEvaluator(data_dir=dev_dir)
        metrics = evaluator.evaluate()

        hashes_after = {f: compute_file_sha256(f) for f in files_to_verify}

        for f in files_to_verify:
            filename = os.path.basename(f)
            assert hashes_before[f] == hashes_after[f], (
                f"Development file '{filename}' was mutated! Before: {hashes_before[f]}, After: {hashes_after[f]}"
            )

        # Verify development dataset metrics & association
        assert metrics.total_scenarios == 10
        assert metrics.evaluated_scenarios == 10
        assert metrics.unassociated_scenarios == 0
        assert metrics.association_integrity == "PASSED"
        assert len(metrics.validation_errors) == 0


# =============================================================================
# 7. FULL SCENARIO EVALUATOR RUN ON HELD-OUT EVALUATION DATASET
# =============================================================================

class TestFullEvaluatorRun:
    def test_held_out_evaluation_results(self):
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        eval_dir = os.path.join(project_root, "data", "evaluation")

        evaluator = ScenarioEvaluator(data_dir=eval_dir)
        metrics = evaluator.evaluate()

        assert metrics.total_scenarios == 10
        assert metrics.evaluated_scenarios == 10
        assert metrics.unassociated_scenarios == 0
        assert metrics.association_integrity == "PASSED"
        assert len(metrics.validation_errors) == 0
        assert metrics.malicious_scenarios == 5
        assert metrics.benign_scenarios == 5
        assert metrics.true_positives == 5
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.true_negatives == 5

        # All scenarios classified
        assert len(metrics.scenario_results) == 10
        for r in metrics.scenario_results:
            assert r["classification"] in ("TP", "FP", "FN", "TN")
            assert r["matched_events_count"] > 0
            assert "Matched via audited bounds" in r["association_notes"]
