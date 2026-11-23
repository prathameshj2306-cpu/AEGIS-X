"""
AEGIS-X Analysis Pipeline — CLI entry point.

Ties together all Phase 1 modules into a runnable pipeline:
1. Generate synthetic data (or use existing files).
2. Ingest CSV/JSON logs.
3. Run detection engine (4 rules).
4. Correlate detections into incidents.
5. Classify severity.
6. Store results in SQLite.
7. Print summary.

Usage:
    python run_pipeline.py                  # Generate data + full analysis
    python run_pipeline.py --generate-only  # Only generate datasets
    python run_pipeline.py --data-dir PATH  # Analyze existing data directory
"""

import argparse
import json
import os
import sys

# Add the backend directory to path so app module is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import AegisConfig, AuthorizedSchedule
from app.ingestion.ingestor import ingest_csv, ingest_json
from app.detection.engine import run_detection
from app.correlation.correlator import correlate_detections, build_incidents
from app.severity.classifier import classify_all
from app.simulator.generator import generate_dataset
from app.database.store import AegisDatabase
from app.schemas.events import EventSource


def main():
    parser = argparse.ArgumentParser(description="AEGIS-X Analysis Pipeline")
    parser.add_argument("--generate-only", action="store_true",
                        help="Only generate synthetic datasets, don't analyze")
    parser.add_argument("--data-dir", type=str, default=None,
                        help="Directory containing auth_events.csv and endpoint_events.csv")
    parser.add_argument("--db-path", type=str, default="aegis.db",
                        help="SQLite database file path")
    parser.add_argument("--dev-seed", type=int, default=42,
                        help="Random seed for development dataset")
    parser.add_argument("--eval-seed", type=int, default=7777,
                        help="Random seed for evaluation dataset")
    args = parser.parse_args()

    # Resolve paths relative to project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dev_dir = os.path.join(project_root, "data", "development")
    eval_dir = os.path.join(project_root, "data", "evaluation")

    # --- Step 0: Configuration ---
    config = AegisConfig()
    # Add authorized schedule for the admin user (benign night login scenario)
    config.authorized_schedules.append(AuthorizedSchedule(
        user="admin",
        days=["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"],
        start="00:00",
        end="23:59",
        timezone="UTC",
    ))

    # --- Step 1: Generate synthetic data ---
    print("=" * 60)
    print("AEGIS-X Analysis Pipeline")
    print("=" * 60)

    if args.data_dir is None:
        print("\n[1/6] Generating synthetic datasets...")
        dev_summary = generate_dataset(
            seed=args.dev_seed,
            output_dir=dev_dir,
            dataset_name="development",
        )
        print(f"  Development dataset: {dev_summary['total_events']} events "
              f"({dev_summary['malicious_scenarios']} malicious, "
              f"{dev_summary['benign_scenarios']} benign)")
        print(f"  Output: {dev_dir}")

        eval_summary = generate_dataset(
            seed=args.eval_seed,
            output_dir=eval_dir,
            dataset_name="evaluation",
        )
        print(f"  Evaluation dataset: {eval_summary['total_events']} events "
              f"({eval_summary['malicious_scenarios']} malicious, "
              f"{eval_summary['benign_scenarios']} benign)")
        print(f"  Output: {eval_dir}")

        if args.generate_only:
            print("\nDatasets generated. Exiting (--generate-only).")
            return

        data_dir = dev_dir
    else:
        data_dir = args.data_dir

    # --- Step 2: Ingest data ---
    print(f"\n[2/6] Ingesting data from: {data_dir}")

    all_events = []

    # Ingest auth events
    auth_csv = os.path.join(data_dir, "auth_events.csv")
    auth_json = os.path.join(data_dir, "auth_events.json")

    if os.path.exists(auth_csv):
        result = ingest_csv(auth_csv, default_source=EventSource.AUTHENTICATION, id_offset=1)
        print(f"  Auth CSV: {result.success_count} events, {result.error_count} errors")
        all_events.extend(result.events)
    elif os.path.exists(auth_json):
        result = ingest_json(auth_json, default_source=EventSource.AUTHENTICATION, id_offset=1)
        print(f"  Auth JSON: {result.success_count} events, {result.error_count} errors")
        all_events.extend(result.events)
    else:
        print("  WARNING: No auth events file found.")

    # Ingest endpoint events
    offset = len(all_events) + 1
    endpoint_csv = os.path.join(data_dir, "endpoint_events.csv")
    endpoint_json = os.path.join(data_dir, "endpoint_events.json")

    if os.path.exists(endpoint_csv):
        result = ingest_csv(endpoint_csv, default_source=EventSource.ENDPOINT, id_offset=offset)
        print(f"  Endpoint CSV: {result.success_count} events, {result.error_count} errors")
        all_events.extend(result.events)
    elif os.path.exists(endpoint_json):
        result = ingest_json(endpoint_json, default_source=EventSource.ENDPOINT, id_offset=offset)
        print(f"  Endpoint JSON: {result.success_count} events, {result.error_count} errors")
        all_events.extend(result.events)
    else:
        print("  WARNING: No endpoint events file found.")

    print(f"  Total events ingested: {len(all_events)}")

    if not all_events:
        print("\nNo events to analyze. Exiting.")
        return

    # --- Step 3: Detection ---
    print("\n[3/6] Running detection engine...")
    detections = run_detection(all_events, config)
    print(f"  Total detections: {len(detections)}")

    # Group by rule
    by_rule: dict[str, int] = {}
    for d in detections:
        by_rule[d.rule_name] = by_rule.get(d.rule_name, 0) + 1
    for rule, count in sorted(by_rule.items()):
        print(f"    {rule}: {count}")

    # --- Step 4: Correlation ---
    print("\n[4/6] Correlating detections into incidents...")
    groups = correlate_detections(detections, all_events, config)
    incidents = build_incidents(groups)
    print(f"  Correlation groups: {len(groups)}")
    print(f"  Incidents created: {len(incidents)}")

    # --- Step 5: Severity classification ---
    print("\n[5/6] Classifying severity...")
    incidents = classify_all(incidents, config)

    by_severity: dict[str, int] = {}
    for inc in incidents:
        sev = inc.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"    {sev}: {by_severity.get(sev, 0)}")

    # --- Step 6: Persist to SQLite ---
    print(f"\n[6/6] Persisting to SQLite ({args.db_path})...")
    db = AegisDatabase(args.db_path)
    db.clear_all()  # Fresh analysis
    run_id = db.start_run(json.dumps({"seed": args.dev_seed}))
    db.store_events(all_events)
    db.store_detections(detections)
    db.store_incidents(incidents)
    db.complete_run(run_id, len(all_events), len(detections), len(incidents))
    print(f"  Stored: {len(all_events)} events, {len(detections)} detections, "
          f"{len(incidents)} incidents")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"\nTotal events analyzed: {len(all_events)}")
    print(f"Total detections: {len(detections)}")
    print(f"Total incidents: {len(incidents)}")
    print(f"\nIncidents by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = by_severity.get(sev, 0)
        marker = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
        print(f"  {marker} {sev}: {count}")

    print("\nIncident details:")
    for inc in incidents:
        print(f"\n  [{inc.severity.value}] {inc.incident_id}: {inc.title}")
        print(f"    Patterns: {', '.join(inc.detected_patterns)}")
        print(f"    User: {inc.user or 'N/A'} | Device: {inc.device or 'N/A'}")
        print(f"    Time: {inc.start_time.strftime('%Y-%m-%d %H:%M:%S')} → "
              f"{inc.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Evidence events: {len(inc.evidence_event_ids)}")
        print(f"    Rationale: {inc.severity_rationale}")

    db.close()
    print(f"\nDatabase saved to: {os.path.abspath(args.db_path)}")


if __name__ == "__main__":
    main()
