"""
AEGIS-X Evaluation CLI Tool.

Evaluates detection performance on a synthetic dataset (default: data/evaluation/)
at the scenario level with fail-closed integrity validation.

Usage:
    python evaluate.py
    python evaluate.py --data-dir ../data/evaluation
    python evaluate.py --json-output ../eval_results.json
"""

import argparse
import json
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.evaluation.evaluator import ScenarioEvaluator


def is_path_inside_dir(target_path: str, dir_path: str) -> bool:
    """Check if target_path is inside dir_path using os.path.realpath and os.path.commonpath.

    Handles Windows drive differences safely without crashing.
    """
    try:
        target_real = os.path.realpath(target_path)
        dir_real = os.path.realpath(dir_path)
        # On Windows, os.path.commonpath raises ValueError if paths are on different drives
        return os.path.commonpath([dir_real, target_real]) == dir_real
    except (ValueError, OSError):
        # Different drive letters or invalid paths
        return False


def format_terminal_report(metrics) -> str:
    """Format evaluation metrics as a clean, readable terminal report."""
    lines = []
    lines.append("=" * 70)
    lines.append("AEGIS-X THREAT DETECTION EVALUATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Dataset Name:          {metrics.dataset_name}")
    lines.append(f"Data Directory:        {metrics.data_dir}")
    lines.append(f"Evaluated At:          {metrics.evaluated_at}")
    lines.append(f"Association Integrity: {metrics.association_integrity}")
    lines.append("-" * 70)
    lines.append(f"Total Scenarios:       {metrics.total_scenarios} ({metrics.malicious_scenarios} Malicious, {metrics.benign_scenarios} Benign)")
    lines.append(f"Evaluated Scenarios:   {metrics.evaluated_scenarios}")
    lines.append(f"Unassociated:          {metrics.unassociated_scenarios}")
    lines.append(f"Confusion Matrix:      TP={metrics.true_positives} | FP={metrics.false_positives} | FN={metrics.false_negatives} | TN={metrics.true_negatives}")
    lines.append("-" * 70)
    lines.append("PRIMARY EVALUATION METRICS:")
    lines.append(f"  • Precision:             {metrics.precision:.4f}  (TP / [TP + FP])")
    lines.append(f"  • Recall (Sensitivity):  {metrics.recall:.4f}  (TP / [TP + FN])")
    lines.append(f"  • F1 Score:              {metrics.f1_score:.4f}  (Harmonic mean of P & R)")
    lines.append(f"  • False Positive Rate:   {metrics.false_positive_rate:.4f}  (FP / [FP + TN])")
    lines.append(f"  • Overall Accuracy:      {metrics.accuracy:.4f}  ([TP + TN] / Evaluated)")
    lines.append("-" * 70)
    lines.append("SCENARIO-BY-SCENARIO BREAKDOWN:")

    for r in metrics.scenario_results:
        tag = r["classification"]
        if tag in ("TP", "TN"):
            marker = "✅"
        elif tag == "UNASSOCIATED":
            marker = "⚠️"
        else:
            marker = "❌"

        mal_str = "MALICIOUS" if r["is_malicious"] else "BENIGN"
        lines.append(f"\n  {marker} [{tag}] {r['scenario_id']}: {r['name']} ({mal_str})")
        lines.append(f"      Matched Events:   {r['matched_events_count']}")
        lines.append(f"      Expected Rules:   {r['expected_rules'] if r['expected_rules'] else 'None (Clean)'}")
        lines.append(f"      Triggered Rules:  {r['triggered_rules'] if r['triggered_rules'] else 'None'}")
        lines.append(f"      Rule Coverage:    {int(r['rule_coverage'] * 100)}%")
        lines.append(f"      Description:      {r['description']}")
        if r.get("association_notes"):
            lines.append(f"      Mapping Method:   {r['association_notes']}")

    lines.append("\n" + "-" * 70)
    lines.append("ENGINE BEHAVIOR NOTES:")
    lines.append("  • Scenario S005 (Multi-Stage Attack): Triggered privilege_escalation and")
    lines.append("    suspicious_process (rule coverage: 67%). The preceding brute-force")
    lines.append("    sequence on Nov 22 did not trigger a separate detection because the")
    lines.append("    Phase 1 detection engine enforces one brute-force detection per user")
    lines.append("    per run, and user 'bob' had already triggered a detection in S001 on Nov 21.")

    lines.append("\n" + "=" * 70)
    lines.append("END OF EVALUATION REPORT")
    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AEGIS-X Scenario Evaluation CLI")
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Path to evaluation dataset directory (default: data/evaluation/)",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Optional path to write machine-readable JSON metrics (must NOT be inside held-out dir)",
    )
    args = parser.parse_args()

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if args.data_dir:
        eval_dir = os.path.abspath(args.data_dir)
    else:
        eval_dir = os.path.join(project_root, "data", "evaluation")

    if not os.path.exists(eval_dir):
        print(f"Error: Evaluation data directory does not exist: {eval_dir}", file=sys.stderr)
        sys.exit(1)

    # Containment check using os.path.realpath() and os.path.commonpath()
    # Protect both data/evaluation/ and data/development/ as benchmark dataset directories
    if args.json_output:
        out_path = os.path.realpath(args.json_output)
        protected_dirs = [
            os.path.realpath(eval_dir),
            os.path.realpath(os.path.join(project_root, "data", "evaluation")),
            os.path.realpath(os.path.join(project_root, "data", "development")),
        ]
        # Remove duplicates while preserving order
        unique_protected = []
        for p in protected_dirs:
            if p not in unique_protected and os.path.exists(p):
                unique_protected.append(p)

        for pdir in unique_protected:
            if is_path_inside_dir(out_path, pdir):
                print(
                    f"Security/Integrity Error: --json-output cannot be written inside benchmark "
                    f"dataset directory: {pdir}",
                    file=sys.stderr,
                )
                sys.exit(1)

    evaluator = ScenarioEvaluator(data_dir=eval_dir)
    metrics = evaluator.evaluate(fail_closed=False)

    # Fail closed on association validation errors: CLI must not produce normal evaluation metrics
    if metrics.association_integrity != "PASSED" or metrics.validation_errors:
        print("=" * 70, file=sys.stderr)
        print("CRITICAL: SCENARIO ASSOCIATION INTEGRITY FAILED", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Association validation reported {len(metrics.validation_errors)} error(s):", file=sys.stderr)
        for err in metrics.validation_errors:
            print(f"  • {err}", file=sys.stderr)
        print("\nEvaluation aborted to preserve metric integrity.", file=sys.stderr)
        sys.exit(2)

    # Print terminal report
    print(format_terminal_report(metrics))

    # Write JSON output if requested
    if args.json_output:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(metrics.to_dict(), f, indent=2)
        print(f"\nMachine-readable metrics saved to: {out_path}")


if __name__ == "__main__":
    main()
