"""
AEGIS-X Investigation Report Generation CLI (Phase 3 Checkpoint 5).

Connects the SQLite telemetry database, report context builder, JSON exporter,
and HTML exporter into a unified SOC investigation report generator.

Usage:
    python backend/generate_report.py --incident-id INC000001 --format html
    python backend/generate_report.py --incident-id INC000001 --format json --sidecar
    python backend/generate_report.py --incident-id INC000001 --format both --output-dir reports/

Exit Codes:
    0: Success
    1: Error (invalid incident ID, file exists without overwrite, protected directory, etc.)
"""

import argparse
import os
from pathlib import Path
import sys
from typing import Optional

# Ensure backend directory is in sys.path
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.database.store import AegisDatabase
from app.reporting import (
    build_incident_report_from_db,
    compute_report_sha256,
    export_html_report,
    export_json_report,
    serialize_report_to_bytes,
)
from app.reporting.json_report import _is_protected_directory


def _default_db_path() -> str:
    """Resolve default SQLite database path."""
    if os.path.exists("backend/aegis.db"):
        return "backend/aegis.db"
    script_db = os.path.join(_BACKEND_DIR, "aegis.db")
    if os.path.exists(script_db):
        return script_db
    if os.path.exists("aegis.db"):
        return "aegis.db"
    return "backend/aegis.db"


def generate_reports(
    incident_id: str,
    output_format: str = "both",
    output_dir: str = "reports",
    overwrite: bool = False,
    sidecar: bool = False,
    db_path: Optional[str] = None,
) -> dict[str, str]:
    """Core report generation pipeline connecting database and report exporters.

    Args:
        incident_id: Identifier of target incident (e.g. 'INC000001').
        output_format: 'html', 'json', or 'both'.
        output_dir: Destination directory for report artifacts.
        overwrite: If True, replaces existing files; otherwise raises FileExistsError.
        sidecar: If True, writes companion .sha256 sidecar file for JSON export.
        db_path: Optional path to SQLite database.

    Returns:
        Dictionary mapping generated artifact types to their resolved file paths.

    Raises:
        ValueError: If incident ID is unknown or output directory is protected.
        FileExistsError: If target file exists and overwrite is False.
        FileNotFoundError: If database file does not exist.
        OSError: If filesystem operations fail.
    """
    clean_incident_id = incident_id.strip()
    if not clean_incident_id:
        raise ValueError("Incident ID must be a non-empty string.")

    target_dir = Path(output_dir).resolve()
    if _is_protected_directory(target_dir):
        raise ValueError(
            f"Security Guard: Cannot output reports to protected dataset directory: '{target_dir}'"
        )

    resolved_db_path = db_path or _default_db_path()
    if not os.path.exists(resolved_db_path):
        raise FileNotFoundError(f"Database file not found at: '{resolved_db_path}'")

    # 1. Connect to SQLite database and retrieve incident context
    db = AegisDatabase(resolved_db_path)
    try:
        report = build_incident_report_from_db(clean_incident_id, db)
    finally:
        # Guarantee database connection closure on both success and exception
        db.close()

    generated_artifacts: dict[str, str] = {}
    target_dir.mkdir(parents=True, exist_ok=True)

    json_path = target_dir / f"{clean_incident_id}_report.json"
    html_path = target_dir / f"{clean_incident_id}_report.html"

    # Pre-check existing files if overwrite is not enabled
    if not overwrite:
        if output_format in ("json", "both") and json_path.exists():
            raise FileExistsError(
                f"Target JSON report already exists: '{json_path}'. Use --overwrite to replace."
            )
        if output_format in ("json", "both") and sidecar:
            sidecar_file = target_dir / f"{clean_incident_id}_report.json.sha256"
            if sidecar_file.exists():
                raise FileExistsError(
                    f"Target sidecar file already exists: '{sidecar_file}'. Use --overwrite to replace."
                )
        if output_format in ("html", "both") and html_path.exists():
            raise FileExistsError(
                f"Target HTML report already exists: '{html_path}'. Use --overwrite to replace."
            )

    json_digest: Optional[str] = None

    # 2. Export JSON if requested
    if output_format in ("json", "both"):
        json_result = export_json_report(
            report=report,
            output_path=json_path,
            overwrite=overwrite,
            write_sidecar=sidecar,
        )
        json_digest = json_result.sha256_digest
        generated_artifacts["json"] = str(json_result.report_path)
        if json_result.sidecar_path is not None:
            generated_artifacts["sidecar"] = str(json_result.sidecar_path)

    # If format is HTML only, compute companion digest over in-memory canonical JSON bytes
    # so the HTML report still includes the canonical JSON integrity digest
    if output_format == "html" and json_digest is None:
        canonical_bytes = serialize_report_to_bytes(report)
        json_digest = compute_report_sha256(canonical_bytes)

    # 3. Export HTML if requested
    if output_format in ("html", "both"):
        out_html = export_html_report(
            report=report,
            output_path=html_path,
            overwrite=overwrite,
            json_digest=json_digest,
        )
        generated_artifacts["html"] = str(out_html)

    return generated_artifacts


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser with comprehensive help."""
    parser = argparse.ArgumentParser(
        prog="generate_report.py",
        description="AEGIS-X Investigation Report Generator — Exports audit-ready JSON and standalone HTML reports.",
        epilog=(
            "Examples:\n"
            "  python backend/generate_report.py --incident-id INC000001 --format html\n"
            "  python backend/generate_report.py --incident-id INC000001 --format json --sidecar\n"
            "  python backend/generate_report.py --incident-id INC000001 --format both --output-dir reports/ --overwrite\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--incident-id",
        type=str,
        required=True,
        help="Target incident ID to generate report for (e.g. INC000001).",
    )
    parser.add_argument(
        "--format",
        choices=["html", "json", "both"],
        default="both",
        help="Report export format: 'html', 'json', or 'both' (default: both).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Destination directory for exported reports (default: reports/).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly permit overwriting existing report files.",
    )
    parser.add_argument(
        "--sidecar",
        action="store_true",
        help="Write cryptographic SHA-256 sidecar file (.sha256) for JSON exports.",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to SQLite database (default: backend/aegis.db).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI execution entrypoint. Returns 0 on success, non-zero on error."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        results = generate_reports(
            incident_id=args.incident_id,
            output_format=args.format,
            output_dir=args.output_dir,
            overwrite=args.overwrite,
            sidecar=args.sidecar,
            db_path=args.db_path,
        )

        print("=" * 68)
        print("AEGIS-X INCIDENT REPORT GENERATION COMPLETE")
        print("=" * 68)
        print(f"Incident ID:    {args.incident_id.strip()}")
        print(f"Export Format:  {args.format.upper()}")
        print(f"Output Directory: {os.path.abspath(args.output_dir)}")
        print("-" * 68)
        for artifact_type, file_path in results.items():
            size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            print(f"  [{artifact_type.upper():<7}] {file_path} ({size:,} bytes)")
        print("=" * 68)
        return 0

    except FileExistsError as err:
        print(f"Error: {err}", file=sys.stderr)
        print("Hint: Specify --overwrite to replace existing report files.", file=sys.stderr)
        return 1
    except (ValueError, FileNotFoundError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected Error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
