"""
Machine-Readable JSON Report Serializer & Integrity Engine for AEGIS-X (Phase 3 Checkpoint 3).

Strict Architectural Guarantees:
1. Determinism: Serializes validated IncidentReport models into canonical, deterministic
   UTF-8 JSON bytes (identical report data produces identical bytes).
2. Non-Destructive: Preserves all report sections, timeline items, and evidence references.
3. Cryptographic Report Integrity: Computes SHA-256 over exact exported JSON bytes.
   - External/Non-Self-Referential: Avoids self-referential digest paradox by keeping
     the digest in export metadata or an optional sidecar (.sha256) file.
   - Integrity vs. Authenticity Distinction:
     * Report-File Integrity: Certifies that exported JSON report bytes have not been
       altered or corrupted in storage or transit.
     * Source-Evidence Authenticity: Pertains to whether original raw telemetry events
       were genuine when ingested. A valid report digest establishes ONLY report-file
       integrity, NOT source-evidence authenticity.
4. Protected File System Boundaries: Refuses to write output into protected dataset
   directories (data/evaluation, data/development).
5. Safe Overwrite Protection: Never silently overwrites existing files unless explicit
   overwrite=True is specified.
"""

from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
import re
from typing import Optional, Union

from pydantic import BaseModel, Field

from app.reporting.models import IncidentReport

# Regex matching a valid 64-character lowercase or uppercase hex SHA-256 string
_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class JsonReportExportResult(BaseModel):
    """Metadata describing an exported JSON investigation report.

    Contains cryptographic report-file integrity verification details.
    """
    report_path: Path = Field(..., description="Absolute path to exported JSON report file")
    sha256_digest: str = Field(..., description="Cryptographic SHA-256 digest of exact exported bytes")
    byte_count: int = Field(..., description="Exact size of the exported report file in bytes")
    sidecar_path: Optional[Path] = Field(None, description="Optional path to written .sha256 sidecar file")
    generated_at_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when export occurred in UTC"
    )

    model_config = {"frozen": True, "extra": "forbid"}


def serialize_report_to_json(report: IncidentReport, indent: int = 2) -> str:
    """Serialize a validated IncidentReport to a formatted, deterministic JSON string.

    Args:
        report: Validated IncidentReport model instance.
        indent: Indentation level for readability (default: 2 spaces).

    Returns:
        Deterministic, formatted JSON string in UTF-8.

    Raises:
        TypeError: If report is not an instance of IncidentReport.
    """
    if not isinstance(report, IncidentReport):
        raise TypeError(f"Expected IncidentReport instance, got {type(report).__name__}")

    # Pydantic v2 model_dump_json guarantees deterministic field ordering
    # matching the model declarations, standard ISO 8601 UTC timestamps, and UTF-8 encoding.
    return report.model_dump_json(indent=indent)


def serialize_report_to_bytes(report: IncidentReport, indent: int = 2) -> bytes:
    """Serialize a validated IncidentReport directly to canonical UTF-8 bytes.

    Args:
        report: Validated IncidentReport model instance.
        indent: Indentation level for readability (default: 2 spaces).

    Returns:
        Exact UTF-8 encoded bytes of the formatted JSON report.
    """
    return serialize_report_to_json(report, indent=indent).encode("utf-8")


def compute_report_sha256(content: Union[bytes, str]) -> str:
    """Calculate the cryptographic SHA-256 digest over JSON report content.

    Important Distinction:
        This digest establishes Report-File Integrity (confirming that exported
        report bytes have not been tampered with or corrupted). It does NOT
        guarantee Source-Evidence Authenticity (whether original endpoint/auth
        logs were forged before ingestion).

    Args:
        content: Raw bytes or UTF-8 string of the report.

    Returns:
        Lowercase 64-character hexadecimal SHA-256 digest.
    """
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray)):
        content_bytes = bytes(content)
    else:
        raise TypeError(f"Expected bytes or str, got {type(content).__name__}")

    return hashlib.sha256(content_bytes).hexdigest().lower()


def verify_report_digest(
    content: Union[bytes, str, Path],
    expected_digest: str,
) -> bool:
    """Verify that report content matches an expected SHA-256 integrity digest.

    Safely rejects malformed digests, non-hex strings, and mismatched lengths
    without raising unhandled exceptions.

    Args:
        content: Raw report bytes, string content, or Path to an existing report file.
        expected_digest: 64-character hex string to verify against.

    Returns:
        True if the computed digest matches expected_digest; False otherwise.
    """
    if not expected_digest or not isinstance(expected_digest, str):
        return False

    cleaned_digest = expected_digest.strip().lower()
    if not _SHA256_HEX_PATTERN.fullmatch(cleaned_digest):
        return False

    try:
        if isinstance(content, Path):
            if not content.is_file():
                return False
            raw_bytes = content.read_bytes()
        elif isinstance(content, str):
            # Check if this string points to an existing file path
            try:
                candidate_path = Path(content)
                if candidate_path.is_file():
                    raw_bytes = candidate_path.read_bytes()
                else:
                    raw_bytes = content.encode("utf-8")
            except (OSError, ValueError):
                raw_bytes = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            raw_bytes = bytes(content)
        else:
            return False

        computed = hashlib.sha256(raw_bytes).hexdigest().lower()
        return hmac.compare_digest(computed, cleaned_digest)
    except Exception:
        return False


def _is_protected_directory(target_path: Path) -> bool:
    """Check if target_path falls inside protected dataset directories."""
    try:
        resolved = target_path.resolve()
        cwd = Path.cwd().resolve()
        for protected_dir_name in ("data/evaluation", "data/development"):
            protected_dir = (cwd / protected_dir_name).resolve()
            if resolved == protected_dir or resolved.is_relative_to(protected_dir):
                return True
    except (ValueError, RuntimeError, OSError):
        pass
    return False


def export_json_report(
    report: IncidentReport,
    output_path: Union[str, Path],
    overwrite: bool = False,
    write_sidecar: bool = False,
    indent: int = 2,
) -> JsonReportExportResult:
    """Export an IncidentReport to a JSON file with cryptographic integrity protection.

    Args:
        report: Validated IncidentReport instance.
        output_path: Target file path (e.g. 'reports/INC000001.json').
        overwrite: If False, raises FileExistsError if target or sidecar file exists.
        write_sidecar: If True, writes a companion '<output_path>.sha256' sidecar checksum file.
        indent: Indentation spaces for deterministic formatting.

    Returns:
        JsonReportExportResult containing path, sha256_digest, byte_count, and sidecar_path.

    Raises:
        ValueError: If output path is inside a protected dataset directory or invalid.
        FileExistsError: If output or sidecar file already exists and overwrite is False.
        OSError: If filesystem operations fail.
    """
    if not isinstance(report, IncidentReport):
        raise TypeError(f"Expected IncidentReport instance, got {type(report).__name__}")

    target_path = Path(output_path).resolve()

    # Guard: Protected dataset directories
    if _is_protected_directory(target_path):
        raise ValueError(
            f"Access Denied: Writing reports inside protected dataset directory '{target_path}' is strictly forbidden."
        )

    # Compute deterministic report bytes & digest prior to writing
    report_bytes = serialize_report_to_bytes(report, indent=indent)
    digest = compute_report_sha256(report_bytes)

    # Check sidecar path if requested
    sidecar_path: Optional[Path] = None
    if write_sidecar:
        sidecar_path = target_path.with_name(f"{target_path.name}.sha256")
        if _is_protected_directory(sidecar_path):
            raise ValueError(
                f"Access Denied: Writing sidecar inside protected directory '{sidecar_path}' is strictly forbidden."
            )

    # Overwrite protection
    if target_path.exists() and not overwrite:
        raise FileExistsError(
            f"Target report file already exists: {target_path}. Specify overwrite=True to replace."
        )

    if sidecar_path is not None and sidecar_path.exists() and not overwrite:
        raise FileExistsError(
            f"Target sidecar file already exists: {sidecar_path}. Specify overwrite=True to replace."
        )

    # Create target directory if needed
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        raise OSError(f"Failed to create report directory '{target_path.parent}': {err}") from err

    # Write report bytes
    try:
        target_path.write_bytes(report_bytes)
    except OSError as err:
        raise OSError(f"Failed to write report file '{target_path}': {err}") from err

    # Write sidecar if requested
    if sidecar_path is not None:
        try:
            # Standard sha256sum format: "<digest>  <filename>\n"
            sidecar_content = (
                f"# AEGIS-X Report File Integrity Digest\n"
                f"# Notice: Certifies exported JSON report file integrity, NOT source-evidence authenticity.\n"
                f"{digest}  {target_path.name}\n"
            )
            sidecar_path.write_text(sidecar_content, encoding="utf-8")
        except OSError as err:
            raise OSError(f"Failed to write sidecar file '{sidecar_path}': {err}") from err

    return JsonReportExportResult(
        report_path=target_path,
        sha256_digest=digest,
        byte_count=len(report_bytes),
        sidecar_path=sidecar_path,
    )
