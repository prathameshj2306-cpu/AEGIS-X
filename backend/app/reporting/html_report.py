"""
Human-Auditable HTML Incident Report Generator for AEGIS-X (Phase 3 Checkpoint 4).

Generates standalone, SOC-grade dark-themed HTML investigation reports from
validated IncidentReport models.

Strict Architectural & Security Guarantees:
1. XSS Prevention: All dynamic data (usernames, processes, IPs, raw_data, AI outputs)
   is strictly escaped using html.escape(..., quote=True).
2. Zero Remote Assets: Self-contained HTML. No external CSS, fonts, CDN scripts, or tracking.
3. No Inline JavaScript: Completely static report with zero executable JavaScript.
4. Visual Separation: Deterministic SOC findings are cleanly separated from AI-assisted
   narratives.
5. Missing Data Transparency: Prominently highlights missing or unreconciled evidence
   without ever fabricating records.
6. Print-Ready: Full @media print styling allowing analysts to Save as PDF from browser.
7. File System Safety: Protected dataset directories (data/evaluation, data/development)
   are guarded against accidental writes. Overwrite protection is enforced by default.
"""

from datetime import datetime
import html
from pathlib import Path
from typing import Any, Optional, Union

from app.reporting.json_report import _is_protected_directory
from app.reporting.models import IncidentReport


def _esc(val: Any) -> str:
    """Safely escape any value for secure HTML insertion."""
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


def _render_severity_badge(severity: str) -> str:
    """Render a styled severity badge for screen and print."""
    sev = (severity or "UNKNOWN").upper()
    color_map = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
    }
    badge_class = color_map.get(sev, "badge-unknown")
    return f'<span class="badge {badge_class}">{_esc(sev)}</span>'


def _render_verification_badge(status: str) -> str:
    """Render a styled evidence verification status badge."""
    status_upper = (status or "NOT_AVAILABLE").upper()
    badge_map = {
        "VERIFIED": ("badge-verification-verified", "VERIFIED"),
        "PARTIAL": ("badge-verification-partial", "PARTIAL"),
        "UNVERIFIED": ("badge-verification-unverified", "UNVERIFIED"),
        "NOT_AVAILABLE": ("badge-verification-na", "NOT AVAILABLE"),
        "PENDING_PHASE_2_CHECKPOINT_3": ("badge-medium", "PENDING_PHASE_2_CHECKPOINT_3"),
    }
    badge_class, label = badge_map.get(status_upper, ("badge-verification-na", status_upper))
    return f'<span class="badge {badge_class} font-mono">{_esc(label)}</span>'


def _render_verification_body(ev) -> str:
    """Render the full Evidence Verification section body."""
    parts = []

    if not ev.verification_performed:
        parts.append(f'''
        <div class="banner banner-neutral">
          Evidence verification has not been performed for this incident.
        </div>
        <p class="muted" style="font-size: 12px; margin-bottom: 12px;">
          {_esc(ev.details)}
        </p>
        <div class="grid-2">
          <div class="metric-card">
            <div class="metric-label">Total Incident Evidence Events</div>
            <div class="metric-value font-mono">{_esc(str(ev.total_evidence_count))}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Verified AI Citations</div>
            <div class="metric-value font-mono">{_esc(str(ev.ai_cited_count))}</div>
          </div>
        </div>
        ''')
        return "\n".join(parts)

    # Verification was performed — render full details
    # Status banner
    if ev.status == "VERIFIED":
        parts.append('<div class="banner banner-success">&check; Evidence Verification: All evidence resolved and validated against ground-truth database records.</div>')
    elif ev.status == "PARTIAL":
        parts.append('<div class="banner banner-warning">&#9888; Evidence Verification: Evidence resolved with partial coverage. Some citations or attributes are incomplete.</div>')
    elif ev.status == "UNVERIFIED":
        parts.append('<div class="banner banner-danger">&#10006; Evidence Verification: Unable to fully verify incident evidence. See rationale and discrepancies below.</div>')
    else:
        parts.append(f'<div class="banner banner-neutral">Evidence Verification Status: {_esc(ev.status)}</div>')

    # Metrics grid
    parts.append(f'''
    <div class="grid-4" style="margin-top: 12px; margin-bottom: 16px;">
      <div class="metric-card">
        <div class="metric-label">Total Evidence</div>
        <div class="metric-value font-mono">{_esc(str(ev.total_evidence_count))}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Resolved from Database</div>
        <div class="metric-value font-mono">{_esc(str(ev.resolved_evidence_count))}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Missing Evidence</div>
        <div class="metric-value font-mono" style="color: {'var(--accent-red)' if ev.missing_evidence_count > 0 else '#ffffff'};">{_esc(str(ev.missing_evidence_count))}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Valid Citations</div>
        <div class="metric-value font-mono">{_esc(str(ev.valid_citation_count))} / {_esc(str(ev.cited_evidence_count))}</div>
      </div>
    </div>
    ''')

    # Verification rationale
    if ev.verification_rationale:
        rationale_items = "".join(
            f"<li>{_esc(str(r))}</li>" for r in ev.verification_rationale
        )
        parts.append(f'''
        <div class="card" style="background-color: var(--bg-card-alt); margin-bottom: 16px;">
          <div class="card-title">Verification Rationale</div>
          <ul class="rec-list">{rationale_items}</ul>
        </div>
        ''')

    # Invalid/missing evidence chips
    if ev.invalid_citation_ids:
        inv_chips = "".join(
            f'<span class="chip chip-mono" style="background-color: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626;">{_esc(eid)}</span>'
            for eid in ev.invalid_citation_ids
        )
        parts.append(f'''
        <div style="margin-bottom: 12px;">
          <div class="metric-label" style="margin-bottom: 6px;">Invalid Citation IDs:</div>
          <div class="chips-container">{inv_chips}</div>
        </div>
        ''')

    if ev.missing_evidence_ids:
        miss_chips = "".join(
            f'<span class="chip chip-mono" style="background-color: #78350f; color: #fde047; border: 1px solid #d97706;">{_esc(eid)}</span>'
            for eid in ev.missing_evidence_ids
        )
        parts.append(f'''
        <div style="margin-bottom: 12px;">
          <div class="metric-label" style="margin-bottom: 6px;">Missing Evidence IDs:</div>
          <div class="chips-container">{miss_chips}</div>
        </div>
        ''')

    if ev.verified_evidence_ids:
        ver_chips = "".join(
            f'<span class="chip chip-mono chip-cited">{_esc(eid)}</span>'
            for eid in ev.verified_evidence_ids
        )
        parts.append(f'''
        <div style="margin-bottom: 12px;">
          <div class="metric-label" style="margin-bottom: 6px;">Verified Evidence IDs:</div>
          <div class="chips-container">{ver_chips}</div>
        </div>
        ''')

    # Discrepancies table
    if ev.discrepancies:
        disc_rows = ""
        for d in ev.discrepancies:
            disc_rows += f'''
            <tr>
              <td class="font-mono">{_esc(d.event_id or "—")}</td>
              <td><span class="chip chip-mono" style="background-color: #7f1d1d; color: #fca5a5;">{_esc(d.mismatch_type)}</span></td>
              <td>{_esc(d.expected_value or "—")}</td>
              <td>{_esc(d.actual_value or "—")}</td>
              <td>{_esc(d.explanation)}</td>
            </tr>
            '''
        parts.append(f'''
        <div class="card" style="background-color: var(--bg-card-alt); margin-bottom: 16px;">
          <div class="card-title">Structured Claims &amp; Discrepancies ({len(ev.discrepancies)})</div>
          <div class="table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Mismatch Type</th>
                  <th>Expected</th>
                  <th>Actual</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {disc_rows}
              </tbody>
            </table>
          </div>
        </div>
        ''')

    # Database error
    if ev.database_error:
        parts.append(f'''
        <div class="banner banner-danger" style="margin-top: 8px;">
          <strong>Database Error:</strong> {_esc(ev.database_error)}
        </div>
        ''')

    return "\n".join(parts)


def render_incident_report_to_html(
    report: IncidentReport,
    json_digest: Optional[str] = None,
) -> str:
    """Render a validated IncidentReport to a standalone, secure HTML document.

    Args:
        report: Validated IncidentReport instance.
        json_digest: Optional 64-character SHA-256 digest of the companion JSON report.

    Returns:
        Self-contained HTML string.
    """
    if not isinstance(report, IncidentReport):
        raise TypeError(f"Expected IncidentReport instance, got {type(report).__name__}")

    # Helper formatters
    def fmt_time(dt: Optional[datetime]) -> str:
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Detection findings cards
    detection_items_html = []
    for d in report.detection_findings:
        event_chips = "".join(
            f'<span class="chip chip-mono">{_esc(eid)}</span>' for eid in d.triggering_event_ids
        )
        detection_items_html.append(
            f"""
            <div class="card detection-card">
              <div class="card-header-flex">
                <div class="detection-title-group">
                  <span class="detection-id font-mono">{_esc(d.detection_id)}</span>
                  <span class="detection-name">{_esc(d.rule_name)}</span>
                </div>
                <div class="badge-confidence">{_esc(d.confidence.upper())} CONFIDENCE</div>
              </div>
              <p class="detection-desc">{_esc(d.explanation)}</p>
              <div class="detection-meta">
                <div><strong>Timestamp:</strong> {fmt_time(d.timestamp)}</div>
                <div><strong>User:</strong> {_esc(d.user or "N/A")}</div>
                <div><strong>Device:</strong> {_esc(d.device or "N/A")}</div>
              </div>
              <div class="detection-triggers">
                <span class="meta-label">Triggering Evidence Events:</span>
                <div class="chips-container">{event_chips}</div>
              </div>
            </div>
            """
        )
    detections_block = "".join(detection_items_html) if detection_items_html else "<p class='muted'>No detections registered.</p>"

    # 2. Timeline table rows
    timeline_rows = []
    for ev in report.timeline:
        primary_badge = (
            '<span class="badge-primary-evidence" title="Primary incident evidence">PRIMARY</span>'
            if ev.is_primary_evidence
            else '<span class="badge-context-evidence" title="Surrounding contextual event">CONTEXT</span>'
        )
        raw_json_str = " ".join(f"{k}={v}" for k, v in ev.raw_data.items()) if ev.raw_data else ""
        timeline_rows.append(
            f"""
            <tr class="timeline-row">
              <td class="font-mono whitespace-nowrap">{fmt_time(ev.timestamp)}</td>
              <td class="font-mono">{_esc(ev.event_id)} {primary_badge}</td>
              <td><span class="chip chip-mono">{_esc(ev.event_type)}</span></td>
              <td>{_esc(ev.source)}</td>
              <td>{_esc(ev.user or "-")}</td>
              <td>{_esc(ev.device or "-")}</td>
              <td class="font-mono">{_esc(ev.ip or "-")}</td>
              <td class="font-mono break-all">{_esc(ev.process or "-")}</td>
              <td class="raw-data-cell"><pre class="raw-data-pre">{_esc(raw_json_str)}</pre></td>
            </tr>
            """
        )
    timeline_block = "".join(timeline_rows) if timeline_rows else "<tr><td colspan='9' class='text-center muted'>No events recorded.</td></tr>"

    # 3. Recommendations rendering
    recs = report.recommendations
    def render_rec_list(items: list[str], empty_msg: str) -> str:
        if not items:
            return f'<p class="muted">{_esc(empty_msg)}</p>'
        li_items = "".join(f"<li>{_esc(item)}</li>" for item in items)
        return f'<ul class="rec-list">{li_items}</ul>'

    # 4. AI Investigation Section
    ai = report.ai_investigation
    if ai.has_ai_analysis and ai.status == "SUCCESS":
        ai_banner = '<div class="banner banner-success">AI Investigation Analysis &bull; SLM Analysis Completed Successfully</div>'
        ai_model_badge = f'<span class="chip chip-mono">Model: {_esc(ai.model or "Local SLM")}</span>'
        ai_fallback_badge = '<span class="badge badge-low">Citation References Validated</span>'
    elif ai.is_fallback:
        ai_banner = '<div class="banner banner-warning">Deterministic Fallback Triage (Local SLM Unavailable or Ambiguous)</div>'
        ai_model_badge = '<span class="chip chip-mono">Engine: Deterministic Fallback</span>'
        ai_fallback_badge = '<span class="badge badge-medium">Fallback Mode</span>'
    else:
        ai_banner = '<div class="banner banner-neutral">Deterministic Triage Only (No AI Analysis Executed)</div>'
        ai_model_badge = '<span class="chip chip-mono">Mode: Offline Deterministic</span>'
        ai_fallback_badge = '<span class="badge badge-low">Deterministic Only</span>'

    cited_chips = "".join(
        f'<span class="chip chip-mono chip-cited">{_esc(eid)}</span>' for eid in ai.cited_event_ids
    ) or "<span class='muted'>None cited</span>"

    uncited_chips = "".join(
        f'<span class="chip chip-mono chip-uncited">{_esc(eid)}</span>' for eid in ai.uncited_evidence_ids
    ) or "<span class='muted'>All evidence cited</span>"

    ai_notes_html = f'<div class="ai-notes"><p><strong>SOC Notes:</strong> {_esc(ai.notes)}</p></div>' if ai.notes else ""

    # 5. Missing Evidence / Reconciliation Notice
    inv = report.evidence_inventory
    missing_banner = ""
    if inv.missing_event_ids or inv.missing_detection_ids:
        missing_parts = []
        if inv.missing_event_ids:
            missing_parts.append(f"Missing Event IDs: {', '.join(_esc(e) for e in inv.missing_event_ids)}")
        if inv.missing_detection_ids:
            missing_parts.append(f"Missing Detection IDs: {', '.join(_esc(d) for d in inv.missing_detection_ids)}")
        missing_banner = f"""
        <div class="banner banner-danger alert-box">
          <strong>AUDIT WARNING: Unresolved Telemetry References Detected</strong><br>
          {'; '.join(missing_parts)}.<br>
          <em>These records could not be resolved from active telemetry or storage. AEGIS-X never fabricates synthetic data.</em>
        </div>
        """
    else:
        missing_banner = """
        <div class="banner banner-success-soft">
          &check; All referenced evidence events and detections successfully reconciled against telemetry store.
        </div>
        """

    # 6. Report Integrity Block
    integrity_block = ""
    if json_digest:
        integrity_block = f"""
        <div class="card integrity-card">
          <div class="card-title">Exported Report Integrity Verification</div>
          <div class="integrity-body">
            <div class="digest-label">Companion Machine-Readable JSON SHA-256 Digest:</div>
            <div class="digest-value font-mono">{_esc(json_digest)}</div>
            <p class="integrity-notice">
              <strong>Notice:</strong> This cryptographic SHA-256 digest establishes <strong>report-file integrity</strong>
              (verifying that the exported JSON investigation report bytes have not been tampered with or corrupted).
              It does <em>NOT</em> certify <strong>source-evidence authenticity</strong> (whether the original raw
              security logs were forged prior to ingestion).
            </p>
          </div>
        </div>
        """

    # 7. Pattern badges
    pattern_badges = "".join(
        f'<span class="chip chip-pattern">{_esc(p)}</span>' for p in report.incident_overview.detected_patterns
    ) or "<span class='muted'>None</span>"

    # Assemble HTML document
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_esc(report.header.report_title)} - {_esc(report.header.incident_id)}</title>
  <style>
    /* AEGIS-X SOC Theme: Premium Dark Cybersecurity Investigation */
    :root {{
      --bg-main: #0b0f19;
      --bg-surface: #111827;
      --bg-card: #1f2937;
      --bg-card-alt: #162032;
      --border-color: #374151;
      --border-subtle: #243042;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --text-subtle: #6b7280;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --accent-red: #ef4444;
      --accent-orange: #f97316;
      --accent-amber: #f59e0b;
      --accent-green: #10b981;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      background-color: var(--bg-main);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 24px;
    }}

    .container {{
      max-width: 1280px;
      margin: 0 auto;
    }}

    /* Typography & Utilities */
    h1, h2, h3, h4 {{
      color: #ffffff;
      font-weight: 700;
      letter-spacing: -0.01em;
    }}
    h1 {{ font-size: 24px; }}
    h2 {{ font-size: 18px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }}
    h3 {{ font-size: 15px; margin-bottom: 8px; }}
    .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
    .text-center {{ text-align: center; }}
    .muted {{ color: var(--text-muted); }}
    .whitespace-nowrap {{ white-space: nowrap; }}
    .break-all {{ word-break: break-all; }}

    /* Header */
    header.report-header {{
      background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px 24px;
      margin-bottom: 24px;
    }}
    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 12px;
      margin-bottom: 12px;
    }}
    .brand-group {{ display: flex; align-items: center; gap: 12px; }}
    .platform-name {{
      font-size: 20px;
      font-weight: 800;
      color: var(--accent-cyan);
      letter-spacing: 0.05em;
    }}
    .platform-tagline {{ font-size: 12px; color: var(--text-muted); }}
    .header-meta {{ font-size: 12px; color: var(--text-muted); text-align: right; }}
    .header-main {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .report-title {{ font-size: 22px; }}
    .incident-badge-group {{ display: flex; align-items: center; gap: 12px; }}

    /* Cards */
    .card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 18px 20px;
      margin-bottom: 20px;
    }}
    .card-title {{
      font-size: 14px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 0.05em;
      border: 1px solid transparent;
    }}
    .badge-critical {{ background-color: #7f1d1d; color: #fca5a5; border-color: #dc2626; }}
    .badge-high {{ background-color: #7c2d12; color: #fdba74; border-color: #ea580c; }}
    .badge-medium {{ background-color: #78350f; color: #fde047; border-color: #d97706; }}
    .badge-low {{ background-color: #1e3a8a; color: #93c5fd; border-color: #2563eb; }}
    .badge-unknown {{ background-color: #374151; color: #e5e7eb; border-color: #4b5563; }}
    .badge-verification-verified {{ background-color: #064e3b; color: #a7f3d0; border-color: #059669; }}
    .badge-verification-partial {{ background-color: #78350f; color: #fde047; border-color: #d97706; }}
    .badge-verification-unverified {{ background-color: #7f1d1d; color: #fca5a5; border-color: #dc2626; }}
    .badge-verification-na {{ background-color: #374151; color: #9ca3af; border-color: #4b5563; }}
    .badge-primary-evidence {{
      background-color: #7f1d1d;
      color: #fca5a5;
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 3px;
      margin-left: 4px;
    }}
    .badge-context-evidence {{
      background-color: #1f2937;
      color: #9ca3af;
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 3px;
      border: 1px solid #374151;
      margin-left: 4px;
    }}
    .badge-confidence {{
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-cyan);
      background: rgba(6, 182, 212, 0.1);
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid rgba(6, 182, 212, 0.3);
    }}

    /* Chips */
    .chip {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      background-color: #374151;
      color: #e5e7eb;
      margin: 2px 4px 2px 0;
    }}
    .chip-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .chip-pattern {{ background-color: #1e3a8a; color: #bfdbfe; border: 1px solid #2563eb; }}
    .chip-cited {{ background-color: #064e3b; color: #a7f3d0; border: 1px solid #059669; }}
    .chip-uncited {{ background-color: #374151; color: #9ca3af; }}
    .chips-container {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }}

    /* Grids */
    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
    .grid-3 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
    .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }}

    .metric-card {{
      background-color: var(--bg-card-alt);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 12px 14px;
    }}
    .metric-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
    .metric-value {{ font-size: 15px; font-weight: 700; color: #ffffff; margin-top: 4px; }}

    /* Banners */
    .banner {{
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 16px;
      font-weight: 600;
    }}
    .banner-success {{ background-color: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid #059669; }}
    .banner-warning {{ background-color: rgba(245, 158, 11, 0.15); color: #fde68a; border: 1px solid #d97706; }}
    .banner-danger {{ background-color: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid #dc2626; }}
    .banner-neutral {{ background-color: rgba(107, 114, 128, 0.15); color: #d1d5db; border: 1px solid #4b5563; }}
    .banner-success-soft {{ background-color: rgba(16, 185, 129, 0.08); color: #a7f3d0; border: 1px solid rgba(16, 185, 129, 0.2); }}

    /* Detection card */
    .detection-card {{ background-color: var(--bg-card-alt); border-left: 4px solid var(--accent-cyan); }}
    .card-header-flex {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
    .detection-id {{ font-size: 13px; color: var(--accent-cyan); font-weight: 700; margin-right: 8px; }}
    .detection-name {{ font-size: 14px; font-weight: 700; color: #ffffff; }}
    .detection-desc {{ font-size: 13px; color: #e5e7eb; margin-bottom: 10px; }}
    .detection-meta {{ display: flex; gap: 24px; font-size: 12px; color: var(--text-muted); margin-bottom: 10px; flex-wrap: wrap; }}

    /* Tables */
    .table-container {{
      overflow-x: auto;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      margin-top: 10px;
    }}
    table.data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }}
    table.data-table th {{
      background-color: #111827;
      color: #9ca3af;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.05em;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-color);
    }}
    table.data-table td {{
      padding: 8px 12px;
      border-bottom: 1px solid var(--border-subtle);
      color: #e5e7eb;
    }}
    table.data-table tr:nth-child(even) td {{
      background-color: rgba(255, 255, 255, 0.02);
    }}
    table.data-table tr:hover td {{
      background-color: rgba(255, 255, 255, 0.04);
    }}
    .raw-data-cell {{ max-width: 250px; }}
    .raw-data-pre {{
      font-size: 10px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      color: #9ca3af;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    /* AI Section Styling */
    .ai-card {{
      background: linear-gradient(135deg, #111e38 0%, #172554 100%);
      border: 1px solid #1e40af;
    }}
    .ai-field {{ margin-bottom: 14px; }}
    .ai-field-label {{ font-size: 11px; font-weight: 700; color: #93c5fd; text-transform: uppercase; margin-bottom: 4px; }}
    .ai-field-content {{ font-size: 13px; color: #f0f9ff; }}
    .ai-notes {{
      margin-top: 12px;
      padding: 10px 12px;
      background: rgba(0, 0, 0, 0.2);
      border-radius: 4px;
      font-size: 12px;
      color: #bae6fd;
    }}

    /* Recommendations */
    .rec-card {{ background-color: var(--bg-card-alt); }}
    .rec-card-containment {{ border-top: 3px solid var(--accent-red); }}
    .rec-card-investigation {{ border-top: 3px solid var(--accent-blue); }}
    .rec-card-hardening {{ border-top: 3px solid var(--accent-green); }}
    .rec-list {{ padding-left: 18px; margin-top: 8px; font-size: 13px; }}
    .rec-list li {{ margin-bottom: 6px; }}

    /* Rationale quote */
    .rationale-box {{
      padding: 12px 16px;
      background: rgba(245, 158, 11, 0.08);
      border-left: 4px solid var(--accent-amber);
      border-radius: 4px;
      font-size: 13px;
      color: #fef3c7;
      margin-top: 10px;
    }}

    /* Integrity */
    .integrity-card {{ background-color: #0f172a; border: 1px solid #1e293b; }}
    .digest-label {{ font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }}
    .digest-value {{
      background-color: #020617;
      padding: 8px 12px;
      border-radius: 4px;
      border: 1px solid #1e293b;
      font-size: 12px;
      color: var(--accent-cyan);
      word-break: break-all;
    }}
    .integrity-notice {{ font-size: 11px; color: #94a3b8; margin-top: 8px; }}

    /* Print Stylesheet */
    @media print {{
      body {{
        background-color: #ffffff !important;
        color: #111827 !important;
        padding: 0 !important;
        font-size: 12px !important;
      }}
      .container {{ max-width: 100% !important; }}
      h1, h2, h3, h4 {{ color: #111827 !important; }}
      header.report-header {{
        background: #f9fafb !important;
        border: 1px solid #d1d5db !important;
        color: #111827 !important;
      }}
      .platform-name {{ color: #0284c7 !important; }}
      .card {{
        background-color: #ffffff !important;
        border: 1px solid #e5e7eb !important;
        color: #111827 !important;
        page-break-inside: avoid;
        break-inside: avoid;
      }}
      .detection-card, .metric-card, .rec-card {{
        background-color: #f9fafb !important;
        border-color: #e5e7eb !important;
      }}
      table.data-table th {{
        background-color: #f3f4f6 !important;
        color: #374151 !important;
      }}
      table.data-table td {{
        color: #1f2937 !important;
        border-bottom-color: #e5e7eb !important;
      }}
      .raw-data-pre {{ color: #4b5563 !important; }}
      .ai-card {{
        background: #f0fdf4 !important;
        border-color: #86efac !important;
      }}
      .ai-field-label {{ color: #166534 !important; }}
      .ai-field-content {{ color: #14532d !important; }}
      .rationale-box {{
        background: #fffbeb !important;
        color: #92400e !important;
        border-color: #f59e0b !important;
      }}
      .digest-value {{
        background-color: #f9fafb !important;
        color: #0369a1 !important;
        border-color: #d1d5db !important;
      }}
      .no-print {{ display: none !important; }}
      .timeline-row {{
        page-break-inside: avoid;
        break-inside: avoid;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">

    <!-- 1. Report Header -->
    <header class="report-header">
      <div class="header-top">
        <div class="brand-group">
          <span class="platform-name">{_esc(report.header.platform)}</span>
          <span class="platform-tagline">&bull; {_esc(report.header.tagline)}</span>
        </div>
        <div class="header-meta">
          <div>Schema v{_esc(report.header.report_version)}</div>
          <div>Generated: {fmt_time(report.header.generated_at)}</div>
        </div>
      </div>
      <div class="header-main">
        <div>
          <h1 class="report-title">{_esc(report.header.report_title)}</h1>
          <p class="muted">Formal Security Incident Investigation & Triage Dossier</p>
        </div>
        <div class="incident-badge-group">
          <span class="font-mono" style="font-size: 16px; font-weight: 700; color: #ffffff;">{_esc(report.header.incident_id)}</span>
          {_render_severity_badge(report.executive_summary.severity)}
        </div>
      </div>
    </header>

    <!-- Missing Evidence Banner -->
    {missing_banner}

    <!-- 2. Executive Summary -->
    <section class="card">
      <div class="card-title">Executive Summary</div>
      <div class="grid-2">
        <div>
          <h2>{_esc(report.executive_summary.title)}</h2>
          <p style="font-size: 14px; margin-top: 8px;">{_esc(report.executive_summary.summary_text)}</p>
          {f'<p style="margin-top: 8px; color: #fca5a5;"><strong>Potential Impact:</strong> {_esc(report.executive_summary.potential_impact)}</p>' if report.executive_summary.potential_impact else ''}
        </div>
        <div>
          <div class="grid-2">
            <div class="metric-card">
              <div class="metric-label">Incident Status</div>
              <div class="metric-value font-mono">{_esc(report.executive_summary.status)}</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Assessed Severity</div>
              <div class="metric-value">{_render_severity_badge(report.executive_summary.severity)}</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Primary User</div>
              <div class="metric-value font-mono">{_esc(report.executive_summary.user or "None")}</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Target Device</div>
              <div class="metric-value font-mono">{_esc(report.executive_summary.device or "None")}</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- 3. Incident Overview & 4. Severity Assessment -->
    <div class="grid-2">
      <section class="card">
        <div class="card-title">Incident Telemetry Overview</div>
        <div class="grid-2" style="margin-bottom: 12px;">
          <div class="metric-card">
            <div class="metric-label">Time Window Start</div>
            <div class="metric-value font-mono" style="font-size: 13px;">{fmt_time(report.incident_overview.start_time)}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Time Window End</div>
            <div class="metric-value font-mono" style="font-size: 13px;">{fmt_time(report.incident_overview.end_time)}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Duration</div>
            <div class="metric-value">{_esc(f"{report.incident_overview.duration_seconds:.1f}s")}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Total Evidence Events</div>
            <div class="metric-value">{_esc(str(report.incident_overview.total_evidence_events))}</div>
          </div>
        </div>
        <div>
          <div class="metric-label">Correlated Attack Patterns:</div>
          <div class="chips-container">{pattern_badges}</div>
        </div>
      </section>

      <section class="card">
        <div class="card-title">Deterministic Severity Evaluation</div>
        <div class="grid-2">
          <div class="metric-card">
            <div class="metric-label">Methodology</div>
            <div class="metric-value" style="font-size: 13px;">{_esc(report.severity_assessment.assessment_type)}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Calculated Risk Score</div>
            <div class="metric-value">{_esc(f"{report.severity_assessment.risk_score:.2f}" if report.severity_assessment.risk_score is not None else "N/A")}</div>
          </div>
        </div>
        <div class="rationale-box">
          <strong>Severity Rationale:</strong><br>
          {_esc(report.severity_assessment.severity_rationale)}
        </div>
      </section>
    </div>

    <!-- 5. Detection Findings -->
    <section>
      <h2>Deterministic Detection Findings ({len(report.detection_findings)})</h2>
      {detections_block}
    </section>

    <!-- 6. Chronological Event Timeline -->
    <section class="card">
      <h2>Chronological Telemetry Timeline ({len(report.timeline)} Events)</h2>
      <p class="muted" style="margin-bottom: 10px;">All supporting authentication and endpoint events strictly ordered by UTC timestamp.</p>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Event ID</th>
              <th>Type</th>
              <th>Source</th>
              <th>User</th>
              <th>Device</th>
              <th>IP Address</th>
              <th>Process</th>
              <th>Raw Telemetry</th>
            </tr>
          </thead>
          <tbody>
            {timeline_block}
          </tbody>
        </table>
      </div>
    </section>

    <!-- 7. AI Investigation Findings (Semantically & Visually Separated) -->
    <section class="card ai-card">
      <div class="card-header-flex">
        <h2>AI-Assisted Investigation Analysis</h2>
        <div style="display: flex; gap: 8px;">
          {ai_model_badge}
          {ai_fallback_badge}
        </div>
      </div>
      {ai_banner}

      <div class="ai-field">
        <div class="ai-field-label">Executive Attack Narrative:</div>
        <div class="ai-field-content">{_esc(ai.summary or "No narrative generated.")}</div>
      </div>

      <div class="grid-2">
        <div class="ai-field">
          <div class="ai-field-label">Attack Interpretation & TTPs:</div>
          <div class="ai-field-content">{_esc(ai.attack_interpretation or "N/A")}</div>
        </div>
        <div class="ai-field">
          <div class="ai-field-label">Potential Organizational Impact:</div>
          <div class="ai-field-content">{_esc(ai.potential_impact or "N/A")}</div>
        </div>
      </div>

      <div class="grid-2" style="margin-top: 10px;">
        <div>
          <div class="ai-field-label">AI Cited Evidence Events ({len(ai.cited_event_ids)}):</div>
          <div class="chips-container">{cited_chips}</div>
        </div>
        <div>
          <div class="ai-field-label">Uncited Incident Evidence ({len(ai.uncited_evidence_ids)}):</div>
          <div class="chips-container">{uncited_chips}</div>
        </div>
      </div>

      {ai_notes_html}
    </section>

    <!-- 8. Evidence Verification -->
    <section class="card verification-card">
      <div class="card-header-flex">
        <h2>Evidence Verification Status</h2>
        {_render_verification_badge(report.evidence_verification.status if report.evidence_verification.verification_performed else report.evidence_verification.status_label)}
      </div>
      {_render_verification_body(report.evidence_verification)}
    </section>

    <!-- 9. Recommended Actions -->
    <section>
      <h2>Recommended SOC Action Plan</h2>
      <div class="grid-3">
        <div class="card rec-card rec-card-containment">
          <div class="card-title" style="color: var(--accent-red);">Immediate Containment</div>
          {render_rec_list(recs.immediate_containment, "No immediate containment actions required.")}
        </div>
        <div class="card rec-card rec-card-investigation">
          <div class="card-title" style="color: var(--accent-blue);">Investigation Steps</div>
          {render_rec_list(recs.investigation_steps, "No further investigative steps indicated.")}
        </div>
        <div class="card rec-card rec-card-hardening">
          <div class="card-title" style="color: var(--accent-green);">Remediation &amp; Hardening</div>
          {render_rec_list(recs.remediation_and_hardening, "No system hardening measures indicated.")}
        </div>
      </div>
    </section>

    <!-- 10. Evidence Inventory -->
    <section class="card">
      <h2>Evidence &amp; Reconciliation Inventory</h2>
      <div class="grid-4" style="margin-top: 12px;">
        <div class="metric-card">
          <div class="metric-label">Primary Evidence IDs</div>
          <div class="metric-value font-mono">{len(inv.all_evidence_event_ids)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Resolved Timeline Events</div>
          <div class="metric-value font-mono">{inv.resolved_event_count}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Missing Event References</div>
          <div class="metric-value font-mono" style="color: {'var(--accent-red)' if inv.missing_event_ids else '#ffffff'};">
            {len(inv.missing_event_ids)}
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Resolved Detections</div>
          <div class="metric-value font-mono">{inv.resolved_detection_count} / {len(inv.detection_ids)}</div>
        </div>
      </div>
    </section>

    <!-- 12. Report Integrity -->
    {integrity_block}

  </div>
</body>
</html>
"""
    return html_content


def export_html_report(
    report: IncidentReport,
    output_path: Union[str, Path],
    overwrite: bool = False,
    json_digest: Optional[str] = None,
) -> Path:
    """Export an IncidentReport to a standalone HTML report file.

    Args:
        report: Validated IncidentReport instance.
        output_path: Target HTML file path (e.g. 'reports/INC000001.html').
        overwrite: If False, raises FileExistsError if target file exists.
        json_digest: Optional SHA-256 digest of companion JSON report to embed in integrity section.

    Returns:
        Resolved Path to written HTML report file.

    Raises:
        ValueError: If target path is in a protected dataset directory.
        FileExistsError: If target path already exists and overwrite is False.
        OSError: If directory creation or file writing fails.
    """
    if not isinstance(report, IncidentReport):
        raise TypeError(f"Expected IncidentReport instance, got {type(report).__name__}")

    target_path = Path(output_path).resolve()

    # Guard: Protected dataset directories
    if _is_protected_directory(target_path):
        raise ValueError(
            f"Access Denied: Writing HTML reports inside protected directory '{target_path}' is strictly forbidden."
        )

    # Overwrite protection
    if target_path.exists() and not overwrite:
        raise FileExistsError(
            f"Target HTML report already exists: {target_path}. Specify overwrite=True to replace."
        )

    # Create parent directories if needed
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        raise OSError(f"Failed to create HTML report directory '{target_path.parent}': {err}") from err

    # Render HTML content
    html_text = render_incident_report_to_html(report, json_digest=json_digest)

    # Write file
    try:
        target_path.write_text(html_text, encoding="utf-8")
    except OSError as err:
        raise OSError(f"Failed to write HTML report '{target_path}': {err}") from err

    return target_path
