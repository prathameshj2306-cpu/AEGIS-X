import React, { useState, useEffect } from 'react';
import {
  fetchIncidentDetail,
  analyzeIncident,
  getReportDownloadUrl
} from '../api';
import {
  ShieldAlert,
  Brain,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileText,
  Clock,
  User,
  Server,
  ArrowLeft,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Sparkles,
  ShieldCheck,
  AlertOctagon,
  Copy,
  Check,
  Tag,
  Database,
  Calendar
} from 'lucide-react';

export default function InvestigationView({
  incidentId,
  incidents = [],
  onSelectIncident,
  onBackToIncidents,
  onNavigateToReports,
  onIncidentUpdated
}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [expandedEventId, setExpandedEventId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    if (incidentId) {
      loadIncident(incidentId);
    } else {
      setData(null);
      setLoading(false);
      setError(null);
    }
  }, [incidentId]);

  const loadIncident = async (id) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetchIncidentDetail(id);
      setData(resp);
    } catch (err) {
      setError(err.message || 'Failed to load incident details');
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async () => {
    if (!incidentId) return;
    setAnalyzing(true);
    setError(null);
    try {
      await analyzeIncident(incidentId);
      // Reload full incident details to display fresh analysis and verification
      await loadIncident(incidentId);
      if (onIncidentUpdated) onIncidentUpdated();
    } catch (err) {
      setError(err.message || 'AI analysis request failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Safe UTC datetime formatter - guarantees clean UTC string and never returns "Invalid Date"
  const formatUTC = (val) => {
    if (!val) return 'Unavailable';
    try {
      const d = new Date(val);
      if (isNaN(d.getTime())) return 'Unavailable';
      return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    } catch {
      return 'Unavailable';
    }
  };

  // Formats confidence preserving original textual values (HIGH, RULE MATCH) without converting to percentage
  const formatConfidenceText = (conf) => {
    if (conf === null || conf === undefined || conf === '') return 'Not provided';
    const s = String(conf).trim();
    // If it's already textual like "high" or "rule_match", display as uppercase string
    if (isNaN(Number(s))) {
      return s.replace(/_/g, ' ').toUpperCase();
    }
    // If purely numeric, show with 2 decimals
    const num = parseFloat(s);
    return isNaN(num) ? s.toUpperCase() : num.toFixed(2);
  };

  if (!incidentId) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#f8fafc' }}>
            SOC Incident Investigation
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Deep-dive triage, deterministic evidence tracing, and local SLM attack hypothesis analysis.
          </p>
        </div>

        <div className="card text-center" style={{ padding: '48px 24px', textAlign: 'center', maxWidth: '750px', margin: '0 auto', width: '100%' }}>
          <ShieldAlert size={48} color="var(--color-cyan)" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', marginBottom: '8px' }}>
            No Incident Selected for Investigation
          </h3>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '24px', maxWidth: '520px', margin: '0 auto 24px' }}>
            Select an incident from the Incidents page to begin investigation, or choose an incident directly below:
          </p>

          {incidents && incidents.length > 0 ? (
            <div style={{ maxWidth: '520px', margin: '0 auto 24px', textAlign: 'left' }}>
              <label className="block text-xs font-semibold text-secondary uppercase mb-1.5" style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>
                SELECT INCIDENT TO INVESTIGATE:
              </label>
              <select
                className="input"
                defaultValue=""
                onChange={(e) => {
                  if (e.target.value && onSelectIncident) {
                    onSelectIncident(e.target.value);
                  }
                }}
                style={{ width: '100%', padding: '10px 14px', fontSize: '13px', borderRadius: '6px' }}
              >
                <option value="">-- Choose an incident from database --</option>
                {incidents.map((inc) => (
                  <option key={inc.incident_id} value={inc.incident_id}>
                    {inc.incident_id} — [{inc.severity}] {inc.title || (inc.detected_patterns && inc.detected_patterns.join(', '))} — {inc.user || 'Unknown User'}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '20px' }}>
              No incidents currently available in SQLite database. Upload logs in the Log Ingestion tab and execute the threat pipeline.
            </p>
          )}

          <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
            <button className="btn btn-cyber" onClick={onBackToIncidents} style={{ padding: '8px 18px', fontSize: '12px' }}>
              <span>View All Incidents in Triage Matrix</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="card text-center py-12" style={{ padding: '60px 20px', textAlign: 'center' }}>
        <RefreshCw size={36} color="var(--color-cyan)" className="animate-spin" style={{ margin: '0 auto 16px' }} />
        <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc' }}>
          Loading Incident Investigation Telemetry...
        </h3>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
          Retrieving correlated evidence and detection state from SQLite database
        </p>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="card" style={{ borderColor: 'var(--color-red)', padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', color: 'var(--color-red)', marginBottom: '12px' }}>
          <AlertTriangle size={24} />
          <h3 style={{ fontSize: '16px', fontWeight: 700 }}>Failed to Load Incident</h3>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>{error}</p>
        <button className="btn btn-outline" onClick={onBackToIncidents}>
          Return to Matrix
        </button>
      </div>
    );
  }

  // Gracefully unpack backend response schema
  const inc = data?.incident || data || {};
  const detections = Array.isArray(data?.detections) ? data.detections : (inc.detections || []);
  const evidenceEvents = Array.isArray(data?.evidence_events) ? data.evidence_events : (inc.evidence_events || []);
  const ai = data?.ai_analysis || inc.ai_analysis;
  const ver = data?.ai_verification || inc.ai_verification;
  const aiStatus = inc.ai_status || data?.ai_status || (ai ? 'SUCCESS' : null);
  const hasAnalysis = !!ai;

  // Evidence verification rationale text handling
  const verificationRationale = ver?.verification_rationale
    ? (Array.isArray(ver.verification_rationale) ? ver.verification_rationale.join(' ') : String(ver.verification_rationale))
    : (ver?.rationale || 'Not provided');

  // Cited metrics mapping from backend model EvidenceVerificationResult
  const totalCitedCount = ver?.cited_evidence_count !== undefined
    ? ver.cited_evidence_count
    : (ver?.total_evidence_count !== undefined ? ver.total_evidence_count : 'Not provided');

  const validCitationCount = ver?.valid_citation_count !== undefined
    ? ver.valid_citation_count
    : (ver?.verified_evidence_ids ? ver.verified_evidence_ids.length : 'Not provided');

  const invalidCitationCount = ver?.invalid_citation_ids
    ? ver.invalid_citation_ids.length
    : (ver?.missing_evidence_count !== undefined ? ver.missing_evidence_count : 'Not provided');

  const verifiedEvidenceList = ver?.verified_evidence_ids || [];
  const invalidCitationList = ver?.invalid_citation_ids || [];
  const discrepanciesList = ver?.discrepancies || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Navigation & Action Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={onBackToIncidents}
            className="btn btn-outline"
            style={{ padding: '8px 14px', fontSize: '12px' }}
          >
            <ArrowLeft size={14} /> Back to Triage Matrix
          </button>

          {incidents && incidents.length > 1 && onSelectIncident && (
            <select
              className="input"
              value={inc.incident_id || incidentId || ''}
              onChange={(e) => e.target.value && onSelectIncident(e.target.value)}
              style={{ fontSize: '12px', padding: '6px 12px', height: '36px', minWidth: '220px' }}
              title="Switch to another incident"
            >
              {incidents.map((i) => (
                <option key={i.incident_id} value={i.incident_id}>
                  {i.incident_id} — [{i.severity}] {i.user || 'Unknown User'}
                </option>
              ))}
            </select>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={() => onNavigateToReports(inc.incident_id)}
            className="btn btn-outline"
            style={{ padding: '8px 14px', fontSize: '12px' }}
          >
            <FileText size={14} /> Export Reports
          </button>

          <button
            onClick={handleAnalyze}
            disabled={analyzing}
            className="btn btn-cyber"
            style={{ padding: '8px 16px', fontSize: '12px' }}
          >
            {analyzing ? (
              <>
                <RefreshCw size={14} className="animate-spin" />
                <span>Running SLM Analysis & Verification...</span>
              </>
            ) : (
              <>
                <Sparkles size={14} />
                <span>{hasAnalysis ? 'Re-run AI Analysis' : 'Analyze Incident with AI'}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          padding: '12px 16px',
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '8px',
          fontSize: '13px',
          color: 'var(--color-red)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Incident Summary Card */}
      <div className="card" style={{ padding: '24px' }}>
        {/* Top Header Row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '8px' }}>
              <span className="badge badge-cyan" style={{ fontSize: '12px', fontWeight: 700 }}>
                {inc.incident_id}
              </span>
              {inc.batch_id && (
                <span className="badge badge-purple" style={{ fontSize: '11px', fontWeight: 600 }}>
                  BATCH: {inc.batch_id}
                </span>
              )}
              <span className={`badge badge-${inc.severity?.toLowerCase() || 'low'}`}>
                {inc.severity || 'LOW'} SEVERITY
              </span>
              <span className="badge badge-medium">
                {inc.status || 'OPEN'}
              </span>
              {inc.risk_score !== undefined && inc.risk_score !== null && (
                <span style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  background: 'rgba(245, 158, 11, 0.1)',
                  color: 'var(--color-amber)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  fontWeight: 600
                }}>
                  RISK SCORE: {inc.risk_score} / 100
                </span>
              )}
            </div>

            <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#f8fafc', marginTop: '6px' }}>
              {inc.title || inc.incident_id}
            </h2>

            {/* Attack Patterns */}
            {inc.detected_patterns && inc.detected_patterns.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginTop: '10px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.5px' }}>
                  ATTACK PATTERNS:
                </span>
                {inc.detected_patterns.map((pat, idx) => (
                  <span key={idx} className="badge badge-cyan" style={{ fontSize: '11px', textTransform: 'none' }}>
                    {pat}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Timestamps */}
          <div style={{ textAlign: 'right', fontSize: '12px', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '6px' }}>
              <Clock size={13} color="var(--color-cyan)" />
              <span>Created: <strong style={{ color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>{formatUTC(inc.created_at || inc.start_time)}</strong></span>
            </div>
            {(inc.start_time || inc.end_time) && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '6px', fontSize: '11px' }}>
                <Calendar size={12} color="var(--text-muted)" />
                <span>Incident Window: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{formatUTC(inc.start_time)}</span> &rarr; <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{formatUTC(inc.end_time)}</span></span>
              </div>
            )}
          </div>
        </div>

        {/* 4-Box Entity & Correlation Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
          paddingTop: '16px',
          borderTop: '1px solid var(--border-color)',
          marginTop: '16px'
        }}>
          {/* Target User */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '12px 14px'
          }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              TARGET USER
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: '#f8fafc', fontWeight: 600 }}>
              <User size={14} color="var(--color-cyan)" />
              <span>{inc.user || 'None'}</span>
            </div>
          </div>

          {/* Target Host / Device */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '12px 14px'
          }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              TARGET HOST / DEVICE
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: '#f8fafc', fontWeight: 600 }}>
              <Server size={14} color="var(--color-cyan)" />
              <span>{inc.device || 'None'}</span>
            </div>
          </div>

          {/* Correlated Evidence */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '12px 14px'
          }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              CORRELATED EVIDENCE
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-green)', fontWeight: 700 }}>
              <Database size={14} color="var(--color-green)" />
              <span>{evidenceEvents.length} Events</span>
            </div>
          </div>

          {/* Detection Signatures */}
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '12px 14px'
          }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              DETECTION SIGNATURES
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', fontSize: '14px', fontFamily: 'var(--font-mono)', color: 'var(--color-amber)', fontWeight: 700 }}>
              <ShieldAlert size={14} color="var(--color-amber)" />
              <span>{detections.length} Triggered</span>
            </div>
          </div>
        </div>

        {/* Deterministic Severity Rationale */}
        {inc.severity_rationale && (
          <div style={{
            marginTop: '16px',
            padding: '14px 16px',
            background: 'rgba(13, 19, 34, 0.75)',
            borderRadius: '6px',
            border: '1px solid var(--border-color)'
          }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '0.5px', marginBottom: '4px' }}>
              DETERMINISTIC SEVERITY RATIONALE:
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', lineHeight: '1.6' }}>
              {inc.severity_rationale}
            </p>
          </div>
        )}
      </div>

      {/* Main Grid: AI Narrative (Left) & Evidence Verification (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>

        {/* Left Column: AI Narrative Analysis */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', flex: '2 1 450px' }}>
          <div className="card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '14px', borderBottom: '1px solid var(--border-color)', marginBottom: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Brain color="var(--color-cyan)" size={20} />
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc' }}>
                  Explainable AI Threat Intelligence
                </h3>
              </div>

              {hasAnalysis ? (
                <div>
                  {aiStatus === 'SUCCESS' ? (
                    <span className="badge badge-verified" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <Sparkles size={12} /> Local SLM (Qwen2.5)
                    </span>
                  ) : (
                    <span className="badge badge-fallback" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <AlertOctagon size={12} /> Deterministic Fallback
                    </span>
                  )}
                </div>
              ) : (
                <span className="badge badge-low">Not Analyzed</span>
              )}
            </div>

            {hasAnalysis ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Executive Summary */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 700, color: 'var(--color-cyan)', letterSpacing: '0.5px', marginBottom: '6px' }}>
                    Executive Threat Summary
                  </h4>
                  <div style={{
                    fontSize: '13px',
                    color: 'var(--text-secondary)',
                    lineHeight: '1.6',
                    background: 'var(--bg-secondary)',
                    padding: '14px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)'
                  }}>
                    {ai.summary || 'Summary unavailable.'}
                  </div>
                </div>

                {/* Tactical Interpretation */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 700, color: 'var(--color-amber)', letterSpacing: '0.5px', marginBottom: '6px' }}>
                    Tactical Attack Interpretation
                  </h4>
                  <div style={{
                    fontSize: '13px',
                    color: 'var(--text-secondary)',
                    lineHeight: '1.6',
                    background: 'var(--bg-secondary)',
                    padding: '14px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)'
                  }}>
                    {ai.attack_interpretation || 'Interpretation unavailable.'}
                  </div>
                </div>

                {/* Potential Impact */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 700, color: 'var(--color-red)', letterSpacing: '0.5px', marginBottom: '6px' }}>
                    Potential Business & Security Impact
                  </h4>
                  <div style={{
                    fontSize: '13px',
                    color: 'var(--text-secondary)',
                    lineHeight: '1.6',
                    background: 'var(--bg-secondary)',
                    padding: '14px',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)'
                  }}>
                    {ai.potential_impact || 'Impact assessment unavailable.'}
                  </div>
                </div>

                {/* Prioritized Remediation Actions */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 700, color: 'var(--color-green)', letterSpacing: '0.5px', marginBottom: '8px' }}>
                    Prioritized Remediation Actions
                  </h4>
                  {ai.recommended_actions && ai.recommended_actions.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {ai.recommended_actions.map((action, idx) => (
                        <div key={idx} style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '10px',
                          fontSize: '13px',
                          color: 'var(--text-secondary)',
                          background: 'var(--bg-secondary)',
                          padding: '10px 14px',
                          borderRadius: '6px',
                          border: '1px solid var(--border-color)'
                        }}>
                          <span style={{
                            fontSize: '11px',
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            background: 'rgba(16, 185, 129, 0.15)',
                            color: 'var(--color-green)'
                          }}>
                            {idx + 1}
                          </span>
                          <span style={{ flex: 1, lineHeight: '1.5' }}>{action}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No remediation actions specified.</p>
                  )}
                </div>

                {/* Events Cited by Analysis */}
                {ai.cited_event_ids?.length > 0 && (
                  <div style={{ paddingTop: '8px', borderTop: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.5px', marginBottom: '8px' }}>
                      EVENTS CITED BY ANALYSIS:
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {ai.cited_event_ids.map((cid) => (
                        <span key={cid} className="badge badge-cyan" style={{ fontSize: '12px', fontWeight: 600 }}>
                          {cid}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px 20px', background: 'var(--bg-secondary)', borderRadius: '6px', border: '1px dashed var(--border-color)' }}>
                <Brain size={36} color="var(--text-muted)" style={{ margin: '0 auto 12px', opacity: 0.5 }} />
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  No AI Analysis Generated Yet
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px', marginBottom: '16px' }}>
                  Run the local Small Language Model or deterministic cybersecurity fallback engine to produce structured threat narratives and mitigation steps.
                </p>
                <button
                  onClick={handleAnalyze}
                  disabled={analyzing}
                  className="btn btn-cyber"
                  style={{ padding: '6px 14px', fontSize: '12px' }}
                >
                  <Sparkles size={14} /> Analyze Now
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Independent Evidence Verification & Detections */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', flex: '1 1 320px' }}>

          {/* Evidence Verification Card */}
          <div className="card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '14px', borderBottom: '1px solid var(--border-color)', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck color="var(--color-green)" size={20} />
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc' }}>
                  Evidence Verification
                </h3>
              </div>

              {ver ? (
                <span className={`badge ${
                  ver.status === 'VERIFIED' ? 'badge-verified' :
                  ver.status === 'PARTIAL' ? 'badge-partial' : 'badge-unverified'
                }`} style={{ fontSize: '12px', fontWeight: 700 }}>
                  {ver.status}
                </span>
              ) : (
                <span className="badge badge-low">Pending</span>
              )}
            </div>

            {ver ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Rationale Box */}
                <div style={{
                  padding: '12px 14px',
                  background: 'var(--bg-secondary)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-color)'
                }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.5px', marginBottom: '4px' }}>
                    VERIFICATION RATIONALE:
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                    {verificationRationale}
                  </p>
                </div>

                {/* 3 Citation Metric Cards */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                  <div style={{
                    background: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    padding: '10px 8px',
                    textAlign: 'center',
                    border: '1px solid var(--border-color)'
                  }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', fontWeight: 600 }}>
                      TOTAL CITED
                    </span>
                    <span style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f8fafc', marginTop: '2px', display: 'block' }}>
                      {totalCitedCount}
                    </span>
                  </div>

                  <div style={{
                    background: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    padding: '10px 8px',
                    textAlign: 'center',
                    border: '1px solid rgba(16, 185, 129, 0.3)'
                  }}>
                    <span style={{ fontSize: '10px', color: 'var(--color-green)', textTransform: 'uppercase', display: 'block', fontWeight: 600 }}>
                      VALID
                    </span>
                    <span style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-green)', marginTop: '2px', display: 'block' }}>
                      {validCitationCount}
                    </span>
                  </div>

                  <div style={{
                    background: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    padding: '10px 8px',
                    textAlign: 'center',
                    border: '1px solid rgba(239, 68, 68, 0.3)'
                  }}>
                    <span style={{ fontSize: '10px', color: 'var(--color-red)', textTransform: 'uppercase', display: 'block', fontWeight: 600 }}>
                      INVALID
                    </span>
                    <span style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-red)', marginTop: '2px', display: 'block' }}>
                      {invalidCitationCount}
                    </span>
                  </div>
                </div>

                {/* Verified References Badges */}
                {verifiedEvidenceList.length > 0 && (
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
                      Verified Ground-Truth References:
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {verifiedEvidenceList.map((id) => (
                        <span key={id} className="badge badge-verified" style={{ fontSize: '11px', gap: '4px' }}>
                          <CheckCircle2 size={11} /> {id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Invalid / Unverified References Badges */}
                {invalidCitationList.length > 0 && (
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--color-red)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
                      Invalid / Unverified References:
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {invalidCitationList.map((id) => (
                        <span key={id} className="badge badge-unverified" style={{ fontSize: '11px', gap: '4px' }}>
                          <XCircle size={11} /> {id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Discrepancies */}
                {discrepanciesList.length > 0 && (
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--color-amber)', textTransform: 'uppercase', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
                      Identified Discrepancies:
                    </span>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {discrepanciesList.map((d, i) => (
                        <div key={i} style={{
                          padding: '8px 10px',
                          background: 'rgba(245, 158, 11, 0.1)',
                          border: '1px solid rgba(245, 158, 11, 0.3)',
                          borderRadius: '4px',
                          fontSize: '12px',
                          color: 'var(--text-secondary)',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '6px'
                        }}>
                          <AlertTriangle size={13} color="var(--color-amber)" style={{ marginTop: '2px', flexShrink: 0 }} />
                          <span>{d.explanation || d}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '24px 12px', color: 'var(--text-muted)', fontSize: '12px' }}>
                Run AI analysis to independently verify all cited evidence IDs against the ground-truth SQLite database records.
              </div>
            )}
          </div>

          {/* Underlying Detection Rules Card */}
          <div className="card" style={{ padding: '24px' }}>
            <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={18} color="var(--color-amber)" />
              Underlying Detection Rules ({detections.length})
            </h4>

            {detections.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)', fontSize: '12px' }}>
                No detection records attached to this incident.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {detections.map((d, idx) => {
                  const ruleName = d.rule_name || d.rule_id || d.detection_id || 'Detection';
                  const explanation = d.explanation || d.description || 'No explanation provided.';
                  const eventCount = (d.event_ids && Array.isArray(d.event_ids))
                    ? `${d.event_ids.length} Events`
                    : (d.evidence_event_ids && Array.isArray(d.evidence_event_ids)
                        ? `${d.evidence_event_ids.length} Events`
                        : 'Unavailable');

                  return (
                    <div key={d.detection_id || idx} style={{
                      padding: '12px 14px',
                      background: 'var(--bg-secondary)',
                      borderRadius: '6px',
                      border: '1px solid var(--border-color)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px'
                    }}>
                      {/* Rule Name & Detection ID */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)', fontWeight: 700, fontSize: '13px' }}>
                          {ruleName}
                        </span>
                        <span className="badge badge-low" style={{ fontSize: '10px' }}>
                          {d.detection_id || `DET-${idx + 1}`}
                        </span>
                      </div>

                      {/* Explanation on a dedicated line */}
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5', margin: '4px 0' }}>
                        {explanation}
                      </p>

                      {/* Event Count & Original Textual Confidence */}
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        fontSize: '11px',
                        color: 'var(--text-muted)',
                        paddingTop: '6px',
                        borderTop: '1px solid var(--border-subtle)',
                        marginTop: '2px'
                      }}>
                        <span>Associated: <strong style={{ color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>{eventCount}</strong></span>
                        <span>Confidence: <strong style={{ color: 'var(--color-green)', fontFamily: 'var(--font-mono)' }}>{formatConfidenceText(d.confidence)}</strong></span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Chronological Evidence Timeline */}
      <div className="card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', paddingBottom: '16px', borderBottom: '1px solid var(--border-color)', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Clock color="var(--color-cyan)" size={18} />
              Chronological Evidence Chain ({evidenceEvents.length} Events)
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Strictly verified and ordered event log records establishing the incident timeline.
            </p>
          </div>
          <span className="badge badge-verified" style={{ fontSize: '11px' }}>
            SQLite Verified
          </span>
        </div>

        {evidenceEvents.length > 0 ? (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: '40px', textAlign: 'center' }}></th>
                  <th style={{ minWidth: '130px' }}>Event ID</th>
                  <th style={{ minWidth: '180px' }}>Timestamp (UTC)</th>
                  <th style={{ minWidth: '120px' }}>Source</th>
                  <th style={{ minWidth: '160px' }}>Action / Event Type</th>
                  <th style={{ minWidth: '180px' }}>User • Host / Device</th>
                  <th style={{ minWidth: '220px' }}>Process / Details</th>
                </tr>
              </thead>
              <tbody>
                {evidenceEvents.map((ev) => {
                  const isExpanded = expandedEventId === ev.event_id;
                  const isCited = ai?.cited_event_ids?.includes(ev.event_id);
                  const userText = ev.user || ev.username || '—';
                  const hostText = ev.device || ev.hostname || '—';
                  const eventType = ev.event_type || ev.action || 'Unknown';
                  const detailsText = ev.process || (ev.raw_data && ev.raw_data.process) || ev.status || ev.process_name || '—';

                  return (
                    <React.Fragment key={ev.event_id}>
                      <tr
                        className={`cursor-pointer ${isCited ? 'bg-cyan/5' : ''}`}
                        onClick={() => setExpandedEventId(isExpanded ? null : ev.event_id)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '12px 10px' }}>
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>

                        {/* Separate Event ID and Citation Badge */}
                        <td style={{ padding: '12px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className="font-mono text-cyan font-bold" style={{ fontSize: '13px' }}>
                              {ev.event_id}
                            </span>
                            {isCited && (
                              <span className="badge badge-cyan" style={{ fontSize: '10px', padding: '1px 6px' }}>
                                CITED
                              </span>
                            )}
                          </div>
                        </td>

                        {/* UTC Timestamp */}
                        <td className="font-mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', whiteSpace: 'nowrap', padding: '12px 16px' }}>
                          {formatUTC(ev.timestamp)}
                        </td>

                        {/* Source */}
                        <td style={{ padding: '12px 16px' }}>
                          <span className="badge badge-low" style={{ fontSize: '10px' }}>
                            {ev.source || 'N/A'}
                          </span>
                        </td>

                        {/* Action / Event Type */}
                        <td style={{ padding: '12px 16px' }}>
                          <span className="font-mono" style={{ fontSize: '12px', fontWeight: 600, color: '#f8fafc' }}>
                            {eventType}
                          </span>
                        </td>

                        {/* User • Host with IP as secondary */}
                        <td style={{ padding: '12px 16px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                            <span style={{ fontWeight: 600, color: '#f8fafc' }}>{userText}</span>
                            <span style={{ color: 'var(--text-muted)' }}>•</span>
                            <span style={{ color: 'var(--color-cyan)', fontFamily: 'var(--font-mono)' }}>{hostText}</span>
                          </div>
                          {ev.ip && (
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                              IP: {ev.ip}
                            </div>
                          )}
                        </td>

                        {/* Process / Details */}
                        <td style={{ padding: '12px 16px', maxWidth: '300px' }}>
                          <div className="truncate font-mono" style={{ fontSize: '12px', color: 'var(--text-secondary)' }} title={detailsText}>
                            {detailsText}
                          </div>
                        </td>
                      </tr>

                      {/* Expandable Raw Event Inspection Row */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={7} style={{ background: 'var(--bg-secondary)', padding: '16px 20px', borderBottom: '1px solid var(--border-color)' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontSize: '12px', fontWeight: 700, color: '#f8fafc' }}>
                                  Full Event Telemetry Record ({ev.event_id})
                                </span>
                                <button
                                  className="btn btn-outline"
                                  style={{ padding: '4px 10px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    copyToClipboard(JSON.stringify(ev, null, 2), ev.event_id);
                                  }}
                                >
                                  {copiedId === ev.event_id ? (
                                    <>
                                      <Check size={12} color="var(--color-green)" /> Copied
                                    </>
                                  ) : (
                                    <>
                                      <Copy size={12} /> Copy JSON
                                    </>
                                  )}
                                </button>
                              </div>
                              <pre style={{
                                padding: '12px 16px',
                                background: '#050811',
                                borderRadius: '6px',
                                border: '1px solid var(--border-color)',
                                fontFamily: 'var(--font-mono)',
                                fontSize: '11px',
                                color: 'var(--color-cyan)',
                                overflowX: 'auto',
                                lineHeight: '1.6'
                              }}>
                                {JSON.stringify(ev, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '32px 20px', color: 'var(--text-muted)', fontSize: '13px' }}>
            No evidence events attached to this incident.
          </div>
        )}
      </div>
    </div>
  );
}
