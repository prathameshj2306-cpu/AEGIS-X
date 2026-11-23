import React from 'react';
import {
  Play,
  ShieldAlert,
  AlertOctagon,
  AlertTriangle,
  Info,
  CheckCircle2,
  ArrowRight,
  Database,
  Layers,
} from 'lucide-react';

export default function OverviewView({
  health,
  incidents = [],
  batches = [],
  selectedBatchId = 'latest',
  onSelectBatch,
  pipelineRunning,
  onRunPipeline,
  onSelectIncident,
}) {
  const safeIncidents = Array.isArray(incidents) ? incidents : [];
  const criticalCount = safeIncidents.filter((i) => i.severity === 'CRITICAL').length;
  const highCount = safeIncidents.filter((i) => i.severity === 'HIGH').length;
  const mediumCount = safeIncidents.filter((i) => i.severity === 'MEDIUM').length;
  const lowCount = safeIncidents.filter((i) => i.severity === 'LOW').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner & Quick Pipeline Action */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.6) 100%)',
        border: '1px solid rgba(6, 182, 212, 0.3)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '24px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="badge badge-cyan">AIR-GAPPED THREAT TRIAGE</span>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>4 Deterministic Rules + Correlator</span>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#f8fafc', margin: '8px 0 4px' }}>
            Security Operations & Threat Intelligence
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '650px' }}>
            AEGIS-X runs locally without cloud telemetry. Ingest authentication and endpoint logs, execute multi-stage correlation, and generate explainable investigation reports.
          </p>
        </div>

        <button
          onClick={() => onRunPipeline(selectedBatchId)}
          disabled={pipelineRunning}
          className="btn btn-cyber"
          style={{ padding: '12px 24px', fontSize: '14px', fontWeight: 600 }}
        >
          <Play size={16} fill="white" className={pipelineRunning ? 'animate-spin' : ''} />
          <span>{pipelineRunning ? 'ANALYZING TELEMETRY...' : 'RUN THREAT INVESTIGATION'}</span>
        </button>
      </div>

      {/* Ingestion Batch Scope Selector */}
      <div className="card" style={{ padding: '12px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            TELEMETRY SCOPE:
          </span>
          <button
            onClick={() => onSelectBatch && onSelectBatch('latest')}
            className={`btn ${selectedBatchId === 'latest' ? 'btn-cyber' : 'btn-outline'}`}
            style={{ padding: '4px 12px', fontSize: '11px', fontWeight: 600 }}
          >
            Latest Batch {health?.latest_batch_id ? `(${health.latest_batch_id})` : ''}
          </button>
          <button
            onClick={() => onSelectBatch && onSelectBatch('all')}
            className={`btn ${selectedBatchId === 'all' ? 'btn-cyber' : 'btn-outline'}`}
            style={{ padding: '4px 12px', fontSize: '11px', fontWeight: 600 }}
          >
            All Historical Records
          </button>
          {batches && batches.length > 0 && (
            <select
              value={selectedBatchId}
              onChange={(e) => onSelectBatch && onSelectBatch(e.target.value)}
              style={{
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '4px 10px',
                fontSize: '11px',
                outline: 'none'
              }}
            >
              <option value="latest">Scope: Latest Batch</option>
              <option value="all">Scope: All Historical Records</option>
              {batches.map((b) => (
                <option key={b.batch_id} value={b.batch_id}>
                  {b.batch_id} — {b.filename} ({b.event_count} ev)
                </option>
              ))}
            </select>
          )}
        </div>

        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          {selectedBatchId === 'all'
            ? 'Analyzing combined telemetry across all historical uploads'
            : `Isolated analysis strictly within active batch ${selectedBatchId === 'latest' && health?.latest_batch_id ? health.latest_batch_id : selectedBatchId}`}
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
        <div className="stat-box">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">Events Stored</span>
            <Database size={16} color="var(--color-cyan)" />
          </div>
          <div className="stat-value">{health?.event_count || 0}</div>
          <div className="stat-sub">Normalized in SQLite</div>
        </div>

        <div className="stat-box">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">Correlated Incidents</span>
            <Layers size={16} color="var(--color-blue)" />
          </div>
          <div className="stat-value">{safeIncidents.length}</div>
          <div className="stat-sub">15-minute sliding windows</div>
        </div>

        <div className="stat-box" style={{ borderLeft: '3px solid var(--color-red)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">Critical</span>
            <AlertOctagon size={16} color="var(--color-red)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--color-red)' }}>{criticalCount}</div>
          <div className="stat-sub">Immediate action required</div>
        </div>

        <div className="stat-box" style={{ borderLeft: '3px solid var(--color-orange)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">High</span>
            <ShieldAlert size={16} color="var(--color-orange)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--color-orange)' }}>{highCount}</div>
          <div className="stat-sub">High severity alerts</div>
        </div>

        <div className="stat-box" style={{ borderLeft: '3px solid var(--color-amber)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">Medium</span>
            <AlertTriangle size={16} color="var(--color-amber)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--color-amber)' }}>{mediumCount}</div>
          <div className="stat-sub">Elevated risk activity</div>
        </div>

        <div className="stat-box" style={{ borderLeft: '3px solid var(--color-blue)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="stat-label">Low</span>
            <Info size={16} color="var(--color-blue)" />
          </div>
          <div className="stat-value" style={{ color: 'var(--color-blue)' }}>{lowCount}</div>
          <div className="stat-sub">Informational alerts</div>
        </div>
      </div>

      {/* Recent Incidents Table */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: '#f8fafc' }}>
              Correlated Security Incidents
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Triaged by deterministic severity matrix
            </p>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Showing {incidents.slice(0, 5).length} of {incidents.length} incidents
          </span>
        </div>

        {safeIncidents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
            <ShieldAlert size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
            <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              No Incidents Correlated Yet
            </div>
            <p style={{ fontSize: '12px', marginTop: '4px' }}>
              Upload authentication and endpoint logs in the <b>Log Ingestion</b> tab, then click <b>Run Threat Investigation</b>.
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Title & Patterns</th>
                  <th>Severity</th>
                  <th>Target Entity</th>
                  <th>Evidence</th>
                  <th>AI Status</th>
                  <th>Verification</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {safeIncidents.slice(0, 5).map((inc) => (
                  <tr key={inc.incident_id}>
                    <td className="font-mono" style={{ fontWeight: 600, color: 'var(--color-cyan)' }}>
                      <div>{inc.incident_id}</div>
                      {inc.batch_id && (
                        <div style={{ marginTop: '2px' }}>
                          <span className="badge badge-purple" style={{ fontSize: '9px', padding: '1px 4px' }}>
                            {inc.batch_id}
                          </span>
                        </div>
                      )}
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{inc.title}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {inc.detected_patterns?.join(' • ')}
                      </div>
                    </td>
                    <td>
                      <span className={`badge badge-${(inc.severity || 'low').toLowerCase()}`}>
                        {inc.severity || 'LOW'}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontSize: '12px' }}>
                        {inc.user ? <span>User: <b>{inc.user}</b></span> : <span style={{ color: 'var(--text-muted)' }}>No user</span>}
                      </div>
                      {inc.device && (
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Host: {inc.device}
                        </div>
                      )}
                    </td>
                    <td className="font-mono" style={{ fontSize: '12px' }}>
                      {inc.evidence_count !== undefined ? `${inc.evidence_count} events` : '0 events'}
                    </td>
                    <td>
                      {inc.ai_status ? (
                        <span className={`badge ${inc.ai_status === 'SUCCESS' ? 'badge-success' : 'badge-fallback'}`}>
                          {inc.ai_status}
                        </span>
                      ) : (
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Unanalyzed</span>
                      )}
                    </td>
                    <td>
                      {inc.verification_status ? (
                        <span className={`badge badge-${(inc.verification_status || 'low').toLowerCase()}`}>
                          {inc.verification_status}
                        </span>
                      ) : (
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Unverified</span>
                      )}
                    </td>
                    <td>
                      <button
                        onClick={() => onSelectIncident(inc.incident_id)}
                        className="btn btn-outline"
                        style={{ padding: '4px 10px', fontSize: '11px' }}
                      >
                        <span>Investigate</span>
                        <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
