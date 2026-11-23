import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowRight,
  Clock,
  User,
  Laptop,
  CheckCircle,
  FileText,
} from 'lucide-react';

export default function IncidentsView({
  incidents = [],
  batches = [],
  selectedBatchId = 'latest',
  onSelectBatch,
  onSelectIncident
}) {
  const safeIncidents = Array.isArray(incidents) ? incidents : [];
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const formatTime = (val) => {
    if (!val) return '—';
    try {
      const d = new Date(val);
      return isNaN(d.getTime()) ? '—' : d.toLocaleTimeString();
    } catch {
      return '—';
    }
  };

  const filteredIncidents = safeIncidents.filter((inc) => {
    if (!inc) return false;
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) {
      return false;
    }
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      const matchId = (inc.incident_id || '').toLowerCase().includes(term);
      const matchTitle = (inc.title || '').toLowerCase().includes(term);
      const matchUser = (inc.user || '').toLowerCase().includes(term);
      const matchDevice = (inc.device || '').toLowerCase().includes(term);
      if (!matchId && !matchTitle && !matchUser && !matchDevice) return false;
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#f8fafc' }}>
            Security Incident Triage Matrix
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Deterministic sliding-window correlation grouped by user identity and target device.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '14px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          {/* Batch Filter Pills */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, marginRight: '4px' }}>
              BATCH:
            </span>
            <button
              onClick={() => onSelectBatch && onSelectBatch('latest')}
              className={`btn ${selectedBatchId === 'latest' ? 'btn-cyber' : 'btn-outline'}`}
              style={{ padding: '4px 10px', fontSize: '11px', fontWeight: 600 }}
            >
              Latest Batch
            </button>
            <button
              onClick={() => onSelectBatch && onSelectBatch('all')}
              className={`btn ${selectedBatchId === 'all' ? 'btn-cyber' : 'btn-outline'}`}
              style={{ padding: '4px 10px', fontSize: '11px', fontWeight: 600 }}
            >
              All Batches
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
                  padding: '4px 8px',
                  fontSize: '11px',
                  outline: 'none'
                }}
              >
                <option value="latest">Scope: Latest Batch</option>
                <option value="all">Scope: All Batches</option>
                {batches.map((b) => (
                  <option key={b.batch_id} value={b.batch_id}>
                    {b.batch_id} ({b.filename})
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Severity Filter Pills */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, marginRight: '4px' }}>
              SEVERITY:
            </span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`btn ${severityFilter === sev ? 'btn-cyber' : 'btn-outline'}`}
                style={{ padding: '4px 10px', fontSize: '11px', fontWeight: 600 }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '260px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            padding: '6px 12px',
            width: '100%'
          }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search user, device, incident ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-primary)',
                fontSize: '12px',
                outline: 'none',
                width: '100%'
              }}
            />
          </div>
        </div>
      </div>

      {/* Incident List Table */}
      <div className="card" style={{ padding: '0' }}>
        {filteredIncidents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-muted)' }}>
            <ShieldAlert size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
            <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              No Matching Incidents Found
            </div>
            <p style={{ fontSize: '12px', marginTop: '4px' }}>
              Adjust your search filter or run the threat investigation pipeline.
            </p>
          </div>
        ) : (
          <div className="table-container" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Title & Attack Patterns</th>
                  <th>Severity</th>
                  <th>Target User / Host</th>
                  <th>Time Window (UTC)</th>
                  <th>Evidence</th>
                  <th>AI Status</th>
                  <th>Verification</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.map((inc) => (
                  <tr key={inc.incident_id}>
                    <td className="font-mono" style={{ fontWeight: 600, color: 'var(--color-cyan)', fontSize: '13px' }}>
                      <div>{inc.incident_id}</div>
                      {inc.batch_id && (
                        <div style={{ marginTop: '2px' }}>
                          <span className="badge badge-purple" style={{ fontSize: '9px', padding: '1px 5px' }}>
                            {inc.batch_id}
                          </span>
                        </div>
                      )}
                    </td>
                    <td style={{ maxWidth: '320px' }}>
                      <div style={{ fontWeight: 600, color: '#f8fafc' }}>
                        {inc.title}
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                        {inc.detected_patterns?.map((pat, idx) => (
                          <span key={idx} className="badge badge-cyan" style={{ fontSize: '10px' }}>
                            {pat}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <span className={`badge badge-${(inc.severity || 'low').toLowerCase()}`}>
                        {inc.severity || 'LOW'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                        <User size={12} color="var(--text-muted)" />
                        <span style={{ fontWeight: 600 }}>{inc.user || 'N/A'}</span>
                      </div>
                      {inc.device && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                          <Laptop size={12} color="var(--text-muted)" />
                          <span>{inc.device}</span>
                        </div>
                      )}
                    </td>
                    <td style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      <div>{formatTime(inc.start_time)}</div>
                      <div>{formatTime(inc.end_time)}</div>
                    </td>
                    <td className="font-mono" style={{ fontSize: '12px' }}>
                      {inc.evidence_count} events
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
                        className="btn btn-cyber"
                        style={{ padding: '6px 12px', fontSize: '11px' }}
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
