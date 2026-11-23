import React, { useState } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Play, Database, ArrowRight, Layers, Clock } from 'lucide-react';
import { uploadLogFile } from '../api';

export default function IngestionView({
  batches = [],
  selectedBatchId = 'latest',
  onSelectBatch,
  onUploadSuccess,
  onRunPipeline,
  pipelineRunning
}) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [sourceType, setSourceType] = useState(''); // '' means auto-detect
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [uploadError, setUploadError] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setUploadResult(null);
      setUploadError(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      setUploadResult(null);
      setUploadError(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    setUploadError(null);
    setUploadResult(null);

    try {
      const result = await uploadLogFile(selectedFile, sourceType || null);
      setUploadResult(result);
      setSelectedFile(null);
      if (onUploadSuccess) onUploadSuccess(result.batch_id);
    } catch (err) {
      setUploadError(err.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '850px' }}>
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#f8fafc' }}>
          Security Telemetry Log Ingestion
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
          Upload authentication logs (failed/successful logins, MFA, password changes) or endpoint logs (process start/stop, privilege elevation).
        </p>
      </div>

      {/* Upload Box */}
      <div className="card">
        <div
          className="dropzone"
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => document.getElementById('file-input-elem').click()}
        >
          <input
            id="file-input-elem"
            type="file"
            accept=".csv,.json"
            style={{ display: 'none' }}
            onChange={handleFileChange}
          />

          <UploadCloud size={40} color="var(--color-cyan)" style={{ margin: '0 auto 12px', opacity: 0.8 }} />

          {selectedFile ? (
            <div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: '#f8fafc' }}>
                {selectedFile.name}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {(selectedFile.size / 1024).toFixed(1)} KB • Click to change file
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: '#f8fafc' }}>
                Drag and drop your security log file here
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
                Supports CSV, JSON, and NDJSON files up to 10 MB
              </div>
            </div>
          )}
        </div>

        {/* Source Configuration */}
        <div style={{ marginTop: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Telemetry Source Classification
          </label>
          <div style={{ display: 'flex', gap: '12px' }}>
            {[
              { id: '', label: 'Auto-Detect (Content Signature)' },
              { id: 'authentication', label: 'Authentication Logs' },
              { id: 'endpoint', label: 'Endpoint / Process Logs' },
            ].map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setSourceType(opt.id)}
                className={`btn ${sourceType === opt.id ? 'btn-cyber' : 'btn-outline'}`}
                style={{ fontSize: '12px', padding: '6px 14px' }}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Auto-detect inspects headers and event types (e.g. <code>process_start</code> → endpoint, <code>login_failure</code> → authentication).
          </p>
        </div>

        {/* Action Button */}
        <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
          {selectedFile && (
            <button
              onClick={() => setSelectedFile(null)}
              className="btn btn-outline"
              disabled={uploading}
            >
              Cancel
            </button>
          )}
          <button
            onClick={handleUpload}
            disabled={!selectedFile || uploading}
            className="btn btn-primary"
            style={{ minWidth: '140px' }}
          >
            {uploading ? 'Ingesting...' : 'Ingest & Store Events'}
          </button>
        </div>
      </div>

      {/* Success Banner */}
      {uploadResult && (
        <div className="card" style={{ borderLeft: '4px solid var(--color-green)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
            <CheckCircle2 size={20} color="var(--color-green)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span className="badge badge-purple" style={{ fontSize: '11px', fontWeight: 700 }}>
                  BATCH: {uploadResult.batch_id}
                </span>
                <span className="badge badge-cyan" style={{ fontSize: '10px' }}>
                  LATEST BATCH
                </span>
              </div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: '#f8fafc' }}>
                Successfully Ingested {uploadResult.event_count} Security Events
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                File: <b>{uploadResult.filename}</b> • Classified Source: <b>{uploadResult.source}</b> • Total in DB: <b>{uploadResult.total_events_in_db}</b>
              </div>
              {uploadResult.error_count > 0 && (
                <div style={{ fontSize: '11px', color: 'var(--color-amber)', marginTop: '4px' }}>
                  {uploadResult.error_count} malformed records were skipped during validation.
                </div>
              )}

              <div style={{ marginTop: '16px' }}>
                <button
                  onClick={() => onRunPipeline(uploadResult.batch_id)}
                  disabled={pipelineRunning}
                  className="btn btn-cyber"
                  style={{ fontSize: '12px', padding: '6px 14px' }}
                >
                  <Play size={12} fill="white" />
                  <span>{pipelineRunning ? 'Analyzing...' : `Run Investigation on Batch ${uploadResult.batch_id}`}</span>
                  <ArrowRight size={12} />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {uploadError && (
        <div className="card" style={{ borderLeft: '4px solid var(--color-red)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
            <AlertCircle size={20} color="var(--color-red)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#fca5a5' }}>
                Upload Rejected
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                {uploadError}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Ingestion Batch History Table */}
      {batches && batches.length > 0 && (
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#f8fafc' }}>
                Ingestion Batch History
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                All uploaded telemetry batches are stored with strict data isolation.
              </p>
            </div>
            <span className="badge badge-cyan">{batches.length} Batch(es)</span>
          </div>

          <div className="table-container" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Batch ID</th>
                  <th>Source File</th>
                  <th>Type</th>
                  <th>Events</th>
                  <th>Status</th>
                  <th>Incidents</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((b) => (
                  <tr key={b.batch_id}>
                    <td>
                      <span className="font-mono" style={{ fontWeight: 600, color: 'var(--color-cyan)', fontSize: '12px' }}>
                        {b.batch_id}
                      </span>
                    </td>
                    <td style={{ fontSize: '12px', fontWeight: 500, color: '#f8fafc' }}>
                      {b.filename}
                    </td>
                    <td>
                      <span className="badge badge-medium" style={{ fontSize: '10px' }}>
                        {b.source}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '12px' }}>
                      {b.event_count}
                    </td>
                    <td>
                      <span className={`badge ${b.status === 'INVESTIGATED' ? 'badge-success' : 'badge-cyan'}`} style={{ fontSize: '10px' }}>
                        {b.status}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '12px' }}>
                      {b.incident_count}
                    </td>
                    <td>
                      <button
                        onClick={() => onRunPipeline(b.batch_id)}
                        disabled={pipelineRunning}
                        className="btn btn-cyber"
                        style={{ padding: '4px 10px', fontSize: '11px' }}
                      >
                        <Play size={10} fill="white" />
                        <span>Investigate</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sample Files Reference */}
      <div className="card" style={{ fontSize: '12px' }}>
        <h4 style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginBottom: '8px' }}>
          Demonstration Datasets Available
        </h4>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '8px' }}>
          You can test ingestion by browsing to sample logs in your project:
        </p>
        <ul style={{ paddingLeft: '20px', color: 'var(--text-muted)', lineHeight: '1.8' }}>
          <li><code>C:\AEGIS-X\data\evaluation\auth_events.csv</code> (Brute-force login attack sequences)</li>
          <li><code>C:\AEGIS-X\data\evaluation\endpoint_events.csv</code> (Privilege escalation & suspicious PowerShell commands)</li>
        </ul>
      </div>
    </div>
  );
}
