import React, { useState, useEffect } from 'react';
import {
  generateReport,
  getReportDownloadUrl,
  fetchIncidents
} from '../api';
import {
  FileText,
  Download,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Hash,
  ExternalLink,
  RefreshCw,
  Copy,
  Check,
  ShieldCheck,
  Sparkles
} from 'lucide-react';

export default function ReportsView({ initialIncidentId, incidents = [] }) {
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId || '');
  const [format, setFormat] = useState('both'); // 'html', 'json', 'both'
  const [includeSidecar, setIncludeSidecar] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [generatedReports, setGeneratedReports] = useState([]);
  const [copiedText, setCopiedText] = useState(null);

  useEffect(() => {
    if (initialIncidentId) {
      setSelectedIncidentId(initialIncidentId);
    }
  }, [initialIncidentId]);

  const handleGenerate = async (e) => {
    if (e) e.preventDefault();
    if (!selectedIncidentId) {
      setError('Please select an incident to generate a report.');
      return;
    }

    setGenerating(true);
    setError(null);

    try {
      const response = await generateReport(selectedIncidentId, {
        format,
        include_sidecar: includeSidecar
      });

      // Parse files from backend response schema GenerateReportResponse
      // generated_files is a dict: { "html": "...", "json": "...", "sidecar": "..." }
      const files = [];
      const sidecars = [];

      if (response && response.generated_files) {
        if (typeof response.generated_files === 'object' && !Array.isArray(response.generated_files)) {
          Object.entries(response.generated_files).forEach(([type, filename]) => {
            const fname = typeof filename === 'string' ? filename : String(filename);
            if (type === 'sidecar' || fname.endsWith('.sha256')) {
              sidecars.push({ type: 'sidecar', filename: fname });
            } else {
              files.push({ type, filename: fname });
            }
          });
        } else if (Array.isArray(response.generated_files)) {
          response.generated_files.forEach((item) => {
            const fname = typeof item === 'string' ? item : (item.filename || String(item));
            const type = (typeof item === 'object' && item.type) ? item.type : (fname.endsWith('.html') ? 'html' : fname.endsWith('.json') ? 'json' : 'file');
            if (type === 'sidecar' || fname.endsWith('.sha256')) {
              sidecars.push({ type: 'sidecar', filename: fname });
            } else {
              files.push({ type, filename: fname });
            }
          });
        }
      }

      // Add to local state of generated reports
      setGeneratedReports((prev) => [
        {
          id: `${selectedIncidentId}-${Date.now()}`,
          incident_id: selectedIncidentId,
          timestamp: response.timestamp || new Date().toISOString(),
          format: format,
          files: files,
          sidecar_files: sidecars,
          output_dir: response.output_dir || 'reports',
          details: response
        },
        ...prev
      ]);
    } catch (err) {
      setError(err.message || 'Failed to generate investigation report.');
    } finally {
      setGenerating(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedText(key);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const currentIncident = incidents.find(i => i.incident_id === selectedIncidentId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <FileText className="text-cyan" size={22} />
          Investigation Report Generator
        </h2>
        <p className="text-secondary text-sm mt-1">
          Export tamper-evident investigation reports in executive HTML and machine-readable JSON formats with cryptographic SHA-256 sidecars.
        </p>
      </div>

      {/* Report Configuration & Generator Card */}
      <div className="card">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 pb-2 border-b border-border/40">
          Report Export Configuration
        </h3>

        {error && (
          <div className="mb-4 p-3 bg-red/10 border border-red/40 rounded-lg text-sm text-red flex items-center gap-2">
            <AlertTriangle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleGenerate} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Incident Selection */}
            <div>
              <label className="block text-xs font-semibold text-secondary uppercase mb-1.5">
                Target Incident
              </label>
              <select
                className="input"
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
              >
                <option value="">-- Select an incident to export report --</option>
                {incidents.length === 0 ? (
                  <option value="" disabled>No incidents available — Run Pipeline first</option>
                ) : (
                  incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      {inc.incident_id} — {inc.severity} — {inc.title || (inc.detected_patterns && inc.detected_patterns.join(', '))} — {inc.user || 'Unknown User'}
                    </option>
                  ))
                )}
              </select>
              {currentIncident && (
                <div className="mt-1.5 text-xs text-muted flex items-center gap-2">
                  {currentIncident.batch_id && (
                    <>
                      <span className="badge badge-purple" style={{ fontSize: '10px' }}>BATCH: {currentIncident.batch_id}</span>
                      <span>•</span>
                    </>
                  )}
                  <span>Patterns: <strong className="text-cyan font-mono">{currentIncident.detected_patterns?.join(', ') || 'N/A'}</strong></span>
                  <span>•</span>
                  <span>Severity: <strong className="text-amber">{currentIncident.severity}</strong></span>
                  <span>•</span>
                  <span>Status: <strong className="text-primary">{currentIncident.status}</strong></span>
                </div>
              )}
            </div>

            {/* Format Selection */}
            <div>
              <label className="block text-xs font-semibold text-secondary uppercase mb-1.5">
                Report Format
              </label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => setFormat('html')}
                  className={`btn text-xs py-2 ${format === 'html' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  <FileText size={14} /> HTML Report
                </button>
                <button
                  type="button"
                  onClick={() => setFormat('json')}
                  className={`btn text-xs py-2 ${format === 'json' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  <FileCode size={14} /> JSON Report
                </button>
                <button
                  type="button"
                  onClick={() => setFormat('both')}
                  className={`btn text-xs py-2 ${format === 'both' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  <Sparkles size={14} /> Both (HTML & JSON)
                </button>
              </div>
            </div>
          </div>

          {/* Cryptographic Verification Checkbox */}
          <div className="pt-2 flex items-center gap-3">
            <label className="flex items-center gap-2 cursor-pointer text-xs text-secondary hover:text-white">
              <input
                type="checkbox"
                checked={includeSidecar}
                onChange={(e) => setIncludeSidecar(e.target.checked)}
                className="rounded border-border bg-bg text-cyan focus:ring-0 focus:ring-offset-0"
              />
              <span className="font-medium">Generate Cryptographic SHA-256 Sidecar Checksums (`.sha256`)</span>
            </label>
            <span className="text-[11px] text-muted font-mono">(Tamper-evident verification guarantee)</span>
          </div>

          {/* Generate Button */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={generating || !selectedIncidentId}
              className="btn btn-primary flex items-center gap-2 px-6 py-2.5"
            >
              {generating ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  <span>Building Report & Calculating SHA-256 Digest...</span>
                </>
              ) : (
                <>
                  <FileText size={16} />
                  <span>Generate Investigation Report</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Generated Reports List */}
      <div className="card">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 pb-2 border-b border-border/40 flex items-center justify-between">
          <span>Generated Reports ({generatedReports.length})</span>
          <span className="text-xs font-normal text-muted font-mono">Storage: backend/reports/</span>
        </h3>

        {generatedReports.length === 0 ? (
          <div className="text-center py-10 text-muted">
            <FileText size={36} className="mx-auto mb-2 opacity-40" />
            <p className="text-sm font-medium">No reports generated in this session yet</p>
            <p className="text-xs mt-1">Select an incident above and click "Generate Investigation Report" to produce downloadable artifacts.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {generatedReports.map((rep) => (
              <div key={rep.id} className="p-4 bg-bg/60 rounded-lg border border-border/40 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="px-2 py-0.5 rounded bg-cyan/10 text-cyan border border-cyan/30 font-bold">
                      {rep.incident_id}
                    </span>
                    <span className="text-muted">
                      {new Date(rep.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="badge badge-low text-[10px] uppercase">
                      {rep.format}
                    </span>
                  </div>

                  <span className="text-xs text-emerald flex items-center gap-1 font-medium">
                    <CheckCircle2 size={13} /> Generated Successfully
                  </span>
                </div>

                {/* Download Buttons Row */}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {Array.isArray(rep.files) && rep.files.map((file, idx) => {
                    const filename = typeof file === 'string' ? file : (file?.filename || String(file || ''));
                    if (!filename) return null;
                    const isHtml = filename.endsWith('.html');
                    const downloadUrl = getReportDownloadUrl(filename);
                    return (
                      <a
                        key={filename || idx}
                        href={downloadUrl}
                        download={filename}
                        className="btn btn-secondary btn-sm flex items-center gap-1.5 text-xs py-1.5 px-3"
                      >
                        <Download size={13} className={isHtml ? 'text-cyan' : 'text-amber'} />
                        <span>Download {filename}</span>
                      </a>
                    );
                  })}

                  {Array.isArray(rep.sidecar_files) && rep.sidecar_files.map((sfile, idx) => {
                    const sfilename = typeof sfile === 'string' ? sfile : (sfile?.filename || String(sfile || ''));
                    if (!sfilename) return null;
                    const downloadUrl = getReportDownloadUrl(sfilename);
                    return (
                      <a
                        key={sfilename || idx}
                        href={downloadUrl}
                        download={sfilename}
                        className="btn btn-secondary btn-sm flex items-center gap-1.5 text-xs py-1.5 px-3 font-mono"
                      >
                        <Hash size={13} className="text-emerald" />
                        <span>{sfilename}</span>
                      </a>
                    );
                  })}
                </div>

                {/* Details Breakdown if available */}
                {rep.details?.sha256_digests && typeof rep.details.sha256_digests === 'object' && !Array.isArray(rep.details.sha256_digests) && (
                  <div className="mt-2 pt-2 border-t border-border/30 text-xs space-y-1">
                    <span className="text-muted font-mono text-[11px] block">Cryptographic Checksums:</span>
                    {Object.entries(rep.details.sha256_digests).map(([fname, hash]) => (
                      <div key={fname} className="flex items-center justify-between bg-black/40 px-2.5 py-1.5 rounded font-mono text-[11px]">
                        <span className="text-secondary truncate max-w-[200px]">{fname}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-emerald font-mono truncate max-w-[280px]" title={String(hash)}>{String(hash)}</span>
                          <button
                            type="button"
                            className="text-muted hover:text-white"
                            onClick={() => copyToClipboard(String(hash), fname)}
                            title="Copy SHA-256 hash"
                          >
                            {copiedText === fname ? <Check size={12} className="text-emerald" /> : <Copy size={12} />}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
