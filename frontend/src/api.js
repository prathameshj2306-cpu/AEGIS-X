/**
 * AEGIS-X Centralized API Client.
 * Connects React frontend directly to the FastAPI backend.
 */

const BASE_URL = '/api';

export async function fetchHealth() {
  const res = await fetch(`${BASE_URL}/health`);
  if (!res.ok) throw new Error(`Health check failed (${res.status})`);
  return res.json();
}

export async function uploadLogFile(file, source = null) {
  const formData = new FormData();
  formData.append('file', file);
  if (source) {
    formData.append('source', source);
  }

  const res = await fetch(`${BASE_URL}/upload`, {
    method: 'POST',
    body: formData,
  });

  const data = await res.json();
  if (!res.ok) {
    const errorMsg = data.detail
      ? (typeof data.detail === 'object' ? JSON.stringify(data.detail) : data.detail)
      : data.error || 'Upload failed';
    throw new Error(errorMsg);
  }
  return data;
}

export async function fetchBatches() {
  const res = await fetch(`${BASE_URL}/batches`);
  if (!res.ok) throw new Error(`Failed to load ingestion batches (${res.status})`);
  return res.json();
}

export async function fetchBatch(batchId) {
  const res = await fetch(`${BASE_URL}/batches/${encodeURIComponent(batchId)}`);
  if (!res.ok) throw new Error(`Batch '${batchId}' not found (${res.status})`);
  return res.json();
}

export async function runPipeline(batchId = null) {
  const query = batchId ? `?batch_id=${encodeURIComponent(batchId)}` : '';
  const res = await fetch(`${BASE_URL}/pipeline/run${query}`, {
    method: 'POST',
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || data.error || 'Pipeline execution failed');
  }
  return data;
}

export async function fetchIncidents(params = {}) {
  const query = new URLSearchParams();
  if (params.batch_id) query.append('batch_id', params.batch_id);
  if (params.severity) query.append('severity', params.severity);
  if (params.status) query.append('status', params.status);
  if (params.user) query.append('user', params.user);

  const url = `${BASE_URL}/incidents${query.toString() ? `?${query.toString()}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load incidents (${res.status})`);
  return res.json();
}

export async function fetchIncidentDetail(incidentId) {
  const res = await fetch(`${BASE_URL}/incidents/${encodeURIComponent(incidentId)}`);
  if (!res.ok) throw new Error(`Incident '${incidentId}' not found (${res.status})`);
  return res.json();
}

// Alias for plural form compatibility
export const fetchIncidentDetails = fetchIncidentDetail;

export async function analyzeIncident(incidentId) {
  const res = await fetch(`${BASE_URL}/incidents/${encodeURIComponent(incidentId)}/analyze`, {
    method: 'POST',
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || data.error || 'AI analysis failed');
  }
  return data;
}

export async function generateReport(incidentId, format = 'both', sidecar = true, overwrite = true) {
  // Support options object or positional arguments
  let fmt = format;
  let sc = sidecar;
  let ow = overwrite;
  if (typeof format === 'object' && format !== null) {
    fmt = format.format || 'both';
    sc = format.include_sidecar !== undefined ? format.include_sidecar : (format.sidecar !== undefined ? format.sidecar : true);
    ow = format.overwrite !== undefined ? format.overwrite : true;
  }

  const query = new URLSearchParams({
    format: fmt,
    sidecar: String(sc),
    overwrite: String(ow),
  });

  const res = await fetch(`${BASE_URL}/incidents/${encodeURIComponent(incidentId)}/report?${query.toString()}`, {
    method: 'POST',
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || data.error || 'Report generation failed');
  }
  return data;
}

// Aliases for component compatibility
export const runSecurityPipeline = runPipeline;
export const generateIncidentReport = generateReport;

export function getReportDownloadUrl(filename) {
  return `${BASE_URL}/reports/${encodeURIComponent(filename)}`;
}
