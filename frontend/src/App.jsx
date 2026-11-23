import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import OverviewView from './components/OverviewView';
import IngestionView from './components/IngestionView';
import IncidentsView from './components/IncidentsView';
import InvestigationView from './components/InvestigationView';
import ReportsView from './components/ReportsView';
import SystemStatusView from './components/SystemStatusView';
import {
  fetchHealth,
  fetchIncidents,
  runPipeline,
  fetchBatches
} from './api';
import {
  CheckCircle2,
  AlertTriangle,
  Info,
  X,
  RefreshCw
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [health, setHealth] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [batches, setBatches] = useState([]);
  const [selectedBatchId, setSelectedBatchId] = useState('latest');
  const [investigationIncidentId, setInvestigationIncidentId] = useState(null);
  const [reportsIncidentId, setReportsIncidentId] = useState(null);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [apiError, setApiError] = useState(null);
  const [toast, setToast] = useState(null); // { type: 'success' | 'error' | 'info', message: string }

  // Initial Load with resilient error handling
  useEffect(() => {
    let mounted = true;
    const initApp = async () => {
      setInitialLoading(true);
      setApiError(null);
      try {
        await Promise.allSettled([loadHealth(), loadBatches(), loadIncidents('latest')]);
      } catch (err) {
        if (mounted) setApiError(err.message || 'Failed to initialize connection to backend');
      } finally {
        if (mounted) setInitialLoading(false);
      }
    };
    initApp();
    return () => { mounted = false; };
  }, []);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 4500);
  };

  const loadHealth = async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
    } catch (err) {
      console.warn('Backend health check unavailable:', err);
      // Defensive fallback health object so Header & views never throw
      setHealth((prev) => prev || {
        status: 'degraded',
        database_connected: false,
        event_count: 0,
        incident_count: 0,
        ollama_online: false,
        ollama_model: 'qwen2.5:1.5b'
      });
    }
  };

  const loadBatches = async () => {
    try {
      const data = await fetchBatches();
      const safeData = Array.isArray(data) ? data : [];
      setBatches(safeData);
      return safeData;
    } catch (err) {
      console.warn('Failed to load batches list:', err);
      setBatches([]);
      return [];
    }
  };

  const loadIncidents = async (batchId = selectedBatchId) => {
    try {
      const params = {};
      if (batchId) {
        params.batch_id = batchId;
      }
      const data = await fetchIncidents(params);
      const safeData = Array.isArray(data) ? data : [];
      setIncidents(safeData);
    } catch (err) {
      console.warn('Failed to load incidents list:', err);
      // Guarantee incidents is always an array
      setIncidents((prev) => (Array.isArray(prev) ? prev : []));
    }
  };

  const handleSelectBatch = async (batchId) => {
    setSelectedBatchId(batchId);
    await loadIncidents(batchId);
  };

  const handleRunPipeline = async (targetBatchId = null) => {
    setPipelineRunning(true);
    const scopeId = targetBatchId || selectedBatchId || 'latest';
    try {
      const result = await runPipeline(scopeId);
      const createdCount = result.incidents_created ?? result.new_incidents_created ?? 0;
      const detectionsCount = result.detections_found ?? result.detections_evaluated ?? 0;
      showToast(
        `Pipeline execution completed: ${createdCount} incident(s) generated from ${detectionsCount} detection(s) (Scope: ${result.batch_id || scopeId}).`,
        'success'
      );
      await Promise.all([loadHealth(), loadBatches(), loadIncidents(scopeId)]);
      setActiveTab('incidents');
    } catch (err) {
      showToast(err.message || 'Pipeline execution failed.', 'error');
    } finally {
      setPipelineRunning(false);
    }
  };

  const handleSelectTab = (tabId) => {
    if (tabId === 'investigation') {
      // Direct sidebar navigation clears specific incident selection
      setInvestigationIncidentId(null);
    }
    if (tabId === 'reports') {
      // Direct sidebar navigation clears specific incident preselection
      setReportsIncidentId(null);
    }
    setActiveTab(tabId);
  };

  const handleSelectIncident = (id) => {
    setInvestigationIncidentId(id);
    setActiveTab('investigation');
  };

  const handleNavigateToReports = (id) => {
    setReportsIncidentId(id || null);
    setActiveTab('reports');
  };

  return (
    <div className="min-h-screen bg-bg text-primary flex flex-col font-sans" style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Header with live health */}
      <Header
        health={health}
        onRefresh={async () => {
          await Promise.all([loadHealth(), loadIncidents()]);
          showToast('Platform telemetry refreshed', 'info');
        }}
      />

      {/* Main Layout Container */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Left Navigation Sidebar - handles both prop conventions */}
        <Sidebar
          currentTab={activeTab}
          activeTab={activeTab}
          onSelectTab={handleSelectTab}
          onTabChange={handleSelectTab}
          incidentCount={Array.isArray(incidents) ? incidents.length : 0}
        />

        {/* Dynamic Content Pane */}
        <main style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', backgroundColor: 'var(--bg-primary)' }}>
          <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>

            {/* Global API Error Notice if both endpoints fail */}
            {apiError && (
              <div style={{
                padding: '14px 18px',
                background: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                borderRadius: '8px',
                fontSize: '13px',
                color: 'var(--color-red)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <AlertTriangle size={18} />
                  <span><strong>Backend Connection Issue:</strong> {apiError}</span>
                </div>
                <button
                  onClick={() => {
                    loadHealth();
                    loadIncidents();
                  }}
                  className="btn btn-outline"
                  style={{ padding: '4px 12px', fontSize: '12px' }}
                >
                  <RefreshCw size={12} /> Retry
                </button>
              </div>
            )}

            {/* Notification Toast */}
            {toast && (
              <div style={{
                padding: '14px 18px',
                borderRadius: '8px',
                border: '1px solid',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)',
                background: toast.type === 'success'
                  ? 'rgba(16, 185, 129, 0.15)'
                  : toast.type === 'error'
                    ? 'rgba(239, 68, 68, 0.15)'
                    : 'rgba(6, 182, 212, 0.15)',
                borderColor: toast.type === 'success'
                  ? 'rgba(16, 185, 129, 0.5)'
                  : toast.type === 'error'
                    ? 'rgba(239, 68, 68, 0.5)'
                    : 'rgba(6, 182, 212, 0.5)',
                color: toast.type === 'success'
                  ? 'var(--color-green)'
                  : toast.type === 'error'
                    ? 'var(--color-red)'
                    : 'var(--color-cyan)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {toast.type === 'success' && <CheckCircle2 size={18} />}
                  {toast.type === 'error' && <AlertTriangle size={18} />}
                  {toast.type === 'info' && <Info size={18} />}
                  <span style={{ fontWeight: 500 }}>{toast.message}</span>
                </div>
                <button
                  onClick={() => setToast(null)}
                  style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', opacity: 0.7 }}
                >
                  <X size={16} />
                </button>
              </div>
            )}

            {/* View Switching — Canonical and Alias ID Support */}
            {activeTab === 'overview' && (
              <OverviewView
                health={health}
                incidents={incidents}
                batches={batches}
                selectedBatchId={selectedBatchId}
                onSelectBatch={handleSelectBatch}
                onRunPipeline={handleRunPipeline}
                pipelineRunning={pipelineRunning}
                onSelectIncident={handleSelectIncident}
                onNavigateToIngest={() => setActiveTab('ingestion')}
              />
            )}

            {(activeTab === 'ingestion' || activeTab === 'ingest') && (
              <IngestionView
                batches={batches}
                selectedBatchId={selectedBatchId}
                onSelectBatch={handleSelectBatch}
                onUploadSuccess={async (newBatchId) => {
                  await Promise.all([loadHealth(), loadBatches()]);
                  if (newBatchId) {
                    setSelectedBatchId(newBatchId);
                    await loadIncidents(newBatchId);
                  } else {
                    await loadIncidents(selectedBatchId);
                  }
                }}
                onRunPipeline={handleRunPipeline}
                pipelineRunning={pipelineRunning}
              />
            )}

            {activeTab === 'incidents' && (
              <IncidentsView
                incidents={incidents}
                batches={batches}
                selectedBatchId={selectedBatchId}
                onSelectBatch={handleSelectBatch}
                onSelectIncident={handleSelectIncident}
                onRefreshIncidents={() => loadIncidents(selectedBatchId)}
              />
            )}

            {activeTab === 'investigation' && (
              <InvestigationView
                incidentId={investigationIncidentId}
                incidents={incidents}
                onSelectIncident={(id) => setInvestigationIncidentId(id)}
                onBackToIncidents={() => setActiveTab('incidents')}
                onNavigateToReports={handleNavigateToReports}
                onIncidentUpdated={() => {
                  loadIncidents();
                  loadHealth();
                }}
              />
            )}

            {activeTab === 'reports' && (
              <ReportsView
                initialIncidentId={reportsIncidentId}
                incidents={incidents}
              />
            )}

            {(activeTab === 'status' || activeTab === 'system') && (
              <SystemStatusView
                health={health}
                onRefreshHealth={loadHealth}
              />
            )}

            {/* Fallback to Overview if unexpected activeTab is set */}
            {!['overview', 'ingestion', 'ingest', 'incidents', 'investigation', 'reports', 'status', 'system'].includes(activeTab) && (
              <OverviewView
                health={health}
                incidents={incidents}
                onRunPipeline={handleRunPipeline}
                pipelineRunning={pipelineRunning}
                onSelectIncident={handleSelectIncident}
                onNavigateToIngest={() => setActiveTab('ingestion')}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
