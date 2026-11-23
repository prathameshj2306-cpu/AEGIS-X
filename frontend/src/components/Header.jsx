import React from 'react';
import { Shield, Database, Cpu, Activity, RefreshCw } from 'lucide-react';

export default function Header({ health, onRefresh, loading }) {
  const isHealthy = health?.status === 'healthy';
  const isOllamaOnline = health?.ollama_online;

  return (
    <header className="top-navbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #0284c7 0%, #06b6d4 100%)',
            padding: '8px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={20} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '16px', fontWeight: 700, letterSpacing: '1px', color: '#f8fafc' }}>
                AEGIS-X
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '10px' }}>OFFLINE SOC</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              From Raw Security Logs to Explainable Cyber Threat Investigations
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Database Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          background: 'var(--bg-surface)',
          padding: '6px 12px',
          borderRadius: '6px',
          border: '1px solid var(--border-color)',
          fontSize: '12px'
        }}>
          <Database size={14} color="var(--color-cyan)" />
          <span style={{ color: 'var(--text-secondary)' }}>SQLite:</span>
          <span style={{ fontWeight: 600, color: health?.database_connected ? 'var(--color-green)' : 'var(--color-red)' }}>
            {health?.database_connected ? 'CONNECTED' : 'DISCONNECTED'}
          </span>
          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
            ({health?.event_count || 0} evts / {health?.incident_count || 0} incs)
          </span>
        </div>

        {/* Ollama SLM Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          background: 'var(--bg-surface)',
          padding: '6px 12px',
          borderRadius: '6px',
          border: '1px solid var(--border-color)',
          fontSize: '12px'
        }}>
          <Cpu size={14} color={isOllamaOnline ? 'var(--color-green)' : 'var(--color-purple)'} />
          <span style={{ color: 'var(--text-secondary)' }}>SLM:</span>
          <span className={`badge ${isOllamaOnline ? 'badge-success' : 'badge-fallback'}`}>
            {isOllamaOnline ? 'QWEN ONLINE' : 'FALLBACK ACTIVE'}
          </span>
        </div>

        {/* System Health Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          background: 'var(--bg-surface)',
          padding: '6px 12px',
          borderRadius: '6px',
          border: '1px solid var(--border-color)',
          fontSize: '12px'
        }}>
          <Activity size={14} color={isHealthy ? 'var(--color-green)' : 'var(--color-amber)'} />
          <span style={{ color: 'var(--text-secondary)' }}>Platform:</span>
          <span className={`badge ${isHealthy ? 'badge-success' : 'badge-medium'}`}>
            {health?.status ? health.status.toUpperCase() : 'CHECKING...'}
          </span>
        </div>

        {/* Refresh button */}
        <button
          onClick={onRefresh}
          disabled={loading}
          className="btn btn-outline"
          title="Refresh telemetry"
          style={{ padding: '6px 10px' }}
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>
    </header>
  );
}
