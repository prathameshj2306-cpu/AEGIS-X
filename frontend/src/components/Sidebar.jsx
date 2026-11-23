import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  AlertTriangle,
  SearchCheck,
  FileText,
  Activity,
  Terminal,
} from 'lucide-react';

export default function Sidebar({
  currentTab,
  activeTab,
  onSelectTab,
  onTabChange,
  incidentCount = 0
}) {
  const active = currentTab || activeTab || 'overview';
  const handleSelect = onSelectTab || onTabChange || (() => {});

  const menuItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'ingestion', label: 'Log Ingestion', icon: UploadCloud, aliases: ['ingestion', 'ingest'] },
    { id: 'incidents', label: 'Incidents', icon: AlertTriangle, badge: incidentCount, aliases: ['incidents'] },
    { id: 'investigation', label: 'Investigation', icon: SearchCheck, aliases: ['investigation'] },
    { id: 'reports', label: 'Reports', icon: FileText, aliases: ['reports'] },
    { id: 'status', label: 'System Status', icon: Activity, aliases: ['status', 'system'] },
  ];

  return (
    <aside className="sidebar">
      <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Terminal size={18} color="var(--color-cyan)" />
          <span style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.5px', color: '#f8fafc' }}>
            SOC INVESTIGATION
          </span>
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
          Air-Gapped & Deterministic
        </div>
      </div>

      <nav style={{ padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = active === item.id || (item.aliases && item.aliases.includes(active));

          return (
            <button
              key={item.id}
              onClick={() => handleSelect(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                borderRadius: '6px',
                border: 'none',
                backgroundColor: isActive ? 'var(--bg-surface-hover)' : 'transparent',
                color: isActive ? 'var(--color-cyan)' : 'var(--text-secondary)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '13px',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease',
                borderLeft: isActive ? '3px solid var(--color-cyan)' : '3px solid transparent',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <Icon size={16} color={isActive ? 'var(--color-cyan)' : 'var(--text-muted)'} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="badge badge-medium" style={{ fontSize: '10px', padding: '1px 6px' }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)', fontSize: '11px', color: 'var(--text-muted)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
          <span>Version:</span>
          <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>1.0.0 (Phase 4)</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span>Local SLM:</span>
          <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>Qwen2.5 1.5B</span>
        </div>
      </div>
    </aside>
  );
}
