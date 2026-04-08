import { SeverityBadge } from './SeverityBadge'
import { EPSSBar } from './EPSSBar'
import { KEVBadge } from './KEVBadge'

export function CVECard({ cve, onSelect, selected, disabled }) {
  const style = {
    background: selected ? 'var(--bg-elevated)' : 'var(--bg-surface)',
    border: `1px solid ${selected ? 'var(--accent-blue)' : cve.kev ? 'var(--kev)' : 'var(--border)'}`,
    borderRadius: '8px',
    padding: '12px 16px',
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled && !selected ? 0.6 : 1,
    position: 'relative',
    transition: 'all 0.2s ease',
    boxShadow: selected ? '0 0 0 2px var(--accent-blue)' : 'none'
  }

  return (
    <div style={style} onClick={() => !disabled && onSelect(cve.id)}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent-blue)', fontWeight: 600 }}>
          {cve.id} {selected && "✓ (Selected)"}
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          {cve.kev && <KEVBadge />}
          {/* using 'severity' as the number/score and 'severity_label' as the text label */}
          <SeverityBadge severity={cve.severity_label || "MEDIUM"} score={cve.severity} />
        </div>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '0 0 10px', lineHeight: 1.5 }}>
        {cve.description || "No description provided."}
      </p>
      <EPSSBar score={cve.epss || 0} />
      <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
        <span>CVSS {cve.severity?.toFixed(1) || '0.0'}</span>
        <span>Asset Criticality: {cve.asset_criticality || 5}</span>
      </div>
    </div>
  )
}
