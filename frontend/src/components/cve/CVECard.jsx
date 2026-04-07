import { useSortable } from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { SeverityBadge } from './SeverityBadge'
import { EPSSBar } from './EPSSBar'
import { KEVBadge } from './KEVBadge'

export function CVECard({ cve, rank }) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: cve.cve_id })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    background: isDragging ? 'var(--bg-elevated)' : 'var(--bg-surface)',
    border: `1px solid ${cve.in_kev ? 'var(--kev)' : 'var(--border)'}`,
    borderRadius: '8px',
    padding: '12px 16px',
    cursor: 'grab',
    opacity: isDragging ? 0.85 : 1,
    zIndex: isDragging ? 10 : 1,
    position: 'relative'
  }

  return (
    <div ref={setNodeRef} style={style} {...attributes} {...listeners}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent-blue)' }}>
          {rank && <span style={{ color: 'var(--text-muted)', marginRight: 8 }}>#{rank}</span>}
          {cve.cve_id}
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          {cve.in_kev && <KEVBadge />}
          <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
        </div>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '0 0 10px', lineHeight: 1.5 }}>
        {cve.description}
      </p>
      <EPSSBar score={cve.epss_score || 0} />
      <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
        <span>CVSS {cve.cvss_score.toFixed(1)}</span>
        <span>Exploit {cve.exploitability_score.toFixed(1)}</span>
        <span>{cve.patch_available ? '✓ Patch available' : '✗ No patch'}</span>
        <span>{cve.published_date}</span>
      </div>
    </div>
  )
}
