const SEVERITY_COLORS = {
  CRITICAL: { bg: 'rgba(255,68,68,0.15)', color: '#ff4444', border: 'rgba(255,68,68,0.4)' },
  HIGH:     { bg: 'rgba(255,140,0,0.15)', color: '#ff8c00', border: 'rgba(255,140,0,0.4)' },
  MEDIUM:   { bg: 'rgba(245,197,24,0.15)', color: '#f5c518', border: 'rgba(245,197,24,0.4)' },
  LOW:      { bg: 'rgba(74,222,128,0.15)', color: '#4ade80', border: 'rgba(74,222,128,0.4)' },
}

export function SeverityBadge({ severity, score }) {
  const colors = SEVERITY_COLORS[severity] || SEVERITY_COLORS.LOW
  return (
    <span style={{
      background: colors.bg,
      color: colors.color,
      border: `1px solid ${colors.border}`,
      borderRadius: 4,
      padding: '2px 8px',
      fontSize: 11,
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      letterSpacing: '0.03em'
    }}>
      {severity} {score.toFixed(1)}
    </span>
  )
}
