export function EPSSBar({ score }) {
  const pct = Math.round(score * 100)
  const color = pct > 50 ? 'var(--epss-high)' : pct > 10 ? 'var(--medium)' : 'var(--epss-low)'

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>EPSS exploitation probability</span>
        <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color }}>{pct.toFixed(1)}%</span>
      </div>
      <div style={{ height: 4, background: 'var(--bg-elevated)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${Math.max(pct, 1)}%`,
          background: color,
          borderRadius: 2,
          transition: 'width 0.4s ease'
        }} />
      </div>
    </div>
  )
}
