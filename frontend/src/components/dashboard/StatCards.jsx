export function StatCards({ observation }) {
  if (!observation) return null

  const cves = observation.cves || []
  const kevCount = cves.filter(c => c.in_kev).length
  const avgEpss = cves.length > 0 ? cves.reduce((acc, c) => acc + (c.epss_score || 0), 0) / cves.length : 0

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Total CVEs</div>
        <div style={{ fontSize: 24, fontWeight: 'bold', fontFamily: 'var(--font-mono)' }}>{cves.length}</div>
      </div>
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>CISA KEV</div>
        <div style={{ fontSize: 24, fontWeight: 'bold', fontFamily: 'var(--font-mono)', color: kevCount > 0 ? 'var(--kev)' : 'inherit' }}>{kevCount}</div>
      </div>
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Avg EPSS</div>
        <div style={{ fontSize: 24, fontWeight: 'bold', fontFamily: 'var(--font-mono)' }}>{(avgEpss * 100).toFixed(1)}%</div>
      </div>
    </div>
  )
}
