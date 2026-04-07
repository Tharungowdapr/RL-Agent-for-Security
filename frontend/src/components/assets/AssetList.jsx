export function AssetList({ assets }) {
  if (!assets || assets.length === 0) return null

  return (
    <div>
      <h3 style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Company Assets
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {assets.map(a => (
          <div key={a.asset_id} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{a.name}</span>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{a.asset_id}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
              {a.description}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Runs: {a.software.slice(0, 2).join(', ')}{a.software.length > 2 ? '...' : ''}
              </div>
              <span style={{
                background: a.criticality_score >= 8 ? 'rgba(255,68,68,0.1)' : 'rgba(255,255,255,0.05)',
                color: a.criticality_score >= 8 ? '#ff4444' : 'var(--text-muted)',
                padding: '2px 6px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)'
              }}>
                Crit: {a.criticality_score.toFixed(1)}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
