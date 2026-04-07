import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts'

export function RewardDisplay({ reward, breakdown, feedback }) {
  const pct = Math.round((reward || 0) * 100)
  const color = pct >= 70 ? '#4ade80' : pct >= 40 ? '#f5c518' : '#ff4444'

  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 20 }}>
      {/* Score ring */}
      <h3 style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Triage Result
      </h3>
      <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 16 }}>
        <div style={{ position: 'relative', width: 80, height: 80 }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart innerRadius="60%" outerRadius="100%"
              data={[{ value: pct, fill: color }]} startAngle={90} endAngle={90 - (pct * 3.6)}>
              <RadialBar dataKey="value" background={{ fill: 'var(--border)' }} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'var(--font-mono)', fontSize: 18, fontWeight: 700, color
          }}>
            {pct}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 4 }}>Reward Score</div>
          <div style={{ fontSize: 24, fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>
            {(reward || 0).toFixed(4)}
          </div>
        </div>
      </div>

      {/* Breakdown */}
      {breakdown && Object.entries(breakdown).map(([key, val]) => (
        <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0',
          borderTop: '1px solid var(--border)', fontSize: 13 }}>
          <span style={{ color: 'var(--text-secondary)' }}>{key.replace(/_/g, ' ')}</span>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {typeof val === 'number' ? val.toFixed(4) : val}
          </span>
        </div>
      ))}

      {/* Feedback */}
      {feedback && (
        <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-secondary)',
          background: 'var(--bg-elevated)', borderRadius: 6, padding: '10px 12px', lineHeight: 1.6 }}>
          {feedback}
        </div>
      )}
    </div>
  )
}
