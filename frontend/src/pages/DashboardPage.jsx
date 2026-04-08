import { useEffect, useState } from 'react'
import { useEnvironment } from '../hooks/useEnvironment'
import { CVECard } from '../components/cve/CVECard'
import { RewardDisplay } from '../components/results/RewardDisplay'

export function DashboardPage() {
  const { observation, reward, done, loading, error, history, reset, step } = useEnvironment()
  const [activeTask, setActiveTask] = useState('easy')

  useEffect(() => {
    reset(activeTask)
  }, [activeTask, reset])

  const handleSelectCVE = (cveId) => {
    if (!loading && !done) {
      step(cveId)
    }
  }

  // Determine what has already been selected across steps
  const selectedCveIds = history.map(h => h.action)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 24, padding: 24,
      minHeight: '100vh', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}>

      {/* Left column — CVE triage */}
      <div>
        <div style={{ marginBottom: 20 }}>
          <h1 style={{ fontSize: 20, marginBottom: 8, color: 'var(--text-primary)' }}>OpenEnv Security Triage</h1>
          <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>AI-driven security vulnerability prioritization console</p>
        </div>

        <div style={{ margin: '24px 0 16px', display: 'flex', gap: 8 }}>
          {['easy', 'medium', 'hard'].map(t => (
            <button key={t} onClick={() => setActiveTask(t)}
              style={{ background: activeTask === t ? 'var(--accent-blue)' : 'var(--bg-elevated)',
                color: activeTask === t ? '#fff' : 'var(--text-secondary)',
                border: '1px solid var(--border)', borderRadius: 6, padding: '8px 16px',
                fontSize: 13, cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>

        {error && (
          <div style={{ padding: 12, background: 'rgba(255,68,68,0.1)', border: '1px solid var(--critical)', borderRadius: 8, color: 'var(--critical)', marginBottom: 16, fontSize: 14 }}>
            Error: {error}
          </div>
        )}

        {observation && (
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20,
            background: 'var(--bg-elevated)', borderRadius: 8, padding: '16px',
            borderLeft: '4px solid var(--accent-teal)' }}>
            <div style={{ marginBottom: 4 }}>Current Step: {observation.step} / 3</div>
            {observation.message && <div>{observation.message}</div>}
            {done && <div style={{ color: 'var(--accent-blue)', fontWeight: 600, marginTop: 4 }}>Episode Complete! Reset to test again.</div>}
          </div>
        )}

        {/* Clickable CVE list */}
        {observation?.vulnerabilities && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {observation.vulnerabilities.map((cve) => {
              const isSelected = selectedCveIds.includes(cve.id)
              return (
                <CVECard 
                  key={cve.id} 
                  cve={cve} 
                  onSelect={handleSelectCVE}
                  selected={isSelected}
                  disabled={loading || done || isSelected} 
                />
              )
            })}
          </div>
        )}
      </div>

      {/* Right column — Results */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <div style={{ background: 'var(--bg-surface)', padding: 20, borderRadius: 8, border: '1px solid var(--border)' }}>
            <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Episode Log</h3>
            {history.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No actions taken yet.</p>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {history.map((h, i) => (
                        <div key={i} style={{ padding: 12, background: 'var(--bg-elevated)', borderRadius: 6, fontSize: 13 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                                <strong>Step {i + 1}</strong>
                                <span>Reward: {h.reward?.toFixed(2)}</span>
                            </div>
                            <div style={{ color: 'var(--text-secondary)' }}>Selected: {h.action}</div>
                            {h.error && <div style={{ color: 'var(--critical)', marginTop: 4 }}>Error: {h.error}</div>}
                        </div>
                    ))}
                </div>
            )}
            
            {reward !== null && (
              <RewardDisplay 
                reward={history.reduce((acc, curr) => acc + (curr.reward || 0), 0)} />
            )}
        </div>
      </div>
    </div>
  )
}
