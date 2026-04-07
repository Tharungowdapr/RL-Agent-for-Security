import { useEffect, useState } from 'react'
import { DndContext, closestCenter } from '@dnd-kit/core'
import { SortableContext, verticalListSortingStrategy, arrayMove } from '@dnd-kit/sortable'
import { useEnvironment } from '../hooks/useEnvironment'
import { CVECard } from '../components/cve/CVECard'
import { AssetList } from '../components/assets/AssetList'
import { RewardDisplay } from '../components/results/RewardDisplay'
import { StatCards } from '../components/dashboard/StatCards'

export function DashboardPage() {
  const { observation, reward, done, loading, error, history, reset, step } = useEnvironment()
  const [priorityOrder, setPriorityOrder] = useState([])
  const [justifications, setJustifications] = useState({})
  const [activeTask, setActiveTask] = useState('task1_severity_ranking')

  useEffect(() => {
    reset(activeTask)
  }, [activeTask])

  useEffect(() => {
    if (observation?.cves) {
      setPriorityOrder(observation.cves.map(c => c.cve_id))
    }
  }, [observation])

  const handleDragEnd = ({ active, over }) => {
    if (!over || active.id === over.id) return
    const oldIdx = priorityOrder.indexOf(active.id)
    const newIdx = priorityOrder.indexOf(over.id)
    setPriorityOrder(arrayMove(priorityOrder, oldIdx, newIdx))
  }

  const handleSubmit = () => {
    // For tasks that request exactly 5 or a subset, we can just pass the priorityOrder
    // Backend grading evaluates up to the max patches usually.
    step(priorityOrder, justifications)
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 24, padding: 24,
      minHeight: '100vh', background: 'var(--bg-primary)', color: 'var(--text-primary)' }}>

      {/* Left column — CVE triage */}
      <div>
        <div style={{ marginBottom: 20 }}>
          <h1 style={{ fontSize: 20, marginBottom: 8, color: 'var(--text-primary)' }}>OpenEnv Security Triage</h1>
          <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>AI-driven security vulnerability prioritization console</p>
        </div>

        <StatCards observation={observation} />

        <div style={{ margin: '24px 0 16px', display: 'flex', gap: 8 }}>
          {['task1_severity_ranking', 'task2_asset_prioritization', 'task3_full_triage'].map(t => (
            <button key={t} onClick={() => setActiveTask(t)}
              style={{ background: activeTask === t ? 'var(--accent-blue)' : 'var(--bg-elevated)',
                color: activeTask === t ? '#fff' : 'var(--text-secondary)',
                border: '1px solid var(--border)', borderRadius: 6, padding: '8px 16px',
                fontSize: 13, cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
              {t.replace('task', 'T').replace(/_/g, ' ')}
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
            {observation.message.split('\n').map((line, i) => <div key={i} style={{ marginBottom: line.trim() === '' ? 8 : 4 }}>{line}</div>)}
          </div>
        )}

        {/* Drag-and-drop CVE list */}
        {observation?.cves && (
          <DndContext collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <SortableContext items={priorityOrder} strategy={verticalListSortingStrategy}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {priorityOrder.map((id, idx) => {
                  const cve = observation.cves.find(c => c.cve_id === id)
                  return cve ? <CVECard key={id} cve={cve} rank={idx + 1} /> : null
                })}
              </div>
            </SortableContext>
          </DndContext>
        )}

        <button onClick={handleSubmit} disabled={loading || done}
          style={{ marginTop: 24, width: '100%', padding: '14px',
            background: done ? 'var(--bg-elevated)' : 'var(--accent-blue)',
            color: '#fff', border: 'none', borderRadius: 8, fontSize: 15,
            fontWeight: 600, cursor: loading || done ? 'not-allowed' : 'pointer' }}>
          {loading ? 'Submitting...' : done ? 'Episode complete (Reset to try again)' : 'Submit Triage Ranking'}
        </button>
      </div>

      {/* Right column — Assets + Results */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        {reward !== null && (
          <RewardDisplay reward={reward}
            breakdown={history[history.length - 1]?.breakdown}
            feedback={history[history.length - 1]?.feedback} />
        )}
        {observation?.assets && <AssetList assets={observation.assets} />}
      </div>
    </div>
  )
}
