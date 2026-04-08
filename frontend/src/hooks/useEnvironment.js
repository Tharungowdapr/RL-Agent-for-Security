import { useState, useCallback } from 'react'
import { resetEnv, stepEnv } from '../api/envClient'

export function useEnvironment() {
  const [observation, setObservation] = useState(null)
  const [reward, setReward] = useState(null)
  const [done, setDone] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])

  const reset = useCallback(async (taskId) => {
    setLoading(true)
    setError(null)
    setHistory([])
    try {
      const result = await resetEnv(taskId)
      setObservation(result.observation)
      setDone(result.observation.done || false)
      setReward(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const step = useCallback(async (targetId) => {
    setLoading(true)
    setError(null)
    try {
      const action = { action_type: 'prioritize', target_id: targetId }
      const result = await stepEnv(action)
      
      setObservation(result.observation)
      setReward(result.reward)
      setDone(result.done)
      
      setHistory(prev => [...prev, {
        step: result.observation?.step || 0,
        reward: result.reward,
        action: targetId,
        error: result.info?.error
      }])
      return result
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  return { observation, reward, done, loading, error, history, reset, step }
}
