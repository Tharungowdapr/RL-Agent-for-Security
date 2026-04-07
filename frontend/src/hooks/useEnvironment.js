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

  const step = useCallback(async (priorityOrder, justifications = {}) => {
    setLoading(true)
    setError(null)
    try {
      const result = await stepEnv({ priority_order: priorityOrder, justifications })
      setObservation(result.observation)
      setReward(result.reward)
      setDone(result.done)
      setHistory(prev => [...prev, {
        step: result.observation?.step || 0,
        reward: result.reward,
        action: priorityOrder,
        breakdown: result.info?.breakdown,
        feedback: result.info?.feedback
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
