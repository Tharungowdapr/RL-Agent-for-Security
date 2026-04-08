import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || ''

const client = axios.create({ baseURL: BASE, timeout: 15000 })

export const resetEnv = (taskId) =>
  client.post(`/reset?task_id=${taskId}`).then(r => r.data)

export const stepEnv = (action) =>
  client.post('/step', action).then(r => r.data)

export const getState = () =>
  client.get('/state').then(r => r.data)

export const getHealth = () =>
  client.get('/health').then(r => r.data)

export const listTasks = () =>
  client.get('/tasks').then(r => r.data)
