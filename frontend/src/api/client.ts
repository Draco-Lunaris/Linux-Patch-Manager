import axios from 'axios'

// Base API client — JWT interceptors added in M2
export const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})
