import axios, { type AxiosError } from 'axios'
import type { InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '../store/authStore'
import type { FleetStatus, CreateJobRequest } from '../types'

const BASE_URL = '/api/v1'

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// ── Request interceptor: attach access token ────────────────────────────────
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = useAuthStore.getState().accessToken
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ── Response interceptor: refresh on 401 ────────────────────────────────────
let isRefreshing = false
let failedQueue: Array<{ resolve: (v: string) => void; reject: (e: unknown) => void }> = []

const processQueue = (error: unknown, token: string | null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error)
    else resolve(token!)
  })
  failedQueue = []
}

apiClient.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status !== 401 || original._retry) {
      return Promise.reject(error)
    }

    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject })
      }).then((token) => {
        original.headers.Authorization = `Bearer ${token}`
        return apiClient(original)
      })
    }

    original._retry = true
    isRefreshing = true

    const { refreshToken, setTokens, logout } = useAuthStore.getState()

    if (!refreshToken) {
      logout()
      window.location.href = '/login'
      return Promise.reject(error)
    }

    try {
      const { data } = await axios.post(`${BASE_URL}/auth/refresh`, {
        refresh_token: refreshToken,
      })
      setTokens(data.access_token, data.refresh_token)
      processQueue(null, data.access_token)
      original.headers.Authorization = `Bearer ${data.access_token}`
      return apiClient(original)
    } catch (refreshError) {
      processQueue(refreshError, null)
      logout()
      window.location.href = '/login'
      return Promise.reject(refreshError)
    } finally {
      isRefreshing = false
    }
  }
)

// ── Auth API functions ───────────────────────────────────────────────────────
export const authApi = {
  login: (username: string, password: string, totpCode?: string) =>
    apiClient.post('/auth/login', { username, password, totp_code: totpCode }),

  logout: (refreshToken: string) =>
    apiClient.post('/auth/logout', { refresh_token: refreshToken }),

  getMfaSetup: () =>
    apiClient.get('/auth/mfa/setup'),

  verifyMfa: (secretBase32: string, code: string) =>
    apiClient.post('/auth/mfa/verify', { secret_base32: secretBase32, code }),
}

// ── Fleet API functions ──────────────────────────────────────────────────────
export const fleetApi = {
  getStatus: () => apiClient.get<FleetStatus>('/status/fleet'),
}

// ── Hosts API functions ──────────────────────────────────────────────────────
export const hostsApi = {
  list: (params?: Record<string, unknown>) => apiClient.get('/hosts', { params }),
  get: (id: string) => apiClient.get(`/hosts/${id}`),
  delete: (id: string) => apiClient.delete(`/hosts/${id}`),
  refresh: (id: string) => apiClient.post(`/hosts/${id}/refresh`),
}

// ── Jobs API ─────────────────────────────────────────────────────────────────
export const jobsApi = {
  list: (params?: Record<string, unknown>) => apiClient.get('/jobs', { params }),
  get: (id: string) => apiClient.get(`/jobs/${id}`),
  create: (body: CreateJobRequest) => apiClient.post('/jobs', body),
  cancel: (id: string) => apiClient.post(`/jobs/${id}/cancel`),
  rollback: (id: string) => apiClient.post(`/jobs/${id}/rollback`),
}

// ── Patches API (per-host patch listing) ──────────────────────────────────────
export const patchesApi = {
  // Returns patches available on a specific host via the manager's proxy
  // The backend reads from host_patch_data table (cached from agent poll)
  getHostPatches: (hostId: string) => apiClient.get(`/hosts/${hostId}/patches`),
}
