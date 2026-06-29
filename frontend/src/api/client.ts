import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '../store/authStore'
import type {
  FleetStatus,
  CreateHostRequest,
  CreateJobRequest,
  CreateMaintenanceWindowRequest,
  MaintenanceWindow,
  UpdateMaintenanceWindowRequest,
  Certificate,
  IssuedCert,
  HealthCheckWithResult,
  CreateHealthCheckRequest,
  UpdateHealthCheckRequest,
  HealthCheckListResponse,
  User,
  ChangePasswordRequest,
  AdminResetPasswordRequest,
  UpdateUserRequest,
  CreateUserRequest,
  AvailableVersion,
  TriggerUpgradeRequest,
  TriggerUpgradeResponse,
  OsPackageMapping,
} from '../types'

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
    else resolve(token!) // eslint-disable-line @typescript-eslint/no-non-null-assertion
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
      return Promise.reject(refreshError)
    } finally {
      isRefreshing = false
    }
  }
)

// ── Auth API functions ───────────────────────────────────────────────────────

export interface SsoConfigResponse {
  enabled: boolean
  display_name: string
  auth_url: string
}

export const ssoConfigApi = {
  /** Public endpoint — no JWT required. Returns minimal SSO config for the login page. */
  get: () => apiClient.get<SsoConfigResponse>('/auth/sso/config'),
}

export const authApi = {
  login: (username: string, password: string, totpCode?: string) =>
    apiClient.post('/auth/login', { username, password, totp_code: totpCode }),

  logout: (refreshToken: string) =>
    apiClient.post('/auth/logout', { refresh_token: refreshToken }),

  forceChangePassword: (username: string, currentPassword: string, newPassword: string) =>
    apiClient.post('/auth/force-change-password', { username, current_password: currentPassword, new_password: newPassword }),

  getMfaSetup: () =>
    apiClient.get('/auth/mfa/setup'),

  verifyMfa: (secretBase32: string, code: string) =>
    apiClient.post('/auth/mfa/verify', { secret_base32: secretBase32, code }),

  // WebAuthn MFA stubs
  webauthnAuthenticateStart: () =>
    apiClient.post('/auth/mfa/webauthn/authenticate/start'),

  webauthnAuthenticateComplete: (challengeKey: string, serializedAssertion: unknown) =>
    apiClient.post('/auth/mfa/webauthn/authenticate/complete', { challenge_key: challengeKey, serialized_assertion: serializedAssertion }),

  webauthnListCredentials: () =>
    apiClient.get('/auth/mfa/webauthn/credentials'),

  webauthnRegisterStart: (keyName?: string) =>
    apiClient.post('/auth/mfa/webauthn/register/start', { key_name: keyName }),

  webauthnRegisterComplete: (challengeKey: string, serializedCredential: unknown, keyName?: string) =>
    apiClient.post('/auth/mfa/webauthn/register/complete', { challenge_key: challengeKey, serialized_credential: serializedCredential, key_name: keyName }),

  webauthnDeleteCredential: (id: string) =>
    apiClient.delete(`/auth/mfa/webauthn/credentials/${id}`),
}

// ── Fleet API functions ──────────────────────────────────────────────────────
export const fleetApi = {
  getStatus: () => apiClient.get<FleetStatus>('/status/fleet'),
}

// ── Hosts API functions ──────────────────────────────────────────────────────
export const hostsApi = {
  list: (params?: Record<string, unknown>) => apiClient.get('/hosts', { params }),
  get: (id: string) => apiClient.get(`/hosts/${id}`),
  register: (body: CreateHostRequest) => apiClient.post('/hosts', body),
  update: (id: string, body: Record<string, string | undefined>) =>
    apiClient.put(`/hosts/${id}`, body),
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

// ── Maintenance Windows API ───────────────────────────────────────────────────
export const maintenanceWindowsApi = {
  /** Bulk: fetch ALL maintenance windows across every host in one request. */
  listAll: () =>
    apiClient.get<{ windows: MaintenanceWindow[] }>('/maintenance-windows'),
  /** Per-host: fetch windows for a single host. */
  list: (hostId: string) =>
    apiClient.get(`/hosts/${hostId}/maintenance-windows`),
  create: (hostId: string, body: CreateMaintenanceWindowRequest) =>
    apiClient.post(`/hosts/${hostId}/maintenance-windows`, body),
  update: (hostId: string, windowId: string, body: UpdateMaintenanceWindowRequest) =>
    apiClient.put(`/hosts/${hostId}/maintenance-windows/${windowId}`, body),
  remove: (hostId: string, windowId: string) =>
    apiClient.delete(`/hosts/${hostId}/maintenance-windows/${windowId}`),
}

// ── WebSocket API (M7) ────────────────────────────────────────────────────────
export const wsApi = {
  /** POST /api/v1/ws/ticket — obtain a single-use WS auth ticket (60 s expiry). */
  createTicket: (): Promise<{ ticket: string }> =>
    apiClient.post<{ ticket: string }>('/ws/ticket').then((r) => r.data),
}

// ── Certificates API (M8) ────────────────────────────────────────────────────
export const certsApi = {
  // List all certs, optional filters
  list: (params?: { host_id?: string; status?: string }) =>
    apiClient.get<Certificate[]>('/certificates', { params }),

  // Download root CA cert as blob
  downloadRootCa: () =>
    apiClient.get('/ca/root.crt', { responseType: 'blob' }),

  // Issue client cert for a host — returns IssuedCert (key_pem only shown once!)
  issue: (hostId: string, hostname: string) =>
    apiClient.post<IssuedCert>(`/hosts/${hostId}/certificates`, { hostname }),

  // Renew a cert
  renew: (certId: string) =>
    apiClient.post<IssuedCert>(`/certificates/${certId}/renew`),

  // Revoke a cert
  revoke: (certId: string) =>
    apiClient.delete(`/certificates/${certId}`),

  // Download host client cert as blob
  downloadClientCert: (hostId: string) =>
    apiClient.get(`/hosts/${hostId}/client.crt`, { responseType: 'blob' }),

  // Re-issue all certs for a host — revokes all active certs and issues a new one
  reissue: (hostId: string) =>
    apiClient.post<IssuedCert>(`/hosts/${hostId}/certificates/reissue`),
}

// ── Reports API (M9) ─────────────────────────────────────────────────────────
export type ReportType = 'compliance' | 'patch-history' | 'vulnerability' | 'audit'
export type ReportFormat = 'csv' | 'pdf'

export const reportsApi = {
  download: (
    reportType: ReportType,
    format: ReportFormat,
    params?: {
      from?: string        // ISO 8601
      to?: string          // ISO 8601
      group_id?: string    // UUID
    }
  ) =>
    apiClient.get(`/reports/${reportType}`, {
      params: { format, ...params },
      responseType: 'blob',
      timeout: 120_000,   // reports can take a while
    }),
}
// ── Settings API (M10) ────────────────────────────────────────────────────

/** @deprecated Use OidcConfigResponse instead */
export interface AzureSsoConfig {
  enabled: boolean
  tenant_id: string
  client_id: string
  redirect_uri: string
  scopes: string
}

export interface OidcConfigResponse {
  enabled: boolean
  provider_type: 'keycloak' | 'azure' | 'custom'
  display_name: string
  discovery_url: string
  client_id: string
  client_secret: string
  redirect_uri: string
  scopes: string
}

export interface OidcDiscoveryResult {
  success: boolean
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string | null
  message?: string
}

export interface SmtpConfig {
  enabled: boolean
  host: string
  port: number
  username: string
  from: string
  tls_mode: string
}

export interface PollingConfig {
  health_poll_interval_secs: number
  patch_poll_interval_secs: number
}

export interface NotificationConfig {
  email_enabled: boolean
  email_from: string
  recipients: string[]
}

export interface SettingsResponse {
  oidc: OidcConfigResponse
  smtp: SmtpConfig
  polling: PollingConfig
  ip_whitelist: string[]
  web_tls_strategy: string
  notification: NotificationConfig
  sso_callback_url?: string
}

export interface TestResult {
  success: boolean
  message: string
}

export interface AuditIntegrityResult {
  intact: boolean
  rows_checked: number
  errors: Array<{
    row_id: number
    expected_hash: string
    actual_hash: string
  }>
}

export const settingsApi = {
  get: () => apiClient.get<SettingsResponse>('/settings'),
  update: (data: Partial<SettingsResponse> & {
    oidc?: OidcConfigResponse & { client_secret?: string }
    smtp?: SmtpConfig & { password?: string }
    notification?: NotificationConfig
  }) => apiClient.put<SettingsResponse>('/settings', data),
  discoverOidc: (discoveryUrl: string) => apiClient.post<OidcDiscoveryResult>('/settings/sso/discover', { discovery_url: discoveryUrl }),
  testOidc: () => apiClient.post<TestResult>('/settings/sso/test'),
  /** @deprecated Use testOidc instead */
  testAzureSso: () => apiClient.post<TestResult>('/settings/sso/test'),
  testSmtp: () => apiClient.post<TestResult>('/settings/smtp/test'),
  getIpWhitelist: () => apiClient.get<{ entries: string[] }>('/settings/ip-whitelist'),
  updateIpWhitelist: (entries: string[]) => apiClient.put<{ entries: string[] }>('/settings/ip-whitelist', { entries }),
  auditIntegrity: () => apiClient.post<AuditIntegrityResult>('/settings/audit-integrity'),
}

// ── Health Checks API ─────────────────────────────────────────────────────────

export const healthChecksApi = {
  list: (hostId: string) =>
    apiClient.get<HealthCheckListResponse>(`/hosts/${hostId}/health-checks`),

  get: (hostId: string, checkId: string) =>
    apiClient.get<HealthCheckWithResult>(`/hosts/${hostId}/health-checks/${checkId}`),

  create: (hostId: string, body: CreateHealthCheckRequest) =>
    apiClient.post<HealthCheckWithResult>(`/hosts/${hostId}/health-checks`, body),

  update: (hostId: string, checkId: string, body: UpdateHealthCheckRequest) =>
    apiClient.put<HealthCheckWithResult>(`/hosts/${hostId}/health-checks/${checkId}`, body),

  delete: (hostId: string, checkId: string) =>
    apiClient.delete(`/hosts/${hostId}/health-checks/${checkId}`),

  test: (hostId: string, checkId: string) =>
    apiClient.post<HealthCheckWithResult>(`/hosts/${hostId}/health-checks/${checkId}/test`),
}

// ── Users API ──────────────────────────────────────────────────────────────
export const usersApi = {
  list: () => apiClient.get<User[]>('/users'),
  get: (id: string) => apiClient.get<User>(`/users/${id}`),
  getMe: () => apiClient.get<User>('/users/me'),
  create: (data: CreateUserRequest) => apiClient.post('/users', data),
  update: (id: string, data: UpdateUserRequest) => apiClient.put(`/users/${id}`, data),
  delete: (id: string) => apiClient.delete(`/users/${id}`),
  revokeSessions: (id: string) => apiClient.post(`/users/${id}/revoke`),
  changePassword: (data: ChangePasswordRequest) => apiClient.put('/users/me/password', data),
  adminResetPassword: (id: string, data: AdminResetPasswordRequest) => apiClient.put(`/users/${id}/password`, data),
  adminDisableMfa: (id: string) => apiClient.delete(`/users/${id}/mfa`),
  disableMfa: (password: string) => apiClient.delete('/auth/mfa', { data: { password } }),
}

// ── Enrollment API (Admin) ────────────────────────────────────────────────
export interface EnrollmentRequest {
  id: string
  machine_id: string
  fqdn: string
  ip_address: string
  os_details: Record<string, unknown>
  polling_token: string
  created_at: string
  expires_at: string
}

export const enrollmentApi = {
  listPending: (): Promise<EnrollmentRequest[]> =>
    apiClient.get<EnrollmentRequest[]>('/admin/enrollments').then(r => r.data),

  approve: (id: string): Promise<void> =>
    apiClient.post(`/admin/enrollments/${id}/approve`).then(() => {}),

  deny: (id: string): Promise<void> =>
    apiClient.delete(`/admin/enrollments/${id}/deny`).then(() => {}),
}

// ── Self-Upgrade API ────────────────────────────────────────────────────────
export const upgradesApi = {
  listAvailableVersions: () =>
    apiClient.get<AvailableVersion[]>('/upgrades/available-versions'),

  refreshVersions: () =>
    apiClient.post<AvailableVersion[]>('/upgrades/refresh-versions'),

  triggerUpgrade: (req: TriggerUpgradeRequest) =>
    apiClient.post<TriggerUpgradeResponse>('/upgrades/trigger', req),
}

// ── Repo Management API (M12) ───────────────────────────────────────────────
export const repoApi = {
  triggerSync: () =>
    apiClient.post('/admin/repo/sync'),

  getSyncStatus: () =>
    apiClient.get('/admin/repo/sync-status'),

  listPackages: () =>
    apiClient.get('/admin/repo/packages'),
}

// ── OS Package Mappings API ───────────────────────────────────────────────────
export const osPackageMappingsApi = {
  list: () =>
    apiClient.get<OsPackageMapping[]>('/settings/os-package-mappings'),

  create: (data: Omit<OsPackageMapping, 'id' | 'created_at' | 'updated_at' | 'is_default'>) =>
    apiClient.post<OsPackageMapping>('/settings/os-package-mappings', data),

  update: (id: string, data: Partial<OsPackageMapping>) =>
    apiClient.put<OsPackageMapping>(`/settings/os-package-mappings/${id}`, data),

  delete: (id: string) =>
    apiClient.delete(`/settings/os-package-mappings/${id}`),
}
