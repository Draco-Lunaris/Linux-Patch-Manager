// Core TypeScript types — expanded per milestone

export type UserRole = 'admin' | 'operator' | 'reporter'
export type AuthProvider = 'local' | 'azure_sso' | 'keycloak' | 'oidc'
export type HostHealthStatus = 'pending' | 'healthy' | 'degraded' | 'unreachable'
export type JobStatus = 'queued' | 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled'
export type JobKind = 'patch_apply' | 'patch_remove' | 'reboot' | 'rollback' | 'self_upgrade'

export interface ApiError {
  error: {
    code: string
    message: string
    request_id?: string
    details?: unknown
  }
}

export interface Host {
  id: string
  fqdn: string
  ip_address: string
  display_name: string
  health_status: HostHealthStatus
  os_family?: string
  os_name?: string
  agent_version?: string
  patches_missing: number
  registered_at: string
  health_check_status?: 'all_healthy' | 'some_unhealthy' | 'none'
  crl_status?: 'valid' | 'expired' | 'missing' | 'invalid'
  crl_age_seconds?: number
  crl_next_update?: string
  gpg_key_status?: 'valid' | 'expired' | 'missing' | 'revoked'
  gpg_key_expires_at?: string
}

export interface CreateHostRequest {
  fqdn: string
  display_name?: string
  agent_port?: number
  notes?: string
  group_ids?: string[]
}

export interface UpdateHostRequest {
  fqdn?: string
  ip_address?: string
  display_name?: string
}

export interface Group {
  id: string
  name: string
  description: string
  created_at: string
}

export interface User {
  id: string
  username: string
  display_name: string
  email: string
  role: UserRole
  auth_provider: AuthProvider
  mfa_enabled: boolean
  is_active: boolean
  force_password_reset: boolean
  last_login_at?: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface AdminResetPasswordRequest {
  new_password: string
  force_password_reset?: boolean
}

export interface UpdateUserRequest {
  display_name?: string
  email?: string
  role?: string
  is_active?: boolean
  force_password_reset?: boolean
}

export interface CreateUserRequest {
  username: string
  display_name?: string
  email: string
  role: string
  password: string
}

export interface FleetStatus {
  total_hosts: number
  healthy: number
  degraded: number
  unreachable: number
  pending: number
  total_pending_patches: number
  hosts_requiring_reboot: number
  compliance_pct: number
  crl_valid: number
  crl_expired: number
  crl_missing: number
  crl_invalid: number
  crl_not_reporting: number
}

export interface PatchInfo {
  name: string
  current_version: string
  available_version: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  cve_ids: string[]
  requires_reboot: boolean
}

export interface PatchJobHost {
  id: string
  job_id: string
  host_id: string
  host_display_name: string
  status: JobStatus
  agent_job_id?: string
  retry_count: number
  output: string
  error_message?: string
  retry_next_at?: string
  started_at?: string
  completed_at?: string
}

export interface PatchJob {
  id: string
  kind: JobKind
  status: JobStatus
  immediate: boolean
  patch_selection: string[]
  notes: string
  created_at: string
  started_at?: string
  completed_at?: string
  hosts: PatchJobHost[]
}

export interface PatchJobSummary {
  id: string
  kind: JobKind
  status: JobStatus
  immediate: boolean
  host_count: number
  host_names: string[]
  succeeded_count: number
  failed_count: number
  notes: string
  created_at: string
  started_at?: string
  completed_at?: string
}

export interface CreateJobRequest {
  host_ids: string[]
  packages: string[]   // empty = all patches
  immediate: boolean
  maintenance_window_id?: string
  allow_reboot?: boolean
  notes?: string
}

// ── Maintenance Windows ───────────────────────────────────────────────────────

export type WindowRecurrence = 'once' | 'daily' | 'weekly' | 'monthly'

export interface MaintenanceWindow {
  id: string
  host_id: string
  label: string
  recurrence: WindowRecurrence
  /** Absolute start (once) or time-of-day reference (recurring) — ISO 8601 UTC */
  start_at: string
  /** Duration in minutes */
  duration_minutes: number
  /** 0-6 for weekly (0=Sun), 1-31 for monthly, null for once/daily */
  recurrence_day?: number | null
  enabled: boolean
  auto_apply: boolean
  created_at: string
  updated_at: string
}

export interface CreateMaintenanceWindowRequest {
  label: string
  recurrence: WindowRecurrence
  start_at: string
  duration_minutes?: number
  recurrence_day?: number | null
  enabled?: boolean
  auto_apply?: boolean
}

export interface UpdateMaintenanceWindowRequest {
  label?: string
  recurrence?: WindowRecurrence
  start_at?: string
  duration_minutes?: number
  recurrence_day?: number | null
  enabled?: boolean
  auto_apply?: boolean
}

// ── WebSocket event types (M7) ────────────────────────────────────────────────

export interface JobWsEvent {
  event_type?: 'host' | 'job'  // defaults to 'host' for backward compat
  job_id: string
  host_id: string
  status: JobStatus
  output?: string
  error_message?: string
  agent_job_id?: string
  // Job-level fields (only present when event_type === 'job')
  succeeded_count?: number
  failed_count?: number
  host_count?: number
}

// ── Certificates (M8) ────────────────────────────────────────────────────────

export type CertStatus = 'active' | 'revoked' | 'expired'

export interface Certificate {
  id: string
  host_id: string | null   // null = root CA cert
  serial_number: string
  common_name: string
  status: CertStatus
  issued_at: string
  expires_at: string
  revoked_at: string | null
  cert_pem: string
}

export interface IssuedCert {
  cert_pem: string
  key_pem: string
  serial_number: string
  expires_at: string
  server_cert_pem: string
  server_key_pem: string
  server_serial_number: string
  ca_root_pem: string
}

// ── Reports (M9) ─────────────────────────────────────────────────────────────
export type ReportType = 'compliance' | 'patch-history' | 'vulnerability' | 'audit'

// ── Settings (M10) ──────────────────────────────────────────────────────────

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

export type ReportFormat = 'csv' | 'pdf'

// ── Health Checks ────────────────────────────────────────────────────────────

export type HealthCheckType = 'service' | 'http'

export interface HealthCheck {
  id: string
  host_id: string
  name: string
  check_type: HealthCheckType
  enabled: boolean
  service_name?: string
  url?: string
  expected_body?: string
  ignore_cert_errors: boolean
  basic_auth_user?: string
  target_host_id?: string | null
  created_at: string
  updated_at: string
}

export interface HealthCheckResult {
  id: string
  check_id: string
  healthy: boolean
  detail?: string
  latency_ms?: number
  checked_at: string
}

export interface HealthCheckWithResult extends HealthCheck {
  last_result?: HealthCheckResult
}

export interface HealthCheckListResponse {
  checks: HealthCheckWithResult[]
  total: number
}

export interface CreateHealthCheckRequest {
  name: string
  check_type: HealthCheckType
  service_name?: string
  url?: string
  expected_body?: string
  ignore_cert_errors?: boolean
  basic_auth_user?: string
  basic_auth_pass?: string
  target_host_id?: string | null
}

export interface UpdateHealthCheckRequest {
  name?: string
  enabled?: boolean
  service_name?: string
  url?: string
  expected_body?: string
  ignore_cert_errors?: boolean
  basic_auth_user?: string
  basic_auth_pass?: string
  target_host_id?: string | null
}

// ── Enrollment (Self-Enrollment) ─────────────────────────────────────────
export interface EnrollmentRequest {
  id: string
  machine_id: string
  fqdn: string
  ip_address: string
  os_details: Record<string, unknown>
  polling_token: string    // hashed token stored in DB
  created_at: string
  expires_at: string
}

export interface EnrollmentConflictResponse {
  error: string
  conflict: {
    existing_host: Host
    message: string
  }
}

// ── Self-Upgrade (Agent Upgrade) ──────────────────────────────────────────

export interface AvailableVersion {
  id: string
  version: string
  download_url: string
  checksum: string | null
  file_name: string
  source: string
  prerelease: boolean
  published_at: string | null
  fetched_at: string
}

export interface OsPackageMapping {
  id: string
  os_name: string
  os_version: string
  package_pattern: string
  display_name: string
  is_default: boolean
  created_at: string
  updated_at: string
}

export interface TriggerUpgradeRequest {
  host_ids: string[]
  target_version: string | null
  immediate: boolean
  maintenance_window_id?: string | null
}

export interface SkippedHost {
  host_id: string
  reason: string
}

export interface TriggerUpgradeResponse {
  job_id: string
  host_count: number
  skipped: SkippedHost[]
}
