// Core TypeScript types — expanded per milestone

export type UserRole = 'admin' | 'operator'
export type AuthProvider = 'local' | 'azure_sso'
export type HostHealthStatus = 'pending' | 'healthy' | 'degraded' | 'unreachable'
export type JobStatus = 'queued' | 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled'
export type JobKind = 'patch_apply' | 'patch_remove' | 'reboot' | 'rollback'

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
  registered_at: string
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
  last_login_at?: string
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
