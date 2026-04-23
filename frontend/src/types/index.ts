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
