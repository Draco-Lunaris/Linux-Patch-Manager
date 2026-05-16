# Linux Patch Manager REST API Reference

Base URL: `/api/v1/`
Content-Type: `application/json`
Security: JWT Bearer Token (except Public Endpoints)

## 1. Authentication & Session
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Authenticate user |
| POST | `/auth/logout` | Invalidate current session |
| POST | `/auth/refresh` | Refresh JWT token |
| GET | `/auth/mfa/setup` | Generate MFA setup QR/code |
| POST | `/auth/mfa/verify` | Verify MFA code |
| DELETE | `/auth/mfa` | Disable MFA for user |

## 2. Public Endpoints (Self-Enrollment)
*No authentication required.*
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/enroll` | Submit host enrollment request |
| GET | `/enroll/status/{token}` | Poll enrollment approval status & retrieve PKI |

## 3. Administration (Enrollment Queue)
*Requires Admin role.*
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/enrollments` | List pending enrollment requests |
| POST | `/admin/enrollments/{id}/approve` | Approve request, generate PKI, migrate to hosts |
| DELETE | `/admin/enrollments/{id}/deny` | Deny and purge enrollment request |

## 4. Host Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/hosts` | List managed hosts |
| POST | `/hosts` | Register host manually |
| GET | `/hosts/{id}` | Get host details |
| DELETE | `/hosts/{id}` | Remove host |
| POST | `/hosts/{id}/refresh` | Trigger on-demand data refresh |
| DELETE | `/hosts/{id}/groups/{group_id}` | Remove host from group |

## 5. Certificate Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/root.crt` | Download Root CA certificate |
| GET | `/certificates` | List issued certificates (grouped by status/host) |
| DELETE | `/certificates/{cert_id}` | Revoke certificate |
| POST | `/certificates/{cert_id}/renew` | Renew certificate |
| POST | `/hosts/{host_id}/certificates` | Issue client certificate for host |
| POST | `/hosts/{host_id}/certificates/reissue` | Reissue host certificates |
| GET | `/hosts/{host_id}/client.crt` | Download client certificate |

## 6. Discovery & Network Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/discovery/cidr` | Start CIDR network scan |
| GET | `/discovery/{scan_id}` | Get scan results |
| POST | `/discovery/{id}/register` | Register discovered host |

## 7. Jobs & Patch Deployment
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/jobs` | List patch jobs |
| POST | `/jobs` | Create new patch job |
| GET | `/jobs/{id}` | Get job status/details |
| POST | `/jobs/{id}/cancel` | Cancel running job |
| POST | `/jobs/{id}/rollback` | Rollback completed job |

## 8. Maintenance Windows
*Scoped to host.*
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/hosts/{host_id}/maintenance-windows` | List windows for host |
| POST | `/hosts/{host_id}/maintenance-windows` | Create window |
| PUT | `/hosts/{host_id}/maintenance-windows/{win_id}` | Update window |
| DELETE | `/hosts/{host_id}/maintenance-windows/{win_id}` | Delete window |

## 9. Health Checks
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health-checks` | List health checks |
| POST | `/health-checks` | Create health check |
| POST | `/health-checks/{check_id}/test` | Run manual health check |

## 10. Users & Groups
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | List users |
| POST | `/users` | Create user |
| GET | `/users/{id}` | Get user details |
| PUT | `/users/{id}` | Update user |
| DELETE | `/users/{id}` | Delete user |
| PUT | `/users/{id}/password` | Admin reset password |
| POST | `/users/{id}/revoke` | Revoke all user sessions |
| DELETE | `/users/{id}/mfa` | Admin disable MFA |
| GET | `/users/me` | Get current authenticated user |
| PUT | `/users/me/password` | Change own password |
| GET | `/groups` | List groups |
| POST | `/groups` | Create group |

## 11. Settings & Configuration
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/settings` | Get system settings |
| PUT | `/settings` | Update system settings |
| POST | `/settings/smtp/test` | Test SMTP configuration |
| POST | `/settings/sso/discover` | Discover OIDC provider config |
| POST | `/settings/sso/test` | Test SSO connection |
| POST | `/settings/azure-sso/test` | Test Azure SSO compatibility |
| POST | `/settings/audit-integrity` | Verify audit log integrity |

## 12. Single Sign-On (SSO)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sso/config` | Get SSO configuration status |
| GET | `/sso/login` | Initiate SSO login flow |
| GET | `/sso/callback` | Handle SSO provider callback |

## 13. Reports & Status
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status/fleet` | Get fleet-wide status summary |
| GET | `/reports/compliance` | Generate compliance report |
| GET | `/reports/patch-history` | Generate patch history report |
| GET | `/reports/vulnerability` | Generate vulnerability exposure report |
| GET | `/reports/audit` | Generate audit trail report |

## 14. Real-Time Updates (WebSocket)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ws/ticket` | Request WebSocket auth ticket |
| GET | `/ws/jobs` | Upgrade to WebSocket for job streaming |
