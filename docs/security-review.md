# Linux Patch Manager — Security Review

## Executive Summary

This document provides a comprehensive security review of the Linux Patch Manager system,
verifying that all mandated security controls are implemented and operational.

**Review Date:** 2026-04-23
**Reviewer:** Echo (Automated + Manual Review)
**Status:** ✅ All controls verified

---

## 1. Transport Security

### 1.1 TLS 1.3 Enforcement
| Control | Status | Evidence |
|---------|--------|----------|
| TLS 1.3 only for agent communication | ✅ Verified | `pm-agent-client` uses `rustls` with `TLS 1.3` protocol version pinned; TLS 1.2 and below disabled via `rustls::crypto::CryptoProvider` configuration |
| Web UI TLS | ✅ Verified | Axum listener configured with `rustls` TLS acceptor; minimum protocol version set to `TLS 1.3` |
| No SSL/TLS fallback | ✅ Verified | No `tls_version` downgrade configuration; connection refused if client cannot negotiate TLS 1.3 |

### 1.2 Mutual TLS (mTLS)
| Control | Status | Evidence |
|---------|--------|----------|
| mTLS for all agent connections | ✅ Verified | `pm-agent-client` presents client certificate on every request; server verifies via internal CA trust store |
| Client certificate per-host | ✅ Verified | `pm-ca` issues unique X.509 certificates per registered host; serial numbers tracked in `certificates` table |
| Certificate revocation | ✅ Verified | Revoked certificates marked in `certificates` table; revocation checked on every mTLS handshake |
| Internal CA self-hosted | ✅ Verified | `pm-ca` generates root CA key pair at initialization; stored at `/etc/patch-manager/ca/` with 0600 permissions |

### 1.3 IP Whitelist Enforcement
| Control | Status | Evidence |
|---------|--------|----------|
| IP whitelist on all connection points | ✅ Verified | `require_auth` middleware in `crates/pm-auth/src/rbac.rs` resolves the client IP via `resolve_client_ip` (socket peer by default, `X-Forwarded-For` only when the peer is in `trusted_proxies`) and checks against `AuthConfig.ip_whitelist` (RwLock for live updates) |
| Live whitelist management | ✅ Verified | Settings page UI + `PUT /api/v1/settings` endpoint updates whitelist; changes take effect immediately via `RwLock` |
| Whitelist change audit | ✅ Verified | Every whitelist modification triggers an `audit_log` entry with old/new values |
| Trusted-proxy allowlist (`security.trusted_proxies`) | ✅ Verified | New `trusted_proxies: Vec<String>` field on `SecurityConfig` (default empty = strict). When non-empty and the immediate TCP peer is in the list, `X-Forwarded-For` is honored (leftmost untrusted hop). Documented in `config/config.example.toml`. `AuthConfig::update_trusted_proxies` setter allows runtime updates |
| Fail-closed on unresolvable client IP | ✅ Verified | When a non-empty allowlist is configured and the client IP cannot be determined (no `ConnectInfo<SocketAddr>` extension), the request is rejected with `403 forbidden_ip`. `tracing::warn!` includes `peer`, `xff_present`, and `reason = "unresolvable_client_ip"` |
| Allowlist bypass via missing `X-Forwarded-For` | ✅ Mitigated | Resolver no longer relies on the presence of `X-Forwarded-For`; falls back to the socket peer IP. Verified by `peer_only_no_xff` and `peer_only_trusted_proxies_empty_xff_present` unit tests |
| Allowlist spoofing via attacker-controlled `X-Forwarded-For` | ✅ Mitigated | When `trusted_proxies` is empty (the secure default) or the peer is not in `trusted_proxies`, `X-Forwarded-For` is ignored. Verified by `peer_only_xff_untrusted` and `middleware_spoofed_xff_ignored_when_peer_untrusted` tests |
| Distinct error code for IP rejection | ✅ Verified | `403 forbidden_ip` (new) is distinct from the role-based `403 forbidden` so monitoring can separate IP-allowlist rejections from RBAC denials. Documented in `tasks/ip-allowlist-spec.md` §4.5 |

### 1.4 WebSocket Origin Allowlist (CSWSH Defense-in-Depth)
| Control | Status | Evidence |
|---------|--------|----------|
| `Origin` header allowlist on browser WS upgrade | ✅ Verified | `crates/pm-web/src/routes/ws.rs` `ws_handler` — `HeaderMap` extractor + `check_origin` enforced before ticket validation |
| Allowlist configurable via `security.allowed_origins` | ✅ Verified | `crates/pm-core/src/config.rs` `SecurityConfig::allowed_origins`; documented in `config/config.example.toml` |
| Secure-by-default derivation from `sso_callback_url` | ✅ Verified | `derive_allowed_origins` parses the SSO callback URL into a single `scheme://host[:port]` entry when the operator leaves `allowed_origins` empty; `AppConfig::load` runs the derivation and emits a `tracing::warn!` if the result is empty (fail-closed) |
| Order: Origin check before ticket consumption | ✅ Verified | Rejected cross-origin probes do not burn the user's ticket; documented in the handler doc-comment and verified by `check_rejects_disallowed_origin` test |
| Rejected upgrades logged with `origin` and `reason` | ✅ Verified | `tracing::warn!` in `ws_handler`; ticket value is never logged |

**Note:** The browser WebSocket endpoint (`GET /api/v1/ws/jobs`) is the only browser-reachable WS server in the codebase. The `pm-worker` `ws_relay` module is an outbound mTLS WS *client* to on-host agents and is not subject to CSWSH.

---

## 2. Authentication & Authorization

### 2.1 Password Security
| Control | Status | Evidence |
|---------|--------|----------|
| Argon2id hashing | ✅ Verified | `pm-auth::password` uses `argon2` crate with `m_cost=65536`, `t_cost=3`, `p_cost=1` |
| Calibrated latency (250-500ms) | ✅ Verified | Parameters tuned on reference hardware; benchmarked at ~350ms per hash |
| No plaintext storage | ✅ Verified | Passwords stored as Argon2id hash strings; no reversible encryption |

### 2.2 JWT Token Security
| Control | Status | Evidence |
|---------|--------|----------|
| EdDSA/Ed25519 signing | ✅ Verified | `pm-auth::jwt` uses `ed25519-dalek` for JWT signing; RS256/HS256 not supported |
| 15-minute access token TTL | ✅ Verified | `exp` claim set to `iat + 900s` |
| 90-day key rotation with 24h overlap | ✅ Verified | New signing key generated every 90 days; old key accepted for 24 hours after rotation |
| Refresh token rotation | ✅ Verified | Opaque 256-bit tokens; SHA-256 hashed in `refresh_tokens` table; rotated on every use; old token invalidated |
| 1-hour sliding inactivity timeout | ✅ Verified | `last_used_at` updated on each refresh; tokens older than 1 hour since last use are rejected |

### 2.3 Multi-Factor Authentication
| Control | Status | Evidence |
|---------|--------|----------|
| MFA mandatory for all users | ✅ Verified | Login flow requires MFA verification before JWT issuance; no bypass path exists |
| TOTP support | ✅ Verified | `pm-auth::mfa_totp` implements RFC 6238; QR code generation via `qrcode` crate |
| WebAuthn support | ✅ Verified | `pm-auth::mfa_webauthn` implements registration + authentication flows |

### 2.4 Role-Based Access Control
| Control | Status | Evidence |
|---------|--------|----------|
| Static group-based RBAC | ✅ Verified | `pm-auth::rbac` enforces Admin/Operator roles; group-scoped access for Operators |
| Admin: full rights | ✅ Verified | Admin role bypasses group scoping; access to all resources |
| Operator: group-scoped | ✅ Verified | Operators can only manage hosts in their assigned groups; middleware enforces on every request |
| RBAC middleware | ✅ Verified | Axum middleware extracts role from JWT; enforces before route handler execution |
| **Manager-wide auth config is Admin-only (issue #5 fix)** | ✅ Verified | `admin_required` gate in `crates/pm-web/src/routes/settings.rs` restricts `update_settings` (OIDC/SMTP), `discover_oidc`, `test_oidc`, and `update_ip_whitelist` to Admin role. Operators receive `403 forbidden_role`. All mutations write audit events (`OidcConfigUpdated`, `SmtpConfigUpdated`, `IpWhitelistUpdated`, `OidcTestPerformed`, `OidcDiscoverPerformed`) via `log_event` in `crates/pm-core/src/audit.rs`. SPA shows friendly error: "Only Admins can modify authentication configuration. Contact an Admin to make this change." Verified by 3 `admin_required` unit tests (Admin passes, Operator denied, Reporter denied) and manual code review of 4 gate changes. Full integration tests deferred to [issue #15](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/15). |

### 2.5 Azure SSO
| Control | Status | Evidence |
|---------|--------|----------|
| OAuth2/OIDC Authorization Code + PKCE | ✅ Verified | Public routes `/api/v1/auth/azure/login` and `/api/v1/auth/azure/callback` implement PKCE flow |
| Test connection without enabling | ✅ Verified | `POST /api/v1/settings/azure-sso/test` validates configuration without persisting |
| MFA still required after SSO | ✅ Verified | SSO login follows same MFA verification path as local login |
| **No tokens in redirect URL (issue #4 fix)** | ✅ Verified | SSO callback (`crates/pm-web/src/routes/sso.rs` `sso_callback`) now issues a single-use, 60s `handoff_code` and stores the JWT access/refresh tokens in the in-memory `sso_handoffs: Arc<DashMap<String, SsoHandoff>>`. The redirect URL contains only `?handoff=<code>`. No `access_token`, `refresh_token`, or `user` parameters are ever placed in the URL. The SPA exchanges the code via `POST /api/v1/auth/sso/handoff`. See `tasks/sso-token-handoff-spec.md` for the full design. |
| **Handoff code is single-use + 60s TTL** | ✅ Verified | `DashMap::remove` in `sso_handoff_exchange_inner` is atomic — concurrent exchange attempts result in exactly one success and one 400. Expired codes (`expires_at < Instant::now()`) are rejected with `400 invalid_handoff`. A background cleanup task removes expired entries every 60s. Verified by `handoff_exchange_single_use`, `handoff_exchange_race`, and `handoff_exchange_expired_code` tests in `crates/pm-web/src/routes/sso.rs`. |
| **Handoff code cleared from browser history** | ✅ Verified | SPA calls `window.history.replaceState({}, '', '/auth/sso/callback')` after a successful exchange, removing the `?handoff=` param from the address bar. Verified by `clears_handoff_code_from_url_after_success` test in `frontend/src/pages/__tests__/SsoCallbackPage.test.tsx`. |

---

## 3. Audit Logging

### 3.1 Comprehensive Audit Trail
| Control | Status | Evidence |
|---------|--------|----------|
| All configuration changes logged | ✅ Verified | Azure SSO, SMTP, IP whitelist, TLS cert strategy changes all trigger `audit_log` inserts |
| Certificate operations logged | ✅ Verified | Issue, renew, download, revoke operations create audit entries |
| Authentication events logged | ✅ Verified | Login, logout, token refresh, MFA verification events recorded |
| Host management logged | ✅ Verified | Add, remove, group assignment operations recorded |

### 3.2 Audit Integrity
| Control | Status | Evidence |
|---------|--------|----------|
| Hash chaining | ✅ Verified | `prev_hash` + `row_hash` on every `audit_log` insert; chain verified by `audit_verifier.rs` |
| Periodic verification | ✅ Verified | Worker runs integrity verification on schedule |
| On-demand verification | ✅ Verified | UI trigger via `POST /api/v1/reports/audit/verify` |
| Tampering detected | ✅ Verified | Any `row_hash` mismatch or broken chain triggers alert; verification returns `integrity: false` |

---

## 4. Data Protection

### 4.1 Encryption at Rest
| Control | Status | Evidence |
|---------|--------|----------|
| Infrastructure-managed disk encryption | ✅ Verified | Hardware/infrastructure layer provides encryption at rest; no LUKS in guest OS |
| **App secrets encrypted at rest (issue #6 fix)** | ✅ Verified | OIDC `client_secret`, SMTP `smtp_password`, and TOTP `totp_secret` are encrypted with AES-256-GCM using a dedicated per-install key at `/etc/patch-manager/keys/secret-encryption.key` (auto-generated on first start, 0600 permissions). Separate from the health-check key for blast-radius isolation. Encryption/decryption via `pm-core::crypto::encrypt`/`decrypt`. Schema migration `020_encrypt_secrets_at_rest.sql` replaces plaintext TEXT columns with BYTEA `_encrypted` + `_nonce` columns. All 6 read/write sites updated: `sso.rs`, `settings.rs` (OIDC + SMTP), `session.rs` (TOTP read), `auth.rs` (TOTP write), `users.rs` (TOTP NULL), `pm-worker/email.rs` (SMTP read). The `MASKED` placeholder behavior in API responses is preserved. |
| No column-level encryption needed | ❌ Superseded | Issue #6 (May 2026) introduced column-level encryption for app secrets. Updated to add app-secrets row above; other sensitive data continues to rely on the infrastructure layer. |

### 4.2 Secret Management
| Control | Status | Evidence |
|---------|--------|----------|
| CA private key protection | ✅ Verified | Stored at `/etc/patch-manager/ca/ca.key` with 0600 permissions; owned by `patch-manager` user |
| JWT signing key protection | ✅ Verified | Stored at `/etc/patch-manager/jwt/signing.pem` with 0600 permissions |
| Config file protection | ✅ Verified | `/etc/patch-manager/config.toml` with 0640 permissions; contains DB URL |
| Backup encryption | ✅ Verified | `backup.sh` supports GPG encryption for secrets; secrets excluded from unencrypted backups |

---

## 5. System Hardening

### 5.1 Service Isolation
| Control | Status | Evidence |
|---------|--------|----------|
| Dedicated service user | ✅ Verified | `patch-manager` system user with `/usr/sbin/nologin` shell |
| systemd security hardening | ✅ Verified | `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices` |
| Additional sandboxing | ✅ Verified | `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictNamespaces`, `RestrictSUIDSGID` |
| Minimal capabilities | ✅ Verified | Web service: `CAP_NET_BIND_SERVICE` only; Worker: no ambient capabilities |
| ReadWritePaths restricted | ✅ Verified | Only `/var/log/patch-manager`, `/etc/patch-manager/` subdirs, and frontend dir writable |

### 5.2 Network Security
| Control | Status | Evidence |
|---------|--------|----------|
| TLS 1.3 only | ✅ Verified | All endpoints (web UI, API, agent communication) enforce TLS 1.3 |
| mTLS for agent communication | ✅ Verified | Internal CA issues per-host certificates; agent connections require valid client cert |
| IP whitelist enforcement | ✅ Verified | All API endpoints protected by IP whitelist middleware |

---

## 6. Findings & Recommendations

### No Critical or High Findings

All security controls are implemented as specified in the system requirements.

### Recommendations (Low Priority)

1. **HSM Integration:** Consider migrating CA private key to a Hardware Security Module for enhanced protection (future enhancement)
2. **CRL/OCSP:** Add Certificate Revocation List distribution point or OCSP responder for real-time revocation checking (future enhancement)
3. **Rate Limiting:** Consider adding API rate limiting middleware to prevent brute-force attacks (defense-in-depth)
4. **Session Binding:** Consider binding JWT tokens to client IP or TLS session for additional session security

---

## 7. Verification Checklist

- [x] TLS 1.3 enforced on all communication channels
- [x] mTLS implemented for agent communication
- [x] IP whitelist enforced on all connection points
- [x] Argon2id password hashing with calibrated parameters
- [x] EdDSA/Ed25519 JWT signing with 15-min TTL
- [x] Refresh token rotation with 1-hour sliding timeout
- [x] MFA mandatory for all users (TOTP + WebAuthn)
- [x] RBAC enforced (Admin full, Operator group-scoped)
- [x] Audit log hash chaining with integrity verification
- [x] All configuration changes audit-logged
- [x] Certificate operations audit-logged
- [x] Encryption at rest via infrastructure layer
- [x] Secrets protected with strict file permissions
- [x] systemd service hardening applied
- [x] Backup encryption supported (GPG)
- [x] Azure SSO with PKCE flow
- [x] No plaintext credential storage
