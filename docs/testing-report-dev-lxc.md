# Linux Patch Manager — Dev LXC Testing Report

**Date:** 2026-04-28  
**Environment:** LXC 131 (linux-patch-manager-dev) on MoonProx13  
**OS:** Ubuntu 24.04 LTS  
**IP:** 192.168.0.247  
**Snapshot:** `pre-install` (clean Ubuntu 24.04 + echo user + SSH key + sudo)

---

## Issues Found & Fixed

### BUG-1: setup.sh Missing PostgreSQL Schema GRANT Statements
**Severity:** Critical (service cannot start)  
**File:** `scripts/setup.sh`  
**Root Cause:** PostgreSQL 15+ removed automatic CREATE/USAGE grants on the `public` schema. The setup script created the database and user but never granted schema permissions.  
**Fix:** Added GRANT statements after database creation (lines 111-116):
```bash
# Grant schema permissions (PostgreSQL 15+ requires explicit grants)
sudo -u postgres psql -v ON_ERROR_STOP=1 -d ${DB_NAME} <<SQL
GRANT USAGE ON SCHEMA public TO ${DB_USER};
GRANT CREATE ON SCHEMA public TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL
```
**Also needed on existing databases:** Grants on all tables and sequences, plus default privileges.

---

### BUG-2: Axum Route Syntax — Old `:param` Instead of `{param}`
**Severity:** Critical (service panics on startup)  
**Files:** 7 route files + main.rs  
**Root Cause:** Axum 0.7+ changed path parameter syntax from `:param` to `{param}`. The codebase used the old syntax throughout, causing an immediate panic at router construction.  
**Files Fixed:**
- `crates/pm-web/src/routes/hosts.rs` — 4 routes
- `crates/pm-web/src/routes/discovery.rs` — 2 routes
- `crates/pm-web/src/routes/maintenance_windows.rs` — 1 route
- `crates/pm-web/src/routes/jobs.rs` — 3 routes
- `crates/pm-web/src/routes/ca.rs` — 4 routes
- `crates/pm-web/src/routes/users.rs` — 2 routes
- `crates/pm-web/src/routes/groups.rs` — 2 routes
- `crates/pm-web/src/main.rs` — 1 nest path

**Total:** 19 route path strings fixed

---

### BUG-3: DbUser Struct Uses String Instead of PostgreSQL Enum Types
**Severity:** Critical (login fails with internal error)  
**File:** `crates/pm-auth/src/session.rs`  
**Root Cause:** `DbUser` struct defined `role: String` and `auth_provider: String`, but the database columns are PostgreSQL custom enum types `user_role` and `auth_provider`. sqlx cannot decode the enum values as plain strings.  
**Fix:** Changed `DbUser` fields to use `UserRole` and `AuthProvider` enum types from `pm_core::models`, and added `.to_string()` conversions where the role is passed to JWT issuance and `SessionUser` construction.

---

### BUG-4: UserRole and AuthProvider Enums Missing Display Trait
**Severity:** Critical (build fails after BUG-3 fix)  
**File:** `crates/pm-core/src/models.rs`  
**Root Cause:** After fixing BUG-3, `user.role.to_string()` calls failed because `UserRole` and `AuthProvider` enums didn't implement `Display`.  
**Fix:** Added `impl std::fmt::Display` for both enums with lowercase string representations matching the PostgreSQL enum values.

---

### BUG-5: Seed Admin Password Hash is Placeholder
**Severity:** Critical (admin cannot log in)  
**File:** `migrations/002_seed_admin.sql`  
**Root Cause:** The seed migration contained `$argon2id$v=19$m=65536,t=3,p=1$placeholder$placeholder` — not a valid Argon2id hash.  
**Fix:** Generated a proper Argon2id hash of `ChangeMe123!` and replaced the placeholder in the migration file.

---

## Issues Found — NOT YET FIXED

### BUG-6: No TLS — Service Serves Plain HTTP on Port 443
**Severity:** Critical (security)  
**File:** `crates/pm-web/src/main.rs` (lines 117-118)  
**Root Cause:** `main.rs` uses `axum::serve(listener, app)` with a plain `TcpListener`. There is no TLS configuration — the service serves plain HTTP on port 443. The config references TLS cert paths but the code never uses them.  
**Impact:** All traffic (including JWT tokens, passwords) is transmitted unencrypted.  
**Fix Needed:** Add `rustls` or `tokio-rustls` TLS listener, or use a reverse proxy (haproxy/nginx) for TLS termination.

---

### BUG-7: Audit Chain Integrity Errors in Worker
**Severity:** High  
**File:** `crates/pm-worker/src/audit_verifier.rs`  
**Root Cause:** The audit_log seed data (from migration 005_audit_hardening.sql) inserts rows with `audit_integrity_verified` action and computed `prev_hash`/`row_hash` values. However, the hash chain is computed at INSERT time, but the actual row content differs from what the migration hardcoded. The worker's audit verifier re-computes the hashes and finds mismatches starting at row 3.  
**Impact:** Worker logs continuous integrity errors. Worker eventually stops.  
**Fix Needed:** Either: (a) remove the seed audit_integrity_verified rows from the migration, or (b) compute the hashes correctly in the migration, or (c) have the worker re-initialize the chain on first run.

---

### BUG-8: Watchdog Timeout — pm-web Doesn't Notify systemd
**Severity:** Medium  
**File:** `crates/pm-web/src/main.rs`  
**Root Cause:** The systemd service file has `WatchdogSec=120s` but pm-web never sends `sd_notify WATCHDOG=1` to systemd. After 2 minutes, systemd kills the process.  
**Impact:** Service restarts every ~2 minutes, causing brief outages.  
**Fix Needed:** Either: (a) add `sd_notify` heartbeat to pm-web, or (b) remove `WatchdogSec` from the systemd unit file.

---

### BUG-9: Worker Service Dies After Audit Errors
**Severity:** Medium  
**Root Cause:** Worker exits after encountering audit chain integrity errors. No graceful degradation or retry logic.  
**Fix Needed:** Worker should log errors but continue operating, or re-initialize the audit chain.

---

## Test Results Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Package install (deb) | ✅ Pass | Installs correctly, creates dirs/users |
| PostgreSQL setup | ✅ Pass | After GRANT fix |
| Database migrations | ✅ Pass | All 5 migrations run via sqlx |
| JWT key generation | ✅ Pass | Ed25519 keys generated |
| CA initialization | ✅ Pass | Root CA auto-generated |
| Web service startup | ✅ Pass | After route syntax + enum fixes |
| Health endpoint | ✅ Pass | `/status/health` returns healthy |
| Login API | ✅ Pass | After password hash + enum fixes |
| Hosts API | ✅ Pass | Returns empty list |
| Users API | ✅ Pass | Returns admin user |
| Groups API | ✅ Pass | Returns empty list |
| Frontend SPA | ✅ Pass | React app served correctly |
| TLS/HTTPS | ❌ Fail | Plain HTTP on port 443 |
| Worker service | ❌ Fail | Audit chain errors + exits |
| Watchdog | ❌ Fail | No sd_notify, killed every 2min |

## Default Credentials (Dev LXC)
- **Username:** admin  
- **Password:** ChangeMe123!
