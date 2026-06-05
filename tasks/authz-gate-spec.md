# Authz Gate — Admin-Only Manager-Wide Configuration (Issue #5)

**Spec version:** v0.1.0
**Status:** Draft — awaiting Kelly sign-off
**Date:** 2026-06-03
**GitHub issue:** [#5](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/5)

---

## 1. Goal

Restrict mutations of Manager-wide authentication configuration to the **Admin** role only. Specifically:

- **OIDC provider config** (`discovery_url`, `client_id`, `client_secret`, `redirect_uri`, `scopes`)
- **SMTP config** (host, credentials, from address, recipients)
- **IP allowlist** (the in-memory `AuthConfig.ip_whitelist`)
- **OIDC discover / test handlers** (`discover_oidc`, `test_oidc`) — these probe the IdP and reveal config details

The **Operator** role is restricted to **per-host settings** for hosts in their scope (hosts with no group, or hosts in groups the operator is a member of). Operators MUST NOT be able to alter Manager-wide auth configuration. The **Reporter** role remains read-only across the board.

Audit-log every accepted change to the above with the acting user, action, and key. Return `403 forbidden_role` to Operators who attempt these mutations.

---

## 2. Non-Goals

- **Per-host group membership scoping** for Operators is **out of scope**. Today, Operator mutations are gated by `can_write()` (`Admin | Operator`); the per-host case relies on the route being "general write" and assumes Operators manage whatever hosts are assigned to them. A follow-up issue will add explicit per-host/group checks (e.g., `assert_operator_can_write_host(operator_id, host_id)`). For this issue, we only fix the Manager-wide auth-config leak.
- **Role changes in the SPA** (e.g., hiding OIDC fields entirely for Operators) are out of scope per Kelly's Q4 = A. We show a friendly error message instead.
- **Audit log changes** (new enum values, new columns) are out of scope. The existing `audit_log` table + `audit_action` enum + `pm-core::audit` module are sufficient. If we need a new audit action (e.g., `oidc_config_updated`), we add it as a migration in this PR.
- **Refactoring `write_access_required`** out of `settings.rs` is out of scope. We add a new `admin_required` helper alongside it.
- **Removing `can_write()`** entirely is out of scope. It's still correct for the per-host case (until the per-host scoping follow-up lands).

---

## 3. Design Decisions (Kelly sign-off)

| # | Question | Answer |
|---|----------|--------|
| **Q1** | Helper function vs inline check? | **A.** New `admin_required` helper in `settings.rs` (matches local `write_access_required` pattern, single point of change for the 403 error format). |
| **Q2** | Should `discover_oidc` / `test_oidc` be Admin-only? | **Yes — Admin-only.** Probing the IdP can leak the resolved `client_id`, scopes, and other details an Operator shouldn't see. The role model is: **Admin** can change Manager-wide config (OIDC, SMTP, IP allowlist) + everything else; **Operator** can only manage per-host settings for hosts in their scope; **Reporter** is read-only across the board. |
| **Q3** | Audit log destination? | **A.** Use the existing `audit_log` table via `pm-core::audit`. New `audit_action` enum values added via migration: `oidc_config_updated`, `smtp_config_updated`, `ip_whitelist_updated`, `oidc_test_performed`, `oidc_discover_performed`. |
| **Q4** | SPA UX for 403? | **A.** Friendly error message in `SettingsPage.tsx`: "Only Admins can modify authentication configuration. Contact an Admin to make this change." Matches the SPA's existing error-handling pattern. |

---

## 4. Design

### 4.1 New `admin_required` helper (settings.rs)

```rust
fn admin_required(auth: &AuthUser) -> Result<(), (StatusCode, Json<Value>)> {
    if !auth.role.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "code": "forbidden_role",
                    "message": "Admin role required to modify this resource"
                }
            })),
        ));
    }
    Ok(())
}
```

Placed in `crates/pm-web/src/routes/settings.rs` immediately after the existing `write_access_required` helper (~line 173). Uses a distinct error code (`forbidden_role` vs `forbidden`) so the SPA can differentiate "you don't have write access at all" from "you have write access but not for this specific resource".

### 4.2 Routes that change (4 in `settings.rs`)

| Handler | Current gate | New gate | Audit action |
|---------|--------------|----------|--------------|
| `update_settings` (line 336) | `write_access_required` | `admin_required` | `oidc_config_updated` and/or `smtp_config_updated` |
| `update_ip_whitelist` (line 902) | `write_access_required` | `admin_required` | `ip_whitelist_updated` |
| `discover_oidc` (line 561) | `write_access_required` | `admin_required` | `oidc_discover_performed` |
| `test_oidc` (line 619) | `write_access_required` | `admin_required` | `oidc_test_performed` |

**Non-changes:** The other 6+ handlers in `settings.rs` that use `write_access_required` for non-auth config (e.g., general `system_config` settings, health check settings, maintenance window settings) **stay as `write_access_required`**. The fix is targeted to the 4 auth-config handlers. The per-host settings endpoints in other route files (e.g., `host_groups.rs`, `hosts.rs`) are also unaffected — those are the per-host scope that Operators can keep accessing.

### 4.3 Audit log integration

Use the existing `crates/pm-core/src/audit.rs` module. New `audit_action` enum values are added via a migration (file `019_auth_config_audit_actions.sql`):

```sql
-- Migration: 019_auth_config_audit_actions
-- Description: Add audit_action enum values for auth-config mutations.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'oidc_config_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'smtp_config_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'ip_whitelist_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'oidc_test_performed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'oidc_discover_performed';
```

Each handler calls the audit log AFTER a successful mutation, with the acting user_id, the action, the config key(s) changed, and an optional hash of old/new values. The `pm-core::audit` module already provides the `write_audit_event()` function (see `audit.rs:179`). The integration looks like:

```rust
// In update_settings, after a successful OIDC config update:
crate::audit::write_audit_event(
    pool,
    auth.user_id,
    AuditAction::OidcConfigUpdated,
    Some(serde_json::json!({
        "keys_changed": ["oidc_discovery_url", "oidc_client_id"],
        "client_secret_changed": req.oidc.client_secret.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
    })),
).await?;
```

`write_audit_event` is async and uses the existing hash-chained `INSERT INTO audit_log` (audit.rs:179). Failures to write the audit log are logged via `tracing::error!` but DO NOT block the operation (the config change is already committed to `system_config` and possibly the in-memory `AuthConfig`). This matches the pattern used by the existing IP-whitelist path (line 956) and other audited handlers.

**Client secret handling:** If the request contains a new `client_secret`, log `client_secret_changed: true` (NOT the secret itself) so the audit trail records that a secret was rotated, but the secret value never touches the audit log.

### 4.4 SPA error message (SettingsPage.tsx)

The current `SettingsPage` likely shows the raw error message from the backend. Update the error handler to detect `error.code === 'forbidden_role'` and show a friendly message:

```tsx
} catch (err) {
  const error = err as AxiosError<{ error: { code: string; message: string } }>;
  const code = error.response?.data?.error?.code;
  if (code === 'forbidden_role') {
    setError('Only Admins can modify authentication configuration. Contact an Admin to make this change.');
  } else {
    setError(error.response?.data?.error?.message || 'Failed to save settings');
  }
}
```

The other 3 auth-config endpoints (OIDC, IP allowlist, test/discover) follow the same pattern. The change is localized to the 4 catch blocks in `SettingsPage` that correspond to these calls.

### 4.5 Test plan (unit + integration)

**Unit tests in `settings.rs` (cfg(test) module):**

1. `admin_required_admin_passes` — AuthUser with role Admin → returns Ok(())
2. `admin_required_operator_denied` — AuthUser with role Operator → returns Err with status 403 and code `forbidden_role`
3. `admin_required_reporter_denied` — AuthUser with role Reporter → returns Err with status 403 and code `forbidden_role`

**Integration tests for the 4 routes (using the existing test harness pattern from `sso_handoff_exchange_inner`):**

4. `update_settings_operator_denied` — POST as Operator with OIDC fields → 403 `forbidden_role`
5. `update_settings_admin_allowed` — POST as Admin with OIDC fields → 200 + audit row written
6. `update_ip_whitelist_operator_denied` — POST as Operator → 403 `forbidden_role`
7. `update_ip_whitelist_admin_allowed` — POST as Admin → 200 + audit row written + in-memory `AuthConfig.ip_whitelist` updated
8. `discover_oidc_operator_denied` — POST as Operator → 403 `forbidden_role`
9. `discover_oidc_admin_allowed` — POST as Admin → 200 + audit row written
10. `test_oidc_operator_denied` — POST as Operator → 403 `forbidden_role`
11. `test_oidc_admin_allowed` — POST as Admin → 200 + audit row written

**SPA test (Vitest, following the pattern from issue #4):**

12. `settings_page_forbidden_role_shows_friendly_message` — mock a 403 with code `forbidden_role` and assert the friendly message is shown

**Audit log assertion (in integration tests 5, 7, 9, 11):** Query `SELECT action, user_id, details FROM audit_log WHERE action = '<expected>'` and assert the row exists with the correct user_id and a non-null details JSONB.

### 4.6 Files changed

**Backend (5 files):**
- `crates/pm-web/src/routes/settings.rs` — new `admin_required` helper, 4 handler gate changes, 4 audit log calls, 11 tests
- `migrations/019_auth_config_audit_actions.sql` — new file, 5 enum values
- `crates/pm-core/src/audit.rs` (or wherever `AuditAction` is defined) — add 5 new enum variants
- `crates/pm-core/src/audit.rs` (or wherever `write_audit_event` is defined) — no API change, just verify the existing function supports the new action types
- `docs/security-review.md` — update §2.3 (Authorization / RBAC) with the new control row
- `docs/REST_API.md` — annotate the 4 affected endpoints with "Admin only"

**Frontend (1 file):**
- `frontend/src/pages/SettingsPage.tsx` — friendly error message in 4 catch blocks
- `frontend/src/pages/__tests__/SettingsPage.test.tsx` — new file, 1 test

---

## 5. Acceptance Criteria

- [ ] `PUT /api/v1/settings` with OIDC fields returns 403 `forbidden_role` for Operator and 200 for Admin.
- [ ] `PUT /api/v1/settings` with SMTP fields returns 403 `forbidden_role` for Operator and 200 for Admin.
- [ ] `PUT /api/v1/settings/ip-whitelist` returns 403 `forbidden_role` for Operator and 200 for Admin.
- [ ] `POST /api/v1/settings/oidc/discover` returns 403 `forbidden_role` for Operator and 200 for Admin.
- [ ] `POST /api/v1/settings/oidc/test` returns 403 `forbidden_role` for Operator and 200 for Admin.
- [ ] Each successful mutation writes a row to `audit_log` with the correct `audit_action`, the acting `user_id`, and a non-null `details` JSONB.
- [ ] Reporter is unaffected (still read-only).
- [ ] The SPA shows the friendly "Only Admins..." error message when it receives a 403 `forbidden_role`.
- [ ] `cargo fmt --check --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `npx eslint --max-warnings 0`, `npm test` all pass.

---

## 6. Risk Analysis

**Risk: SPA regression — friendly error message doesn't trigger in some cases.**
Mitigation: The new test (`settings_page_forbidden_role_shows_friendly_message`) mocks a 403 with `error.code === 'forbidden_role'` and asserts the message. If the backend returns a different code, the SPA falls through to the raw error path (preserving existing behavior). Worst case: Operators see a raw 403 message instead of the friendly one — same security outcome, slightly worse UX.

**Risk: Audit log failures block the operation.**
Mitigation: `write_audit_event` returns a `Result` but the handlers log+continue on error (same pattern as the existing IP-whitelist path at line 956). The config change is already committed to `system_config` and possibly the in-memory `AuthConfig` before the audit log call. A failed audit log write is a serious problem (loses accountability) but is recoverable from the database state.

**Risk: Operators lose legitimate workflows that relied on the old gate.**
Mitigation: The 4 affected routes are Manager-wide auth config. Operators do not have a legitimate need to change these (per Kelly's role model: "The operator role should only be able to manage per host settings for hosts that have no group or the operator is in they're group"). No legitimate Operator workflow breaks. The 6+ other `write_access_required` handlers in `settings.rs` (health check, maintenance window, etc.) are unchanged.

**Risk: Existing `write_access_required` callers still let Operators mutate non-auth config they shouldn't.**
Mitigation: This is acknowledged as out of scope. The non-auth settings that `write_access_required` still gates (e.g., health check settings, maintenance window settings) are arguably Manager-wide too, but the issue body only flags the 4 auth-config handlers. A follow-up issue will audit the other 6+ handlers and decide which are Manager-wide (Admin-only) vs per-host (Operator-allowed via group membership).

---

## 7. Documentation

- **docs/security-review.md** §2.3 (Authorization / RBAC): add 2 new rows:
  - "Manager-wide auth config (OIDC, SMTP, IP allowlist) is Admin-only" with evidence pointing to `admin_required` helper and 11 tests
  - "Audit log captures every auth-config mutation with the acting user" with evidence pointing to the 5 new `audit_action` enum values and the `write_audit_event` calls
- **docs/REST_API.md**: annotate the 4 affected endpoints with "🔒 Admin only" and link to the role model
- **tasks/lessons.md**: add a project-specific lesson about the role model (Admin = Manager-wide, Operator = per-host, Reporter = read-only) so future issues get it right

---

## 8. Follow-ups (out of scope for this PR)

1. **Per-host group membership scoping** for Operators — currently `can_write()` is a coarse "Admin or Operator" check. The follow-up adds explicit `assert_operator_can_write_host(operator_id, host_id)` that checks the host's group membership against the operator's group memberships. This is the proper fix for the "Operator can only manage per-host settings for hosts in their scope" requirement.
2. **Audit the other 6+ `write_access_required` handlers in `settings.rs`** to determine which are Manager-wide (Admin-only) vs per-host (Operator-allowed). Some likely candidates for Admin-only: system name, default timezone, default maintenance window. Some likely candidates for Operator-allowed: host label assignments, per-host health check targets, per-host maintenance window assignments.
3. **Hide auth-config fields in the SPA for Operators** — once the role model is settled, the SPA can conditionally render the OIDC/SMTP/IP allowlist sections only for Admins, instead of showing the fields and rejecting on save.
4. **Promote `admin_required` to `pm-auth`** as a shared helper alongside `Role::is_admin`, if the codebase grows more admin-only routes.

---

## 9. Sign-off

- [ ] Kelly approves spec (Q1=A, Q2=Admin-only, Q3=A, Q4=A confirmed)
- [ ] Echo implements Phase 1 (admin_required helper + 3 unit tests)
- [ ] Echo implements Phase 2 (4 handler gate changes + audit log calls)
- [ ] Echo implements Phase 3 (11 backend integration tests)
- [ ] Echo implements Phase 4 (SPA error message + 1 test)
- [ ] Echo implements Phase 5 (docs updates)
- [ ] Echo implements Phase 6 (review + commit + push + PR + comment on issue #5)
