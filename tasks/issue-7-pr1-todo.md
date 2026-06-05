# PR 1: Manager-side CRL generation + endpoint + enrollment bundle

**Branch:** `feat/7-crl-manager-side`
**Target issue:** https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/7

## Pre-implementation

- [x] Read existing `pm-ca/src/ca.rs` to understand CA structure
- [x] Confirm rcgen 0.13 is the chosen library
- [x] Confirm sub-CA handling: extend `PkiBundle` with `ca_chain` field
- [x] Read design doc decisions table (concerns 1-12)

## Code changes

- [ ] **pm-ca/src/ca.rs**: Add `generate_crl(db: &PgPool) -> Result<String>` function
  - Query `certificates` for `status='revoked' AND not_after > NOW()`
  - Build CRL using rcgen 0.13 `CertificateRevocationList`
  - Sign with CA private key
  - Return PEM-encoded CRL

- [ ] **pm-core/src/models.rs**: Extend `PkiBundle` with `ca_chain: String` field
  - Concatenated PEM bundle of full chain (intermediate + root) for sub-CA mode
  - For root mode, contains just the root cert (same as ca_crt)

- [ ] **pm-web/src/routes/pki.rs** (NEW): `GET /api/v1/pki/crl.pem` route
  - Public endpoint (no auth, CRLs are self-authenticating)
  - `Cache-Control: max-age=3600`
  - Returns latest cached CRL (regenerated on schedule or on revoke)

- [ ] **pm-web/src/routes/enrollment.rs**: Include CRL in enrollment response
  - Fetch current CRL via `generate_crl()`
  - Add `crl_pem: String` to response

- [ ] **pm-web/src/main.rs**: Wire up background CRL regeneration task
  - Regenerate every 12 hours
  - Hook into `revoke_cert` to trigger immediate regeneration
  - Store latest CRL in shared state (ArcSwap or similar)

- [ ] **crates/pm-web/src/state.rs** (or similar): Shared state for cached CRL

## Tests

- [ ] **Unit tests** in `pm-ca/src/ca.rs`:
  - `generate_crl` produces valid X.509 CRL signed by test CA
  - Revoked serials appear in CRL
  - Non-revoked serials do not appear
  - Expired certs (not_after < now) are excluded
  - Empty table produces CRL with zero revoked entries

- [ ] **Property tests** (proptest):
  - Random revoked cert data: CRL is always parseable, signature always verifies
  - Single-byte mutations to CRL fail signature verification

- [ ] **Fuzz harness** (cargo-fuzz):
  - Target: `pm_ca::ca::generate_crl`
  - Target: `pm_ca::ca::parse_crl` (if we add parsing)

- [ ] **Integration tests** in `pm-web/tests/`:
  - `GET /pki/crl.pem` returns 200 + valid PEM + correct Cache-Control
  - Enrollment bundle includes CRL
  - Enrollment bundle includes `ca_chain` field

## Documentation

- [ ] **docs/security/revocation.md** (NEW): Revocation policy and operational behavior
- [ ] **docs/api/REST_API.md** (or equivalent): Document `GET /pki/crl.pem`
- [ ] **Inline doc comments** on new public functions/structs
- [ ] **CHANGELOG.md** entry for the release

## Pre-PR checklist

- [ ] `cargo build` clean
- [ ] `cargo test` all pass
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] CI on GitHub passes

## Out of scope for PR 1 (deferred to later PRs)

- Agent-side consumption (PR 2, in linux-patch-api repo)
- Health check schema additions (PR 3)
- Agent health response field (PR 4)
- Health aggregation logic (PR 5)
- E2E test harness (PR 6)
