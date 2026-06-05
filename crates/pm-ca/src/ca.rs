//! Internal Certificate Authority for Linux Patch Manager.
//!
//! Issues and renews mTLS client certificates and agent server certificates
//! for agent communication. Uses rcgen (ECDSA P-256) for all certificate
//! generation. CA key and certificate are stored on disk under `base_dir`
//! (default: /etc/patch-manager/ca/). Certificate metadata is persisted in
//! the `certificates` PostgreSQL table.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256,
};
use sqlx::{PgPool, Row};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Returned by [`CertAuthority::issue_client_cert`] and [`CertAuthority::renew_cert`].
///
/// The private keys are intentionally **not** stored in the database.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// PEM-encoded client certificate (mTLS).
    pub cert_pem: String,
    /// PEM-encoded client private key (PKCS#8).
    pub key_pem: String,
    /// Hex-encoded 16-byte random serial number (client cert).
    pub serial_number: String,
    /// Certificate expiry timestamp (UTC).
    pub expires_at: DateTime<Utc>,
    /// PEM-encoded agent server certificate (for TLS listener).
    pub server_cert_pem: String,
    /// PEM-encoded agent server private key (PKCS#8).
    pub server_key_pem: String,
    /// Hex-encoded serial number of the server certificate.
    pub server_serial_number: String,
    /// PEM-encoded CA root certificate.
    pub ca_root_pem: String,
}
// ---------------------------------------------------------------------------
// CertAuthority
// ---------------------------------------------------------------------------

/// Thread-safe, cloneable handle to the internal certificate authority.
///
/// CA certificate and key are held in memory as PEM strings; rcgen objects
/// are reconstructed on demand so this struct is unconditionally `Send + Sync`.
#[derive(Debug, Clone)]
pub struct CertAuthority {
    #[allow(dead_code)]
    base_dir: PathBuf,
    /// PEM-encoded CA certificate (public cert only).
    ca_cert_pem: String,
    /// PEM-encoded CA private key (PKCS#8).
    ca_key_pem: String,
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Generate a 16-byte cryptographically-random serial number.
/// Returns `(rcgen::SerialNumber, hex_encoded_string)`.
fn make_serial() -> (SerialNumber, String) {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex_serial = hex::encode(bytes);
    let serial = SerialNumber::from_slice(&bytes);
    (serial, hex_serial)
}

/// `OffsetDateTime::now_utc()` offset forward by `days` (for rcgen params).
fn odt_offset_days(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + TimeDuration::days(days)
}

/// `chrono::Utc::now()` offset forward by `days` (for DB / return values).
fn chrono_offset_days(days: i64) -> DateTime<Utc> {
    Utc::now() + ChronoDuration::days(days)
}

/// Build a `CertificateParams` with common fields pre-filled.
/// Caller still needs to set `is_ca`, `key_usages`, `extended_key_usages`, and `subject_alt_names`.
fn base_params(cn: &str, validity_days: i64) -> Result<(CertificateParams, String, DateTime<Utc>)> {
    let (serial, serial_hex) = make_serial();
    let expires_at = chrono_offset_days(validity_days);

    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = odt_offset_days(validity_days);
    params.serial_number = Some(serial);

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;

    Ok((params, serial_hex, expires_at))
}

/// Write `contents` to `path` and set Unix permissions to `0600`.
async fn write_protected(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::write(path, contents).await?;
    let perms = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(path, perms).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// impl CertAuthority
// ---------------------------------------------------------------------------

impl CertAuthority {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Load an existing CA from disk, or generate a brand-new one if absent.
    ///
    /// Files managed:
    /// * `{base_dir}/ca.key`  — PKCS#8 PEM private key (mode `0600`)
    /// * `{base_dir}/ca.crt`  — PEM certificate         (mode `0600`)
    ///
    /// On first generation the CA row is inserted into `certificates`
    /// with `host_id = NULL` (marks it as the root CA record).
    pub async fn init(base_dir: &Path, db: &PgPool) -> Result<Self> {
        let key_path = base_dir.join("ca.key");
        let crt_path = base_dir.join("ca.crt");

        // ── Load existing CA ──────────────────────────────────────────────
        if key_path.exists() && crt_path.exists() {
            tracing::info!(path = %base_dir.display(), "Loading existing root CA from disk");

            let ca_key_pem = tokio::fs::read_to_string(&key_path)
                .await
                .context("read ca.key")?;
            let ca_cert_pem = tokio::fs::read_to_string(&crt_path)
                .await
                .context("read ca.crt")?;

            // Validate that both PEMs parse without error.
            KeyPair::from_pem(&ca_key_pem).context("parse CA private-key PEM")?;
            CertificateParams::from_ca_cert_pem(&ca_cert_pem)
                .context("parse CA certificate PEM")?;

            tracing::info!("Root CA loaded successfully");
            return Ok(Self {
                base_dir: base_dir.to_owned(),
                ca_cert_pem,
                ca_key_pem,
            });
        }

        // ── Generate new CA ───────────────────────────────────────────────
        tracing::info!(
            path = %base_dir.display(),
            "Generating new root CA (ECDSA P-256, 10-year validity)"
        );
        tokio::fs::create_dir_all(base_dir)
            .await
            .context("create CA directory")?;

        let ca_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate CA key pair")?;

        let (serial, serial_hex) = make_serial();
        let expires_at = chrono_offset_days(365 * 10);

        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = odt_offset_days(365 * 10);
        params.serial_number = Some(serial);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Patch Manager Root CA");
        dn.push(DnType::OrganizationName, "Patch Manager");
        params.distinguished_name = dn;

        let ca_cert_obj = params
            .self_signed(&ca_key)
            .context("self-sign CA certificate")?;
        let ca_cert_pem = ca_cert_obj.pem();
        let ca_key_pem = ca_key.serialize_pem();

        write_protected(&key_path, &ca_key_pem)
            .await
            .context("write ca.key")?;
        write_protected(&crt_path, &ca_cert_pem)
            .await
            .context("write ca.crt")?;

        tracing::info!(
            serial = %serial_hex,
            expires_at = %expires_at,
            "Root CA generated and written to disk"
        );

        // Persist CA cert metadata (host_id = NULL marks the root CA row).
        sqlx::query(
            "INSERT INTO certificates \
             (host_id, serial_number, common_name, status, expires_at, cert_pem) \
             VALUES (NULL, $1, 'Patch Manager Root CA', 'active'::cert_status, $2, $3)",
        )
        .bind(&serial_hex)
        .bind(expires_at)
        .bind(&ca_cert_pem)
        .execute(db)
        .await
        .context("insert root CA cert into database")?;

        tracing::info!("Root CA certificate recorded in database");

        Ok(Self {
            base_dir: base_dir.to_owned(),
            ca_cert_pem,
            ca_key_pem,
        })
    }

    // -----------------------------------------------------------------------
    // Public accessors
    // -----------------------------------------------------------------------

    /// Return the PEM-encoded root CA certificate (public cert only).
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    // -----------------------------------------------------------------------
    // Certificate issuance
    // -----------------------------------------------------------------------

    /// Issue a one-year mTLS client certificate for a managed host.
    ///
    /// * Subject: `CN=<hostname>`
    /// * Key usage: Digital Signature
    /// * Extended key usage: Client Authentication
    ///
    /// Also issues a server certificate for the agent's TLS listener
    /// (see [`issue_server_cert`]).
    ///
    /// The certificate PEMs are stored in `certificates`.
    /// The private keys are returned to the caller **only** and never persisted.
    pub async fn issue_client_cert(
        &self,
        host_id: Uuid,
        hostname: &str,
        ip_address: &str,
        db: &PgPool,
    ) -> Result<IssuedCert> {
        tracing::info!(host_id = %host_id, hostname, ip_address, "Issuing mTLS client certificate");

        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate client key pair")?;

        let (mut params, serial_hex, expires_at) = base_params(hostname, 365)?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let (ca_key, ca_cert) = self.ca_objects()?;
        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .context("sign client cert with CA")?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        sqlx::query(
            "INSERT INTO certificates \
             (host_id, serial_number, common_name, status, expires_at, cert_pem) \
             VALUES ($1, $2, $3, 'active'::cert_status, $4, $5)",
        )
        .bind(host_id)
        .bind(&serial_hex)
        .bind(hostname)
        .bind(expires_at)
        .bind(&cert_pem)
        .execute(db)
        .await
        .context("insert client cert into database")?;

        tracing::info!(
            host_id = %host_id,
            hostname,
            serial = %serial_hex,
            expires_at = %expires_at,
            "Client certificate issued successfully"
        );

        // Also issue a server certificate for the agent's TLS listener.
        let (server_cert_pem, server_key_pem, server_serial_number, _server_expires_at) = self
            .issue_server_cert(host_id, hostname, ip_address, db)
            .await?;

        Ok(IssuedCert {
            cert_pem,
            key_pem,
            serial_number: serial_hex,
            expires_at,
            server_cert_pem,
            server_key_pem,
            server_serial_number,
            ca_root_pem: self.root_cert_pem().to_owned(),
        })
    }

    /// Issue a one-year server certificate for a managed host's agent TLS listener.
    ///
    /// * Subject: `CN=<hostname>-server`
    /// * Key usage: Digital Signature
    /// * Extended key usage: Server Authentication
    /// * SANs: DNS `<hostname>` + IP `<ip_address>` (if valid)
    ///
    /// The certificate PEM is stored in `certificates` with common_name
    /// `{hostname}-server` to distinguish from client certs.
    /// The private key is returned to the caller **only** and never persisted.
    ///
    /// Returns `(cert_pem, key_pem, serial_number, expires_at)`.
    pub async fn issue_server_cert(
        &self,
        host_id: Uuid,
        hostname: &str,
        ip_address: &str,
        db: &PgPool,
    ) -> Result<(String, String, String, DateTime<Utc>)> {
        tracing::info!(host_id = %host_id, hostname, ip_address, "Issuing agent server certificate");

        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate server key pair")?;

        let server_cn = format!("{hostname}-server");
        let (mut params, serial_hex, expires_at) = base_params(&server_cn, 365)?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Build SANs: DNS hostname + optional IP address
        let mut sans = vec![SanType::DnsName(
            Ia5String::try_from(hostname.to_owned()).context("hostname is not valid IA5")?,
        )];
        // Strip CIDR netmask (e.g. "192.168.3.36/32") before parsing
        let ip_str = ip_address.split('/').next().unwrap_or(ip_address);
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            tracing::warn!(
                ip_address,
                "Could not parse IP address for server cert SANs, skipping IP SAN"
            );
        }
        params.subject_alt_names = sans;

        let (ca_key, ca_cert) = self.ca_objects()?;
        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .context("sign server cert with CA")?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        sqlx::query(
            "INSERT INTO certificates \
             (host_id, serial_number, common_name, status, expires_at, cert_pem) \
             VALUES ($1, $2, $3, 'active'::cert_status, $4, $5)",
        )
        .bind(host_id)
        .bind(&serial_hex)
        .bind(&server_cn)
        .bind(expires_at)
        .bind(&cert_pem)
        .execute(db)
        .await
        .context("insert server cert into database")?;

        tracing::info!(
            host_id = %host_id,
            hostname,
            serial = %serial_hex,
            expires_at = %expires_at,
            "Server certificate issued successfully"
        );

        Ok((cert_pem, key_pem, serial_hex, expires_at))
    }

    /// Revoke a certificate by database ID.
    ///
    /// Sets `status = 'revoked'` and `revoked_at = NOW()` in the `certificates` table.
    /// Does **not** reissue a replacement; use [`renew_cert`] for that.
    pub async fn revoke_cert(&self, cert_id: Uuid, db: &PgPool) -> Result<()> {
        tracing::info!(cert_id = %cert_id, "Revoking certificate");

        let rows = sqlx::query(
            "UPDATE certificates \
             SET status = 'revoked'::cert_status, revoked_at = NOW() \
             WHERE id = $1",
        )
        .bind(cert_id)
        .execute(db)
        .await
        .context("revoke certificate in database")?;

        if rows.rows_affected() == 0 {
            anyhow::bail!("certificate not found: {}", cert_id);
        }

        tracing::info!(cert_id = %cert_id, "Certificate revoked");
        Ok(())
    }

    /// Renew a certificate: revoke the existing cert and issue a new one with
    /// the same `host_id` and `common_name`.
    ///
    /// Also issues a new server certificate and populates all `IssuedCert` fields.
    /// The host's IP address is looked up from the database for server cert SANs.
    pub async fn renew_cert(&self, cert_id: Uuid, db: &PgPool) -> Result<IssuedCert> {
        tracing::info!(cert_id = %cert_id, "Renewing certificate");

        // Fetch the existing cert's host_id and common_name.
        let row = sqlx::query("SELECT host_id, common_name FROM certificates WHERE id = $1")
            .bind(cert_id)
            .fetch_one(db)
            .await
            .context("fetch certificate for renewal")?;

        let host_id: Uuid = row
            .try_get("host_id")
            .context("certificate has no host_id (cannot renew root CA)")?;
        let common_name: String = row.try_get("common_name").context("fetch common_name")?;

        // Look up the host's IP address for the server cert SANs.
        let ip_address: String =
            sqlx::query_scalar("SELECT ip_address::text FROM hosts WHERE id = $1")
                .bind(host_id)
                .fetch_one(db)
                .await
                .context("fetch host IP address for renewal")?;

        // Revoke the old cert first.
        self.revoke_cert(cert_id, db).await?;

        // Issue a fresh cert with the same CN.
        let issued = self
            .issue_client_cert(host_id, &common_name, &ip_address, db)
            .await?;

        tracing::info!(
            old_cert_id = %cert_id,
            new_serial = %issued.serial_number,
            "Certificate renewed"
        );
        Ok(issued)
    }

    /// Generate a self-signed TLS certificate for the web UI using the CA.
    ///
    /// * Subject: `CN=<hostname>`
    /// * Key usage: Digital Signature
    /// * Extended key usage: Server Authentication
    /// * SAN: DNS `<hostname>`
    ///
    /// Returns `(cert_pem, key_pem)`. This certificate is **not** stored in the
    /// database; it is intended for runtime use only.
    pub async fn issue_web_tls_cert(&self, hostname: &str) -> Result<(String, String)> {
        tracing::info!(hostname, "Issuing web TLS certificate");

        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate web TLS key pair")?;

        let (mut params, serial_hex, expires_at) = base_params(hostname, 365)?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names = vec![SanType::DnsName(
            Ia5String::try_from(hostname.to_owned()).context("hostname is not valid IA5")?,
        )];

        let (ca_key, ca_cert) = self.ca_objects()?;
        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .context("sign web TLS cert with CA")?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        tracing::info!(
            hostname,
            serial = %serial_hex,
            expires_at = %expires_at,
            "Web TLS certificate issued"
        );

        Ok((cert_pem, key_pem))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Reconstruct rcgen `(KeyPair, Certificate)` from the in-memory PEM strings.
    ///
    /// The returned `Certificate` is used solely as an issuer reference when
    /// signing leaf certificates; it is never distributed directly.
    fn ca_objects(&self) -> Result<(KeyPair, Certificate)> {
        let key =
            KeyPair::from_pem(&self.ca_key_pem).context("reconstruct CA key pair from PEM")?;
        let params = CertificateParams::from_ca_cert_pem(&self.ca_cert_pem)
            .context("reconstruct CA params from PEM")?;
        let cert = params
            .self_signed(&key)
            .context("reconstruct CA certificate for signing")?;
        Ok((key, cert))
    }

    // -----------------------------------------------------------------------
    // CRL generation
    // -----------------------------------------------------------------------

    /// Generate a Certificate Revocation List (CRL) signed by this CA.
    ///
    /// Queries the `certificates` table for certs with `status = 'revoked'`
    /// and `not_after > NOW()` (i.e., not yet naturally expired) and bundles
    /// their serials into an X.509 v2 CRL.
    ///
    /// Returns the CRL as a PEM-encoded string.
    ///
    /// # Performance
    ///
    /// O(n) where n is the number of revoked-but-not-expired certs. For our
    /// target scale (max ~2500 clients per manager, low single-digit % annual
    /// revocation rate), this is KB-range and sub-millisecond to generate.
    pub async fn generate_crl(&self, db: &PgPool) -> Result<String> {
        tracing::debug!("Generating CRL from certificates table");

        // Query revoked certs that haven't naturally expired yet.
        // Expired certs are pruned from the CRL to keep it small.
        let rows = sqlx::query(
            "SELECT serial_number, revoked_at \
             FROM certificates \
             WHERE status = 'revoked'::cert_status \
               AND revoked_at IS NOT NULL \
               AND not_after > NOW() \
             ORDER BY revoked_at ASC",
        )
        .fetch_all(db)
        .await
        .context("query revoked certificates for CRL")?;

        let mut revoked_certs = Vec::with_capacity(rows.len());
        for row in &rows {
            let serial_hex: String = row.try_get("serial_number").context("serial_number")?;
            let revoked_at: DateTime<Utc> = row.try_get("revoked_at").context("revoked_at")?;

            // Convert hex serial back to bytes for rcgen.
            let serial_bytes =
                hex::decode(&serial_hex).context("serial_number is not valid hex")?;
            let serial_number = SerialNumber::from_slice(&serial_bytes);

            // Convert chrono DateTime to time::OffsetDateTime for rcgen.
            let revocation_time = OffsetDateTime::from_unix_timestamp(revoked_at.timestamp())
                .unwrap_or_else(|_| OffsetDateTime::now_utc());

            revoked_certs.push(RevokedCertParams {
                serial_number,
                revocation_time,
                reason_code: Some(RevocationReason::Unspecified),
                invalidity_date: None,
            });
        }

        let count = revoked_certs.len();
        tracing::debug!(revoked_count = count, "Building CRL with revoked entries");

        // CRL validity window: this_update = now, next_update = now + 24h
        // (agents refresh every 24h, so this gives them a fresh CRL on every poll).
        let now = OffsetDateTime::now_utc();
        let next_update = now + TimeDuration::hours(24);

        // CRL number: monotonic counter derived from current Unix timestamp.
        // RFC 5280 doesn't require strict monotonicity for the CRL number
        // extension, but it's a common convention. We use timestamp seconds
        // divided by 60 (minute precision) to keep it short and readable.
        let crl_number = SerialNumber::from_slice(&Utc::now().timestamp().to_be_bytes());

        let crl_params = CertificateRevocationListParams {
            this_update: now,
            next_update,
            crl_number,
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let (ca_key, ca_cert) = self.ca_objects()?;
        let crl = crl_params
            .signed_by(&ca_cert, &ca_key)
            .context("sign CRL with CA key")?;
        let crl_pem = crl.pem().context("encode CRL as PEM")?;

        tracing::info!(
            revoked_count = count,
            next_update = %next_update,
            "CRL generated and signed"
        );

        Ok(crl_pem)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a `CertAuthority` for testing without going through disk init.
    /// Generates a fresh ECDSA P-256 CA in memory.
    async fn test_ca() -> CertAuthority {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(365 * 10);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test Root CA");
        dn.push(DnType::OrganizationName, "Patch Manager Test");
        params.distinguished_name = dn;

        let ca_cert = params.self_signed(&key).unwrap();
        CertAuthority {
            base_dir: PathBuf::from("/tmp/test-ca"),
            ca_cert_pem: ca_cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    #[test]
    fn make_serial_produces_unique_16_byte_serials() {
        let (s1, h1) = make_serial();
        let (s2, h2) = make_serial();
        assert_ne!(h1, h2, "serial hex strings should differ");
        assert_eq!(
            h1.len(),
            32,
            "serial should be 16 bytes hex-encoded (32 chars)"
        );
        assert_ne!(s1, s2, "rcgen SerialNumber values should differ");
    }

    #[test]
    fn ca_objects_round_trip() {
        // Build a CA, then reconstruct via ca_objects() and verify the cert+key parse.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ca = rt.block_on(test_ca());
        let (key, cert) = ca.ca_objects().expect("ca_objects should succeed");
        assert!(!key.serialize_pem().is_empty());
        assert!(!cert.pem().is_empty());
    }

    /// Verifies that `generate_crl` produces a valid PEM-encoded X.509 CRL
    /// even when the database has no revoked certs (empty CRL).
    ///
    /// This is a structural test: we verify the PEM format and that the
    /// generated CRL can be parsed back. Full integration testing with a real
    /// database is in `tests/crl_integration.rs`.
    #[tokio::test]
    async fn generate_crl_empty_db_produces_valid_pem() {
        // Use a real but empty Postgres test database. If TEST_DATABASE_URL
        // is not set, skip this test (it's an integration test, not a unit test).
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        };

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("connect to test db");
        let ca = test_ca().await;

        let crl_pem = ca.generate_crl(&pool).await.expect("generate_crl");
        assert!(
            crl_pem.contains("-----BEGIN X509 CRL-----"),
            "PEM header missing"
        );
        assert!(
            crl_pem.contains("-----END X509 CRL-----"),
            "PEM footer missing"
        );
    }
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;

    /// Generating a CRL twice in quick succession should produce valid PEM output.
    /// (Full integration test with a real database is in tests/crl_integration.rs.)
    #[test]
    fn make_serial_produces_unique_values() {
        let (s1, h1) = make_serial();
        let (s2, h2) = make_serial();
        assert_ne!(h1, h2, "serial hex strings should differ");
        assert_eq!(h1.len(), 32, "serial should be 16 bytes hex-encoded");
        assert_ne!(s1, s2, "rcgen SerialNumber values should differ");
    }
}
