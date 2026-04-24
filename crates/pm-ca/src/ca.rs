//! Internal Certificate Authority for Linux Patch Manager.
//!
//! Issues and renews mTLS client certificates for agent communication.
//! Uses rcgen (ECDSA P-256) for all certificate generation.
//! CA key and certificate are stored on disk under `base_dir`
//! (default: /etc/patch-manager/ca/).
//! Certificate metadata is persisted in the `certificates` PostgreSQL table.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
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
/// The private key is intentionally **not** stored in the database.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// PEM-encoded public certificate.
    pub cert_pem: String,
    /// PEM-encoded private key (PKCS#8).
    pub key_pem: String,
    /// Hex-encoded 16-byte random serial number.
    pub serial_number: String,
    /// Certificate expiry timestamp (UTC).
    pub expires_at: DateTime<Utc>,
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
    /// The certificate PEM is stored in `certificates`.
    /// The private key is returned to the caller **only** and never persisted.
    pub async fn issue_client_cert(
        &self,
        host_id: Uuid,
        hostname: &str,
        db: &PgPool,
    ) -> Result<IssuedCert> {
        tracing::info!(host_id = %host_id, hostname, "Issuing mTLS client certificate");

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

        Ok(IssuedCert {
            cert_pem,
            key_pem,
            serial_number: serial_hex,
            expires_at,
        })
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

        // Revoke the old cert first.
        self.revoke_cert(cert_id, db).await?;

        // Issue a fresh cert with the same CN.
        let issued = self.issue_client_cert(host_id, &common_name, db).await?;

        tracing::info!(
            old_cert_id = %cert_id,
            new_serial   = %issued.serial_number,
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
}
