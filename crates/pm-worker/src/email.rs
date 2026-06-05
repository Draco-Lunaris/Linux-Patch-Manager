//! Email notification module.
//!
//! Loads SMTP configuration from `system_config` and sends notification emails
//! for patch job events (completion, failure) and maintenance window reminders.
//! All emails are optional and disabled by default via `notification_email_enabled`.

use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use sqlx::PgPool;

use pm_core::audit::{log_event, AuditAction};

/// SMTP configuration loaded from `system_config`.
struct SmtpSettings {
    enabled: bool,
    host: String,
    port: u16,
    username: String,
    password: String,
    from: String,
    tls_mode: String,
}

/// Notification preferences loaded from `system_config`.
struct NotificationSettings {
    email_enabled: bool,
    email_from: String,
    recipients: Vec<String>,
}

/// Load SMTP settings from the `system_config` table.
///
/// Issue #6 fix: SMTP password is stored as two rows:
///   - `smtp_password_encrypted` (hex of AES-256-GCM ciphertext)
///   - `smtp_password_nonce` (hex of AES-256-GCM nonce)
async fn load_smtp_settings(pool: &PgPool) -> SmtpSettings {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM system_config WHERE key IN (
            'smtp_enabled', 'smtp_host', 'smtp_port', 'smtp_username',
            'smtp_password_encrypted', 'smtp_password_nonce',
            'smtp_from', 'smtp_tls_mode'
        )",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let get = |key: &str| -> String {
        rows.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    // Decrypt the SMTP password
    let enc_hex = get("smtp_password_encrypted");
    let nonce_hex = get("smtp_password_nonce");
    let password = if !enc_hex.is_empty() && !nonce_hex.is_empty() {
        match (
            hex_decode(&enc_hex),
            hex_decode(&nonce_hex),
            crate::secret_key::get(),
        ) {
            (Some(enc), Some(nonce), Ok(key)) => {
                pm_core::crypto::decrypt(&enc, &nonce, key).unwrap_or_default()
            },
            _ => String::new(),
        }
    } else {
        String::new()
    };

    SmtpSettings {
        enabled: get("smtp_enabled") == "true",
        host: get("smtp_host"),
        port: get("smtp_port").parse().unwrap_or(587),
        username: get("smtp_username"),
        password,
        from: get("smtp_from"),
        tls_mode: get("smtp_tls_mode"),
    }
}

/// Decode a hex string to bytes. Returns None on invalid input.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Load notification preferences from `system_config`.
async fn load_notification_settings(pool: &PgPool) -> NotificationSettings {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM system_config WHERE key IN (
            'notification_email_enabled', 'notification_email_from', 'notification_email_recipients'
        )",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let get = |key: &str| -> String {
        rows.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    let recipients: Vec<String> =
        serde_json::from_str(&get("notification_email_recipients")).unwrap_or_default();

    NotificationSettings {
        email_enabled: get("notification_email_enabled") == "true",
        email_from: get("notification_email_from"),
        recipients,
    }
}

/// Build an async SMTP transport from settings.
fn build_transport(settings: &SmtpSettings) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    match settings.tls_mode.as_str() {
        "tls" => {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)
                .map_err(|e| format!("TLS relay error: {}", e))?;
            builder = builder.port(settings.port);
            if !settings.username.is_empty() {
                builder = builder.credentials(Credentials::new(
                    settings.username.clone(),
                    settings.password.clone(),
                ));
            }
            Ok(builder.build())
        },
        "starttls" => {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)
                .map_err(|e| format!("STARTTLS relay error: {}", e))?;
            builder = builder.port(settings.port);
            if !settings.username.is_empty() {
                builder = builder.credentials(Credentials::new(
                    settings.username.clone(),
                    settings.password.clone(),
                ));
            }
            Ok(builder.build())
        },
        _ => {
            // "none" — plaintext / no TLS
            let mut builder =
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
                    .port(settings.port);
            if !settings.username.is_empty() {
                builder = builder.credentials(Credentials::new(
                    settings.username.clone(),
                    settings.password.clone(),
                ));
            }
            Ok(builder.build())
        },
    }
}

/// Send an email notification. Returns true if the email was sent successfully.
async fn send_email(pool: &PgPool, subject: &str, body: &str) -> bool {
    let smtp = match load_smtp_settings(pool).await {
        s if !s.enabled => {
            tracing::debug!("SMTP not enabled, skipping email notification");
            return false;
        },
        s => s,
    };

    let notif = load_notification_settings(pool).await;
    if !notif.email_enabled {
        tracing::debug!("Email notifications disabled, skipping");
        return false;
    }

    if notif.recipients.is_empty() {
        tracing::debug!("No email recipients configured, skipping notification");
        return false;
    }

    let from_addr = if notif.email_from.is_empty() {
        smtp.from.clone()
    } else {
        notif.email_from
    };

    let from_mailbox: Mailbox = match from_addr.parse() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "Invalid from address for email notification");
            return false;
        },
    };

    let mut builder = Message::builder()
        .from(from_mailbox.clone())
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);

    // Add all recipients
    for recipient in &notif.recipients {
        let mailbox: Mailbox = match recipient.parse() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(error = %e, recipient = %recipient, "Invalid recipient address");
                continue;
            },
        };
        builder = builder.to(mailbox);
    }

    let email = match builder.body(body.to_string()) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build email message");
            return false;
        },
    };

    let transport = match build_transport(&smtp) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build SMTP transport");
            return false;
        },
    };

    match transport.send(email).await {
        Ok(_) => {
            tracing::info!(subject, "Email notification sent successfully");
            true
        },
        Err(e) => {
            tracing::error!(error = %e, subject, "Failed to send email notification");
            false
        },
    }
}

/// Send a patch failure notification email for a specific host.
pub async fn send_patch_failure_email(
    pool: &PgPool,
    host_fqdn: &str,
    job_id: &str,
    error_message: &str,
) {
    let subject = format!("[Patch Manager] Patch Failed on {}", host_fqdn);
    let body = format!(
        "Patch operation failed on host: {host_fqdn}\n\
         Job ID: {job_id}\n\
         Error: {error_message}\n\
         \n\
         Please review the job details in the Patch Manager dashboard."
    );

    let sent = send_email(pool, &subject, &body).await;

    log_event(
        pool,
        AuditAction::EmailNotificationSent,
        None,
        None,
        Some("patch_job"),
        Some(job_id),
        serde_json::json!({
            "type": "patch_failure",
            "host_fqdn": host_fqdn,
            "sent": sent,
        }),
        None,
        None,
    )
    .await;
}

/// Send a job completion notification email.
pub async fn send_job_completion_email(
    pool: &PgPool,
    job_id: &str,
    host_count: i64,
    succeeded_count: i64,
    failed_count: i64,
) {
    let subject = format!("[Patch Manager] Job {} Completed", job_id);
    let body = format!(
        "Patch job completed: {job_id}\n\
         Total hosts: {host_count}\n\
         Succeeded: {succeeded_count}\n\
         Failed: {failed_count}\n\
         \n\
         Please review the job details in the Patch Manager dashboard."
    );

    let sent = send_email(pool, &subject, &body).await;

    log_event(
        pool,
        AuditAction::EmailNotificationSent,
        None,
        None,
        Some("patch_job"),
        Some(job_id),
        serde_json::json!({
            "type": "job_completion",
            "host_count": host_count,
            "succeeded_count": succeeded_count,
            "failed_count": failed_count,
            "sent": sent,
        }),
        None,
        None,
    )
    .await;
}

/// Send a maintenance window reminder email.
#[allow(dead_code)]
pub async fn send_maintenance_window_reminder_email(
    pool: &PgPool,
    host_fqdn: &str,
    window_label: &str,
    start_at: &str,
) {
    let subject = format!(
        "[Patch Manager] Upcoming Maintenance Window: {}",
        window_label
    );
    let body = format!(
        "Maintenance window reminder:\n\
         Host: {host_fqdn}\n\
         Window: {window_label}\n\
         Starts at: {start_at}\n\
         \n\
         Patch operations will begin at the scheduled time."
    );

    let sent = send_email(pool, &subject, &body).await;

    log_event(
        pool,
        AuditAction::MaintenanceWindowReminder,
        None,
        None,
        Some("maintenance_window"),
        None,
        serde_json::json!({
            "type": "maintenance_reminder",
            "host_fqdn": host_fqdn,
            "window_label": window_label,
            "sent": sent,
        }),
        None,
        None,
    )
    .await;
}
