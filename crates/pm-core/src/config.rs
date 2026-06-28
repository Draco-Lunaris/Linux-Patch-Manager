use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

/// Rate limiting configuration per route group.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Enrollment endpoint: requests per minute per IP (default: 5)
    #[serde(default = "default_enrollment_rpm")]
    pub enrollment_rpm: u32,
    /// Enrollment burst allowance (default: 3)
    #[serde(default = "default_enrollment_burst")]
    pub enrollment_burst: u32,
    /// Public auth endpoints: requests per minute per IP (default: 20)
    #[serde(default = "default_auth_rpm")]
    pub auth_rpm: u32,
    /// Auth burst allowance (default: 10)
    #[serde(default = "default_auth_burst")]
    pub auth_burst: u32,
    /// Authenticated API: requests per minute per IP (default: 120)
    #[serde(default = "default_api_rpm")]
    pub api_rpm: u32,
    /// API burst allowance (default: 30)
    #[serde(default = "default_api_burst")]
    pub api_burst: u32,
}

fn default_enrollment_rpm() -> u32 {
    5
}
fn default_enrollment_burst() -> u32 {
    3
}
fn default_auth_rpm() -> u32 {
    20
}
fn default_auth_burst() -> u32 {
    10
}
fn default_api_rpm() -> u32 {
    120
}
fn default_api_burst() -> u32 {
    30
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enrollment_rpm: default_enrollment_rpm(),
            enrollment_burst: default_enrollment_burst(),
            auth_rpm: default_auth_rpm(),
            auth_burst: default_auth_burst(),
            api_rpm: default_api_rpm(),
            api_burst: default_api_burst(),
        }
    }
}

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub worker: WorkerConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Manager-hosted package repository configuration for agent self-update.
    ///
    /// When present, the manager serves a GPG-signed package repo on port 80
    /// and distributes repo config to agents during enrollment.
    ///
    /// Added for issue #116 (self-update v2.0.0).
    #[serde(default)]
    pub repo: RepoServerConfig,
}

/// Configuration for the manager-hosted package repository.
///
/// Controls GPG-signed package repo serving on port 80 and repo config
/// distribution to agents during enrollment.
///
/// Added for issue #116 (self-update v2.0.0).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RepoServerConfig {
    /// Base directory for package repo files (default: /var/www/lpa-repo).
    /// Subdirectories: apt/, dnf/, apk/, pacman/.
    #[serde(default = "default_repo_dir")]
    pub dir: String,
    /// Path to the GPG public key file (ASCII-armored) for repo signing.
    #[serde(default = "default_gpg_key_path")]
    pub gpg_public_key_path: String,
    /// Base URL for the repo as seen by agents (e.g., http://lpm.moon-dragon.us).
    /// Used to generate distro-specific sources_config strings.
    #[serde(default = "default_repo_url_base")]
    pub url_base: String,
    /// HTTP port for the repo server (default: 80).
    #[serde(default = "default_repo_http_port")]
    pub http_port: u16,
}

fn default_repo_dir() -> String {
    "/var/www/lpa-repo".to_string()
}
fn default_gpg_key_path() -> String {
    "/var/www/lpa-repo/lpa-repo-public-key.asc".to_string()
}
fn default_repo_url_base() -> String {
    "http://lpm.moon-dragon.us".to_string()
}
fn default_repo_http_port() -> u16 {
    80
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Bind address for the web server
    pub host: String,
    /// HTTPS port
    pub port: u16,
    /// Path to static frontend assets
    pub static_dir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// Full PostgreSQL connection URL
    pub url: String,
    /// Maximum pool connections
    pub max_connections: u32,
    /// Minimum pool connections
    pub min_connections: u32,
    /// Connection acquire timeout in seconds
    pub acquire_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkerConfig {
    /// Health poll interval in seconds (default: 300 = 5 min)
    pub health_poll_interval_secs: u64,
    /// Patch data poll interval in seconds (default: 1800 = 30 min)
    pub patch_poll_interval_secs: u64,
    /// Health check poll interval in seconds (default: 300 = 5 min)
    #[serde(default = "default_health_check_poll_interval")]
    pub health_check_poll_interval_secs: u64,
    /// Maximum concurrent agent calls
    pub max_concurrent_agent_calls: usize,
    /// Worker heartbeat interval in seconds (default: 300 = 5 min)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// WS relay HTTP polling fallback interval in seconds (default: 10)
    pub ws_relay_poll_interval_secs: u64,
    /// Self-upgrade reconnect timeout in seconds (default: 600 = 10 min).
    /// How long to wait for an agent to come back online after a self-upgrade.
    #[serde(default = "default_self_upgrade_reconnect_timeout")]
    pub self_upgrade_reconnect_timeout_secs: u64,
    /// Self-upgrade reconnect poll interval in seconds (default: 10).
    /// How often to poll the agent during reconnect confirmation.
    #[serde(default = "default_self_upgrade_reconnect_poll_interval")]
    pub self_upgrade_reconnect_poll_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level filter: trace, debug, info, warn, error
    pub level: String,
    /// Output format: json or pretty
    pub format: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// IP whitelist (CIDR or individual IPs); empty = allow all (not recommended)
    pub ip_whitelist: Vec<String>,
    /// IP addresses (CIDR or single IP) of trusted reverse proxies. When the
    /// immediate TCP peer is in this list, `X-Forwarded-For` is honored;
    /// otherwise the socket peer IP is used for allowlist enforcement.
    /// Default: empty (do not trust `X-Forwarded-For`). See
    /// `tasks/ip-allowlist-spec.md` §4.3 for the operational guidance.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// JWT signing key path (Ed25519 PEM)
    pub jwt_signing_key_path: String,
    /// JWT verification key path (Ed25519 public PEM)
    pub jwt_verify_key_path: String,
    /// JWT access token TTL in seconds (default: 900 = 15 min)
    pub jwt_access_ttl_secs: u64,
    /// Agent mTLS client cert path
    pub agent_client_cert_path: String,
    /// Agent mTLS client key path
    pub agent_client_key_path: String,
    /// Internal CA cert path
    pub ca_cert_path: String,
    /// Internal CA key path
    pub ca_key_path: String,
    /// Web UI TLS cert path
    pub web_tls_cert_path: String,
    /// Web UI TLS key path
    pub web_tls_key_path: String,
    /// Frontend URL to redirect to after SSO callback (default: http://localhost:5173/auth/sso/callback)
    #[serde(default = "default_sso_callback_url")]
    pub sso_callback_url: String,
    /// Allowlist of browser `Origin` values permitted to open the
    /// `/api/v1/ws/jobs` WebSocket upgrade. Entries are exact
    /// `scheme://host[:port]` strings. If left empty in the TOML file, the
    /// server derives the default from `sso_callback_url` at load time
    /// (see [`derive_allowed_origins`]).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Derive a default `Origin` allowlist from a single SSO callback URL.
///
/// Parses `scheme://host[:port][/path]` and returns a single-element vector
/// containing `scheme://host[:port]` (with default ports normalized away —
/// e.g. `https://x:443` becomes `https://x`). Returns an empty vector if the
/// URL is unparseable; callers should log a warning in that case because the
/// WebSocket endpoint will reject all browser upgrades (fail-closed).
///
/// Exposed publicly so tests and the handler can share the same parser.
pub fn derive_allowed_origins(sso_callback_url: &str) -> Vec<String> {
    let s = sso_callback_url.trim().trim_end_matches('/');
    let (scheme, rest) = match s.split_once("://") {
        Some(parts) if !parts.0.is_empty() => parts,
        _ => return vec![],
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return vec![];
    }
    // Authority is everything up to the first `/`, `?`, or `#`.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return vec![];
    }
    // Split host:port. We treat the LAST `:` as the port separator. IPv6
    // literal hosts (e.g. `[::1]`) contain a `:` inside the brackets; we
    // explicitly do not support IPv6 in sso_callback_url and return empty
    // for those to be safe.
    let (host, port_str) = match authority.rsplit_once(':') {
        Some((h, _)) if h.contains(':') => return vec![],
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host = host.trim();
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains(':') {
        return vec![];
    }
    let default_port: Option<u16> = match scheme_lower.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    let port_num = match port_str {
        Some(p) => match p.parse::<u16>() {
            Ok(n) => Some(n),
            Err(_) => return vec![],
        },
        None => None,
    };
    let origin = match (port_num, default_port) {
        (Some(p), Some(d)) if p == d => format!("{}://{}", scheme_lower, host),
        (Some(p), _) => format!("{}://{}:{}", scheme_lower, host, p),
        (None, _) => format!("{}://{}", scheme_lower, host),
    };
    vec![origin]
}

impl AppConfig {
    /// Load configuration from a TOML file and environment variable overrides.
    ///
    /// Environment variables follow the pattern: `PATCH_MANAGER__SECTION__KEY`
    /// e.g. `PATCH_MANAGER__DATABASE__URL=postgres://...`
    ///
    /// After deserialization, if `security.allowed_origins` is empty, it is
    /// derived from `security.sso_callback_url`. A `tracing::warn!` is emitted
    /// when the resulting allowlist is empty (the WS endpoint will reject all
    /// browser upgrades in that case).
    pub fn load(config_path: &str) -> Result<Self, ConfigError> {
        let cfg = Config::builder()
            .add_source(File::with_name(config_path).required(false))
            .add_source(
                Environment::with_prefix("PATCH_MANAGER")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let mut config: Self = cfg.try_deserialize()?;
        if config.security.allowed_origins.is_empty() {
            config.security.allowed_origins =
                derive_allowed_origins(&config.security.sso_callback_url);
        }
        if config.security.allowed_origins.is_empty() {
            tracing::warn!(
                sso_callback_url = %config.security.sso_callback_url,
                "security.allowed_origins is empty and could not be derived \
                 from sso_callback_url; the WebSocket endpoint will reject all \
                 browser upgrades"
            );
        }
        Ok(config)
    }
}

fn default_health_check_poll_interval() -> u64 {
    300
}

fn default_heartbeat_interval() -> u64 {
    300
}
fn default_self_upgrade_reconnect_timeout() -> u64 {
    600
}
fn default_self_upgrade_reconnect_poll_interval() -> u64 {
    10
}

fn default_sso_callback_url() -> String {
    "http://localhost:5173/auth/sso/callback".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 443,
                static_dir: "/usr/share/patch-manager/frontend".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://patch_manager:changeme@localhost/patch_manager".to_string(),
                max_connections: 20,
                min_connections: 2,
                acquire_timeout_secs: 30,
            },
            worker: WorkerConfig {
                health_poll_interval_secs: 300,
                patch_poll_interval_secs: 1800,
                health_check_poll_interval_secs: 300,
                max_concurrent_agent_calls: 64,
                heartbeat_interval_secs: 30,
                ws_relay_poll_interval_secs: 10,
                self_upgrade_reconnect_timeout_secs: 600,
                self_upgrade_reconnect_poll_interval_secs: 10,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            security: SecurityConfig {
                ip_whitelist: vec![],
                trusted_proxies: vec![],
                jwt_signing_key_path: "/etc/patch-manager/jwt/signing.pem".to_string(),
                jwt_verify_key_path: "/etc/patch-manager/jwt/verify.pem".to_string(),
                jwt_access_ttl_secs: 900,
                agent_client_cert_path: "/etc/patch-manager/certs/client.crt".to_string(),
                agent_client_key_path: "/etc/patch-manager/certs/client.key".to_string(),
                ca_cert_path: "/etc/patch-manager/ca/ca.crt".to_string(),
                ca_key_path: "/etc/patch-manager/ca/ca.key".to_string(),
                web_tls_cert_path: "/etc/patch-manager/tls/web.crt".to_string(),
                web_tls_key_path: "/etc/patch-manager/tls/web.key".to_string(),
                sso_callback_url: default_sso_callback_url(),
                allowed_origins: derive_allowed_origins(&default_sso_callback_url()),
            },
            rate_limit: RateLimitConfig::default(),
            repo: RepoServerConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_strips_default_https_port() {
        assert_eq!(
            derive_allowed_origins("https://app.example.com:443/auth/sso/callback"),
            vec!["https://app.example.com".to_string()]
        );
    }

    #[test]
    fn derive_keeps_non_default_port() {
        assert_eq!(
            derive_allowed_origins("https://app.example.com:8443/auth/sso/callback"),
            vec!["https://app.example.com:8443".to_string()]
        );
    }

    #[test]
    fn derive_strips_default_http_port() {
        assert_eq!(
            derive_allowed_origins("http://localhost:80/x"),
            vec!["http://localhost".to_string()]
        );
    }

    #[test]
    fn derive_handles_trailing_slash() {
        assert_eq!(
            derive_allowed_origins("https://app.example.com/"),
            vec!["https://app.example.com".to_string()]
        );
    }

    #[test]
    fn derive_handles_no_path() {
        assert_eq!(
            derive_allowed_origins("https://app.example.com"),
            vec!["https://app.example.com".to_string()]
        );
    }

    #[test]
    fn derive_returns_empty_for_garbage() {
        assert!(derive_allowed_origins("not a url").is_empty());
        assert!(derive_allowed_origins("").is_empty());
        assert!(derive_allowed_origins("ftp://x").is_empty());
    }

    #[test]
    fn derive_lowercases_scheme() {
        assert_eq!(
            derive_allowed_origins("HTTPS://App.Example.com"),
            vec!["https://App.Example.com".to_string()]
        );
    }
}
