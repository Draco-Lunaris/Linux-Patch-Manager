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
    /// Worker heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// WS relay HTTP polling fallback interval in seconds (default: 10)
    pub ws_relay_poll_interval_secs: u64,
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
}

impl AppConfig {
    /// Load configuration from a TOML file and environment variable overrides.
    ///
    /// Environment variables follow the pattern: `PATCH_MANAGER__SECTION__KEY`
    /// e.g. `PATCH_MANAGER__DATABASE__URL=postgres://...`
    pub fn load(config_path: &str) -> Result<Self, ConfigError> {
        let cfg = Config::builder()
            .add_source(File::with_name(config_path).required(false))
            .add_source(
                Environment::with_prefix("PATCH_MANAGER")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        cfg.try_deserialize()
    }
}

fn default_health_check_poll_interval() -> u64 {
    300
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
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            security: SecurityConfig {
                ip_whitelist: vec![],
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
            },
            rate_limit: RateLimitConfig::default(),
        }
    }
}
