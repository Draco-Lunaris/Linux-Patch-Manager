use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

/// Top-level application configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub worker: WorkerConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
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
    /// Maximum concurrent agent calls
    pub max_concurrent_agent_calls: usize,
    /// Worker heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
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
                max_concurrent_agent_calls: 64,
                heartbeat_interval_secs: 30,
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
            },
        }
    }
}
