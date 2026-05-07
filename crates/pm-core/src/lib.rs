pub mod audit;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod logging;
pub mod models;
pub mod request_id;

// Re-export commonly used types
pub use config::AppConfig;
pub use crypto::{decrypt, encrypt, load_or_create_key, CryptoError, KEY_PATH};
pub use error::{AppError, ErrorResponse};
pub use models::{
    AuthProvider, CreateGroupRequest, CreateHealthCheckRequest, CreateHostRequest,
    ChangePasswordRequest, AdminResetPasswordRequest, CreateUserRequest,
    DiscoveryCidrRequest, DiscoveryResult, Group, HealthCheck,
    HealthCheckResult, HealthCheckWithResult, Host, HostHealthStatus, HostSummary,
    RegisterDiscoveredRequest, UpdateGroupRequest, UpdateHealthCheckRequest, UpdateUserRequest,
    User, UserRole as DbUserRole,
};

// Re-export audit integrity types
pub use audit::{verify_integrity, IntegrityError, IntegrityResult};
