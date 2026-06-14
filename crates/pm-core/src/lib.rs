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
pub use crypto::{
    decrypt, encrypt, load_or_create_key, CryptoError, KEY_PATH, SECRET_ENCRYPTION_KEY_PATH,
};
pub use error::{AppError, ErrorResponse};
pub use models::{
    AdminResetPasswordRequest, AuthProvider, ChangePasswordRequest, CreateGroupRequest,
    CreateHealthCheckRequest, CreateHostRequest, CreateOsPackageMapping, CreateUserRequest,
    DiscoveryCidrRequest, DiscoveryResult, Group, HealthCheck, HealthCheckResult,
    HealthCheckWithResult, Host, HostHealthStatus, HostSummary, OsPackageMapping,
    RegisterDiscoveredRequest, UpdateGroupRequest, UpdateHealthCheckRequest,
    UpdateOsPackageMapping, UpdateUserRequest, User, UserRole as DbUserRole,
};

// Re-export audit integrity types
pub use audit::{verify_integrity, IntegrityError, IntegrityResult};
