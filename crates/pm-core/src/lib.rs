pub mod audit;
pub mod config;
pub mod db;
pub mod error;
pub mod logging;
pub mod models;
pub mod request_id;

// Re-export commonly used types
pub use config::AppConfig;
pub use error::{AppError, ErrorResponse};
pub use models::{
    AuthProvider, CreateGroupRequest, CreateHostRequest, CreateUserRequest, DiscoveryCidrRequest,
    DiscoveryResult, Group, Host, HostHealthStatus, HostSummary, RegisterDiscoveredRequest,
    UpdateGroupRequest, UpdateUserRequest, User, UserRole as DbUserRole,
};

// Re-export audit integrity types
pub use audit::{verify_integrity, IntegrityError, IntegrityResult};
