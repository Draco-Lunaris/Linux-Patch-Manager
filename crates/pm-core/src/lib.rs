pub mod config;
pub mod db;
pub mod error;
pub mod logging;
pub mod models;
pub mod audit;
pub mod request_id;

// Re-export commonly used types
pub use error::{AppError, ErrorResponse};
pub use config::AppConfig;
pub use models::{
    Host, HostSummary, HostHealthStatus, CreateHostRequest,
    Group, CreateGroupRequest, UpdateGroupRequest,
    User, UserRole as DbUserRole, AuthProvider, CreateUserRequest, UpdateUserRequest,
    DiscoveryResult, DiscoveryCidrRequest, RegisterDiscoveredRequest,
};
