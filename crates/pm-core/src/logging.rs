use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use crate::config::LoggingConfig;

/// Initialize the global tracing subscriber.
///
/// Format is controlled by `cfg.format`:
/// - `"json"` — machine-readable JSON (production default)
/// - anything else — human-readable pretty output (development)
///
/// Log level is controlled by `cfg.level` (e.g. `"info"`, `"debug"`).
/// The `RUST_LOG` environment variable overrides `cfg.level`.
pub fn init(cfg: &LoggingConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    match cfg.format.as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_current_span(true))
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().pretty())
                .init();
        }
    }

    tracing::info!(format = %cfg.format, level = %cfg.level, "Logging initialized");
}
