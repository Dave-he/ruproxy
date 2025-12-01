pub mod common;
pub mod features;
pub mod core;
pub mod config;
pub mod protocols;
pub mod transport;

// Re-export commonly used types
pub use common::{CoreResult, CoreError, HasType, Runnable};
pub use core::Instance;
pub use features::Feature;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get version string
pub fn version() -> &'static str {
    VERSION
}

/// Initialize tracing
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}