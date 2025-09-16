//! zkTLS Gateway - Unified API and CLI Layer
//!
//! This crate provides a unified interface for zkTLS verification through both
//! HTTP API endpoints and command-line interface. It serves as the single
//! entry point for all external interactions with the zkTLS system.
//!
//! ## Architecture
//!
//! The gateway follows a clean architecture pattern:
//! - **API Layer**: HTTP REST endpoints for programmatic access
//! - **CLI Layer**: Command-line interface for interactive usage
//! - **Service Layer**: Core business logic and platform abstraction
//! - **Config Layer**: Unified configuration management
//!
//! ## Features
//!
//! - **Multi-platform support**: SP1 and RISC0 zkVM backends
//! - **REST API**: HTTP/HTTPS endpoints for proof generation and verification
//! - **CLI Interface**: Command-line tool for interactive operations
//! - **Unified configuration**: Single config system for both interfaces
//! - **Production-ready**: Comprehensive logging, error handling, and monitoring
//!
//! ## Usage
//!
//! ### API Server
//! ```bash
//! zktls server --port 8080 --platform sp1
//! ```
//!
//! ### CLI Commands
//! ```bash
//! zktls prove --platform sp1 --input data.json
//! zktls verify --platform risc0 --proof proof.bin
//! ```

pub mod api;
pub mod cli;
pub mod config;
pub mod service;
pub mod types;
pub mod error;

// Re-export commonly used types
pub use types::*;
pub use error::*;
pub use service::ZkTlsGateway;

/// Gateway version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Gateway name
pub const NAME: &str = "zktls-gateway";

/// Default configuration file name
pub const DEFAULT_CONFIG_FILE: &str = "zktls.toml";

/// Default API port
pub const DEFAULT_PORT: u16 = 8080;

/// Default host address
pub const DEFAULT_HOST: &str = "0.0.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_constants() {
        assert!(!VERSION.is_empty());
        assert!(!NAME.is_empty());
        assert!(!DEFAULT_CONFIG_FILE.is_empty());
        assert!(DEFAULT_PORT > 0);
        assert!(!DEFAULT_HOST.is_empty());
    }
}
