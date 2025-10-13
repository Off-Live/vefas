//! VEFAS Node Server Binary
//!
//! Production-grade HTTP server providing zkTLS verification endpoints:
//! - POST /requests: Execute HTTP requests and generate ZK proofs
//! - POST /verify: Verify ZK proofs with selective disclosure
//! - GET /health: Health check endpoint
//! - GET /: Service information

use std::env;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use vefas_node::{VefasNode, VefasNodeConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    init_logging();

    info!(
        "Starting VEFAS Node Server v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load configuration from environment variables
    let config = load_config();

    info!("Configuration loaded: bind_address={}", config.bind_address);
    info!(
        "Features: CORS={}, request_timeout={}s",
        config.enable_cors, config.request_timeout
    );

    // Create and start the node server
    match VefasNode::new(config).await {
        Ok(node) => {
            info!("VEFAS Node initialized successfully");

            // Handle graceful shutdown
            let shutdown_signal = async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to install Ctrl+C handler");
                info!("Shutdown signal received, stopping server...");
            };

            // Run the server with graceful shutdown
            tokio::select! {
                result = node.serve() => {
                    if let Err(e) = result {
                        error!("Server error: {}", e);
                        std::process::exit(1);
                    }
                }
                _ = shutdown_signal => {
                    info!("VEFAS Node stopped gracefully");
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize VEFAS Node: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Initialize structured logging with configurable levels
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default log levels for different components
        "vefas_node=info,vefas_core=info,axum=info,tower=warn,hyper=warn".into()
    });

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(false)
        .with_line_number(false);

    // Check if we should use JSON formatting (useful for production)
    let result = if env::var("VEFAS_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer.json())
            .try_init()
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer.pretty())
            .try_init()
    };

    // Only log if initialization succeeded (avoid panic if already initialized)
    if result.is_ok() {
        info!("Logging initialized");
    }
}

/// Load configuration from environment variables
fn load_config() -> VefasNodeConfig {
    let mut config = VefasNodeConfig::default();

    // Server bind address
    if let Ok(addr) = env::var("VEFAS_BIND_ADDRESS") {
        config.bind_address = addr;
    }

    // Request timeout
    if let Ok(timeout_str) = env::var("VEFAS_REQUEST_TIMEOUT") {
        match timeout_str.parse::<u64>() {
            Ok(timeout) if timeout >= 1 && timeout <= 300 => {
                config.request_timeout = timeout;
            }
            Ok(timeout) => {
                warn!(
                    "Invalid request timeout '{}', using default {}s",
                    timeout, config.request_timeout
                );
            }
            Err(e) => {
                warn!(
                    "Failed to parse VEFAS_REQUEST_TIMEOUT '{}': {}",
                    timeout_str, e
                );
            }
        }
    }

    // CORS configuration
    if let Ok(cors_str) = env::var("VEFAS_ENABLE_CORS") {
        config.enable_cors = cors_str.eq_ignore_ascii_case("true") || cors_str == "1";
    }

    // RISC0 configuration
    if let Ok(risc0_str) = env::var("VEFAS_ENABLE_RISC0") {
        config.enable_risc0 = risc0_str.eq_ignore_ascii_case("true") || risc0_str == "1";
    }

    // SP1 configuration
    if let Ok(sp1_str) = env::var("VEFAS_ENABLE_SP1") {
        config.enable_sp1 = sp1_str.eq_ignore_ascii_case("true") || sp1_str == "1";
    }

    // Log the final configuration
    info!("Server configuration:");
    info!("  Bind Address: {}", config.bind_address);
    info!("  Request Timeout: {}s", config.request_timeout);
    info!("  CORS Enabled: {}", config.enable_cors);
    info!("  RISC0 Enabled: {}", config.enable_risc0);
    info!("  SP1 Enabled: {}", config.enable_sp1);

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = VefasNodeConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.request_timeout, 300);
        assert!(config.enable_cors);
        assert!(config.enable_risc0);
        assert!(config.enable_sp1);
    }

    #[test]
    fn test_config_from_env() {
        // Set environment variables
        env::set_var("VEFAS_BIND_ADDRESS", "127.0.0.1:8080");
        env::set_var("VEFAS_REQUEST_TIMEOUT", "60");
        env::set_var("VEFAS_ENABLE_CORS", "false");
        env::set_var("VEFAS_ENABLE_RISC0", "false");
        env::set_var("VEFAS_ENABLE_SP1", "false");

        let config = load_config();

        assert_eq!(config.bind_address, "127.0.0.1:8080");
        assert_eq!(config.request_timeout, 60);
        assert!(!config.enable_cors);
        assert!(!config.enable_risc0);
        assert!(!config.enable_sp1);

        // Clean up
        env::remove_var("VEFAS_BIND_ADDRESS");
        env::remove_var("VEFAS_REQUEST_TIMEOUT");
        env::remove_var("VEFAS_ENABLE_CORS");
        env::remove_var("VEFAS_ENABLE_RISC0");
        env::remove_var("VEFAS_ENABLE_SP1");
    }

    #[test]
    fn test_invalid_config_values() {
        // Test invalid timeout (too large)
        env::set_var("VEFAS_REQUEST_TIMEOUT", "400");
        let config = load_config();
        assert_eq!(config.request_timeout, 300); // Should use default

        // Clean up
        env::remove_var("VEFAS_REQUEST_TIMEOUT");
    }
}
