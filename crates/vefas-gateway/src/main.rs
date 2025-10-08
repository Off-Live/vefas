//! VEFAS Gateway Server Binary
//!
//! Production-grade HTTP server providing zkTLS verification endpoints:
//! - POST /api/v1/requests: Execute TLS request and generate proof
//! - POST /api/v1/verify: Verify cryptographic proof authenticity
//! - GET /api/v1/health: Health check endpoint
//! - GET /: Service information

use std::env;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use vefas_gateway::{VefasGateway, VefasGatewayConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    init_logging();

    info!(
        "Starting VEFAS Gateway Server v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load configuration from environment variables
    let config = load_config();

    info!("Configuration loaded: bind_address={}", config.bind_address);
    info!(
        "Features: CORS={}, request_timeout={}s",
        config.enable_cors, config.request_timeout
    );

    // Create and start the gateway server
    match VefasGateway::new(config).await {
        Ok(gateway) => {
            info!("VEFAS Gateway initialized successfully");

            // Handle graceful shutdown
            let shutdown_signal = async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to install Ctrl+C handler");
                info!("Shutdown signal received, stopping server...");
            };

            // Run the server with graceful shutdown
            tokio::select! {
                result = gateway.serve() => {
                    if let Err(e) = result {
                        error!("Server error: {}", e);
                        std::process::exit(1);
                    }
                }
                _ = shutdown_signal => {
                    info!("VEFAS Gateway stopped gracefully");
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize VEFAS Gateway: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Initialize structured logging with configurable levels
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default log levels for different components
        "vefas_gateway=info,vefas_core=info,axum=info,tower=warn,hyper=warn".into()
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
fn load_config() -> VefasGatewayConfig {
    let mut config = VefasGatewayConfig::default();

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

    // Maximum request size
    if let Ok(size_str) = env::var("VEFAS_MAX_REQUEST_SIZE") {
        match size_str.parse::<usize>() {
            Ok(size) if size >= 1024 && size <= 100 * 1024 * 1024 => {
                // 1KB to 100MB
                config.max_request_size = size;
            }
            Ok(size) => {
                warn!(
                    "Invalid max request size '{}', using default {}MB",
                    size,
                    config.max_request_size / 1024 / 1024
                );
            }
            Err(e) => {
                warn!(
                    "Failed to parse VEFAS_MAX_REQUEST_SIZE '{}': {}",
                    size_str, e
                );
            }
        }
    }

    // CORS configuration
    if let Ok(cors_str) = env::var("VEFAS_ENABLE_CORS") {
        config.enable_cors = cors_str.eq_ignore_ascii_case("true") || cors_str == "1";
    }

    // Rate limiting
    if let Ok(rate_str) = env::var("VEFAS_RATE_LIMIT") {
        match rate_str.parse::<u64>() {
            Ok(rate) if rate >= 1 && rate <= 1000 => {
                config.rate_limit = rate;
            }
            Ok(rate) => {
                warn!(
                    "Invalid rate limit '{}', using default {}",
                    rate, config.rate_limit
                );
            }
            Err(e) => {
                warn!("Failed to parse VEFAS_RATE_LIMIT '{}': {}", rate_str, e);
            }
        }
    }

    // Log the final configuration
    info!("Server configuration:");
    info!("  Bind Address: {}", config.bind_address);
    info!("  Request Timeout: {}s", config.request_timeout);
    info!(
        "  Max Request Size: {}MB",
        config.max_request_size / 1024 / 1024
    );
    info!("  CORS Enabled: {}", config.enable_cors);
    info!("  Rate Limit: {} req/min", config.rate_limit);

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = VefasGatewayConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:3000");
        assert_eq!(config.request_timeout, 30);
        assert_eq!(config.max_request_size, 10 * 1024 * 1024);
        assert!(config.enable_cors);
        assert_eq!(config.rate_limit, 10);
    }

    #[test]
    fn test_config_from_env() {
        // Set environment variables
        env::set_var("VEFAS_BIND_ADDRESS", "127.0.0.1:8080");
        env::set_var("VEFAS_REQUEST_TIMEOUT", "60");
        env::set_var("VEFAS_MAX_REQUEST_SIZE", "20971520"); // 20MB
        env::set_var("VEFAS_ENABLE_CORS", "false");
        env::set_var("VEFAS_RATE_LIMIT", "20");

        let config = load_config();

        assert_eq!(config.bind_address, "127.0.0.1:8080");
        assert_eq!(config.request_timeout, 60);
        assert_eq!(config.max_request_size, 20 * 1024 * 1024);
        assert!(!config.enable_cors);
        assert_eq!(config.rate_limit, 20);

        // Clean up
        env::remove_var("VEFAS_BIND_ADDRESS");
        env::remove_var("VEFAS_REQUEST_TIMEOUT");
        env::remove_var("VEFAS_MAX_REQUEST_SIZE");
        env::remove_var("VEFAS_ENABLE_CORS");
        env::remove_var("VEFAS_RATE_LIMIT");
    }

    #[test]
    fn test_invalid_config_values() {
        // Test invalid timeout (too large)
        env::set_var("VEFAS_REQUEST_TIMEOUT", "400");
        let config = load_config();
        assert_eq!(config.request_timeout, 30); // Should use default

        // Test invalid request size (too large)
        env::set_var("VEFAS_MAX_REQUEST_SIZE", "200000000"); // 200MB
        let config = load_config();
        assert_eq!(config.max_request_size, 10 * 1024 * 1024); // Should use default

        // Clean up
        env::remove_var("VEFAS_REQUEST_TIMEOUT");
        env::remove_var("VEFAS_MAX_REQUEST_SIZE");
    }
}
