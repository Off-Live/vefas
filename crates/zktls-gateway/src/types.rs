//! Gateway types and data structures
//!
//! This module defines the core types used throughout the zkTLS gateway,
//! including API request/response structures, configuration types, and
//! platform-specific abstractions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use zktls_zkvm::{ZkTlsInput, ZkTlsProofClaim};

/// Supported zkVM platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    /// SP1 zkVM platform
    SP1,
    /// RISC0 zkVM platform
    RISC0,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::SP1 => write!(f, "sp1"),
            Platform::RISC0 => write!(f, "risc0"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sp1" => Ok(Platform::SP1),
            "risc0" => Ok(Platform::RISC0),
            _ => Err(format!("Unsupported platform: {}", s)),
        }
    }
}

/// API request for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    /// Target platform
    pub platform: Platform,
    /// Input data for proof generation
    pub input: ZkTlsInput,
    /// Optional timeout in milliseconds
    pub timeout_ms: Option<u64>,
}

/// API response for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResponse {
    /// Generated proof data
    pub proof: Vec<u8>,
    /// Proof metadata
    pub metadata: ProofMetadata,
    /// Request ID for tracking
    pub request_id: String,
}

/// API request for proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Target platform
    pub platform: Platform,
    /// Proof data to verify
    pub proof: Vec<u8>,
    /// Optional expected result
    pub expected: Option<ZkTlsProofClaim>,
}

/// API response for proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Verification result
    pub verified: bool,
    /// Extracted claim (if verification successful)
    pub claim: Option<ZkTlsProofClaim>,
    /// Request ID for tracking
    pub request_id: String,
}

/// Proof metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Platform used for proof generation
    pub platform: Platform,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Proof size in bytes
    pub size_bytes: usize,
    /// Generation time in milliseconds
    pub generation_time_ms: u64,
    /// Execution cycles (platform-specific)
    pub cycles: Option<u64>,
    /// Memory usage in bytes (platform-specific)
    pub memory_usage_bytes: Option<u64>,
}

/// Gateway status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStatus {
    /// Gateway version
    pub version: String,
    /// Available platforms
    pub available_platforms: Vec<Platform>,
    /// Default platform
    pub default_platform: Platform,
    /// Server uptime in seconds
    pub uptime_seconds: u64,
    /// Total proofs generated
    pub proofs_generated: u64,
    /// Total proofs verified
    pub proofs_verified: u64,
    /// Last proof generation timestamp
    pub last_proof_at: Option<DateTime<Utc>>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Individual platform health
    pub platforms: HashMap<String, HealthStatus>,
    /// Timestamp of health check
    pub timestamp: DateTime<Utc>,
}

/// Health status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but functional
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Gateway configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Platform configurations
    pub platforms: PlatformConfigs,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Security configuration
    pub security: SecurityConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// Default platform
    pub default_platform: Platform,
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
    /// Maximum request size in bytes
    pub max_request_size_bytes: usize,
}

/// Platform-specific configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfigs {
    /// SP1 platform configuration
    pub sp1: Option<PlatformConfig>,
    /// RISC0 platform configuration
    pub risc0: Option<PlatformConfig>,
}

/// Individual platform configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Platform-specific timeout in milliseconds
    pub timeout_ms: u64,
    /// Platform-specific memory limit in bytes
    pub memory_limit_bytes: Option<u64>,
    /// Platform-specific configuration options
    pub options: HashMap<String, String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Enable structured logging
    pub structured: bool,
    /// Log file path (optional)
    pub file: Option<String>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable CORS
    pub enable_cors: bool,
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// Enable request rate limiting
    pub enable_rate_limiting: bool,
    /// Rate limit requests per minute
    pub rate_limit_per_minute: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                default_platform: Platform::SP1,
                request_timeout_ms: 30000,
                max_request_size_bytes: 10 * 1024 * 1024, // 10MB
            },
            platforms: PlatformConfigs {
                sp1: Some(PlatformConfig {
                    timeout_ms: 30000,
                    memory_limit_bytes: Some(2 * 1024 * 1024), // 2MB
                    options: HashMap::new(),
                }),
                risc0: Some(PlatformConfig {
                    timeout_ms: 30000,
                    memory_limit_bytes: Some(1 * 1024 * 1024), // 1MB
                    options: HashMap::new(),
                }),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                structured: true,
                file: None,
            },
            security: SecurityConfig {
                enable_cors: true,
                allowed_origins: vec!["*".to_string()],
                enable_rate_limiting: true,
                rate_limit_per_minute: 100,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_parsing() {
        assert_eq!("sp1".parse::<Platform>().unwrap(), Platform::SP1);
        assert_eq!("risc0".parse::<Platform>().unwrap(), Platform::RISC0);
        assert!("invalid".parse::<Platform>().is_err());
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::SP1.to_string(), "sp1");
        assert_eq!(Platform::RISC0.to_string(), "risc0");
    }

    #[test]
    fn test_default_config() {
        let config = GatewayConfig::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.default_platform, Platform::SP1);
        assert!(config.platforms.sp1.is_some());
        assert!(config.platforms.risc0.is_some());
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }
}
