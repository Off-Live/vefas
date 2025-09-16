//! Platform configuration for different zkVM environments
//! 
//! This module provides platform-specific configurations and feature flags
//! to support both SP1 and RISC0 zkVM environments.

use serde::{Deserialize, Serialize};
use alloc::string::{String, ToString};

/// zkVM platform configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVmConfig {
    /// Platform type
    pub platform: ZkVmPlatform,
    /// Enable cryptographic precompiles
    pub enable_precompiles: bool,
    /// Maximum proof size
    pub max_proof_size: usize,
    /// Memory limit for zkVM execution
    pub memory_limit: usize,
    /// Cycle limit for zkVM execution
    pub cycle_limit: u64,
}

/// Supported zkVM platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkVmPlatform {
    /// Succinct's SP1 zkVM
    SP1,
    /// RiscZero zkVM
    RISC0,
}

/// Platform-specific cryptographic precompile configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoPrecompiles {
    /// SHA-256 precompile available
    pub sha256: bool,
    /// SHA-384 precompile available  
    pub sha384: bool,
    /// AES-GCM precompile available
    pub aes_gcm: bool,
    /// ECDSA secp256r1 precompile available
    pub ecdsa_secp256r1: bool,
    /// Ed25519 precompile available
    pub ed25519: bool,
    /// RSA precompile available
    pub rsa: bool,
    /// BigInt operations precompile available
    pub bigint: bool,
}

impl ZkVmConfig {
    /// Create default configuration for SP1
    #[cfg(feature = "sp1")]
    pub const fn sp1_default() -> Self {
        Self {
            platform: ZkVmPlatform::SP1,
            enable_precompiles: true,
            max_proof_size: 1024 * 1024, // 1MB
            memory_limit: 64 * 1024 * 1024, // 64MB
            cycle_limit: 100_000_000, // 100M cycles
        }
    }
    
    /// Create default configuration for RISC0
    #[cfg(feature = "risc0")]
    pub const fn risc0_default() -> Self {
        Self {
            platform: ZkVmPlatform::RISC0,
            enable_precompiles: true,
            max_proof_size: 2 * 1024 * 1024, // 2MB
            memory_limit: 128 * 1024 * 1024, // 128MB
            cycle_limit: 50_000_000, // 50M cycles
        }
    }
    
    /// Get available cryptographic precompiles for this platform
    pub const fn crypto_precompiles(&self) -> CryptoPrecompiles {
        match self.platform {
            ZkVmPlatform::SP1 => CryptoPrecompiles {
                sha256: true,
                sha384: true,
                aes_gcm: true,
                ecdsa_secp256r1: true,
                ed25519: true,
                rsa: true,
                bigint: true,
            },
            ZkVmPlatform::RISC0 => CryptoPrecompiles {
                sha256: true,
                sha384: false, // Currently not available in RISC0
                aes_gcm: false, // Currently not available in RISC0  
                ecdsa_secp256r1: true,
                ed25519: true,
                rsa: false, // Currently not available in RISC0
                bigint: false, // Currently not available in RISC0
            },
        }
    }
    
    /// Check if a specific cryptographic operation is supported
    pub const fn supports_crypto(&self, operation: CryptoOperationType) -> bool {
        let precompiles = self.crypto_precompiles();
        match operation {
            CryptoOperationType::Sha256 => precompiles.sha256,
            CryptoOperationType::Sha384 => precompiles.sha384,
            CryptoOperationType::AesGcm => precompiles.aes_gcm,
            CryptoOperationType::EcdsaSecp256r1 => precompiles.ecdsa_secp256r1,
            CryptoOperationType::Ed25519 => precompiles.ed25519,
            CryptoOperationType::Rsa => precompiles.rsa,
            CryptoOperationType::BigInt => precompiles.bigint,
        }
    }
}

/// Types of cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOperationType {
    Sha256,
    Sha384,
    AesGcm,
    EcdsaSecp256r1,
    Ed25519,
    Rsa,
    BigInt,
}

/// Configuration for HTTPS client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsClientConfig {
    /// Timeout for connection establishment (in seconds)
    pub connection_timeout_secs: u32,
    /// Timeout for request/response cycle (in seconds) 
    pub request_timeout_secs: u32,
    /// Maximum response size to accept (in bytes)
    pub max_response_size: usize,
    /// Whether to generate commitments for zkTLS proofs
    pub generate_commitments: bool,
    /// Maximum number of redirects to follow
    pub max_redirects: u32,
    /// User agent string
    pub user_agent: String,
}

impl Default for HttpsClientConfig {
    fn default() -> Self {
        Self {
            connection_timeout_secs: 30,
            request_timeout_secs: 60,
            max_response_size: 1024 * 1024, // 1MB
            generate_commitments: true,
            max_redirects: 5,
            user_agent: "zkTLS/1.0".to_string(),
        }
    }
}


impl Default for ZkVmConfig {
    fn default() -> Self {
        #[cfg(feature = "sp1")]
        {
            return Self::sp1_default();
        }
        
        #[cfg(all(feature = "risc0", not(feature = "sp1")))]
        {
            return Self::risc0_default();
        }
        
        #[cfg(not(any(feature = "sp1", feature = "risc0")))]
        {
            // Fallback for tests - should not be used in production
            Self {
                platform: ZkVmPlatform::SP1,
                enable_precompiles: false,
                max_proof_size: 1024 * 1024,
                memory_limit: 64 * 1024 * 1024,
                cycle_limit: 100_000_000,
            }
        }
    }
}

impl core::fmt::Display for ZkVmPlatform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZkVmPlatform::SP1 => write!(f, "SP1"),
            ZkVmPlatform::RISC0 => write!(f, "RISC0"),
        }
    }
}

/// Platform-specific constants
pub mod constants {
    /// Maximum circuit size for SP1
    #[cfg(feature = "sp1")]
    pub const SP1_MAX_CIRCUIT_SIZE: usize = 1 << 22; // 4M constraints
    
    /// Maximum memory for SP1 guest program
    #[cfg(feature = "sp1")]
    pub const SP1_MAX_MEMORY: usize = 64 * 1024 * 1024; // 64MB
    
    /// Maximum circuit size for RISC0
    #[cfg(feature = "risc0")]
    pub const RISC0_MAX_CIRCUIT_SIZE: usize = 1 << 20; // 1M cycles
    
    /// Maximum memory for RISC0 guest program
    #[cfg(feature = "risc0")]
    pub const RISC0_MAX_MEMORY: usize = 128 * 1024 * 1024; // 128MB
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_platform_configuration() {
        let config = ZkVmConfig::default();
        // When no features are enabled, precompiles are disabled by default
        // This is the fallback configuration for testing
        assert!(!config.enable_precompiles);
        assert!(config.max_proof_size > 0);
    }
    
    #[cfg(feature = "sp1")]
    #[test]
    fn test_sp1_precompiles() {
        let config = ZkVmConfig::sp1_default();
        assert_eq!(config.platform, ZkVmPlatform::SP1);
        assert!(config.supports_crypto(CryptoOperationType::Sha256));
        assert!(config.supports_crypto(CryptoOperationType::AesGcm));
    }
    
    #[cfg(feature = "risc0")]
    #[test]
    fn test_risc0_precompiles() {
        let config = ZkVmConfig::risc0_default();
        assert_eq!(config.platform, ZkVmPlatform::RISC0);
        assert!(config.supports_crypto(CryptoOperationType::Sha256));
        // AES-GCM not currently supported in RISC0
        assert!(!config.supports_crypto(CryptoOperationType::AesGcm));
    }
}