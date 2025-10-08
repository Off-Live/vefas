//! # Guest Validation
//!
//! This module provides complete validation for guest programs in zktls.
//! It combines structure validation (BundleValidator) and cryptographic validation (CryptographicValidator).
//! Note: Zero-knowledge proof generation is handled by the zkVM host crates (vefas-sp1, vefas-risc0).

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{Result, VefasCoreError};
use vefas_types::VefasCanonicalBundle;
use super::bundle_validation::{BundleValidator, ValidationReport};
use super::cryptographic_validator::{CryptographicValidator, CryptographicValidationReport};
use vefas_types::crypto_provider::CryptoProvider;

/// Guest validation error types
#[derive(Debug, Clone, PartialEq)]
pub enum GuestValidationError {
    /// Structure validation failed
    StructureValidationFailed {
        /// Description of the structure validation failure
        message: String,
    },
    /// Cryptographic validation failed
    CryptographicValidationFailed {
        /// Description of the cryptographic validation failure
        message: String,
    },
    /// Missing required data for guest validation
    MissingGuestData {
        /// Description of missing data
        message: String,
    },
}

/// Guest validation report
#[derive(Debug, Clone)]
pub struct GuestValidationReport {
    /// Whether all guest validations passed
    pub is_valid: bool,
    /// List of guest validation errors
    pub errors: Vec<GuestValidationError>,
    /// List of guest validation warnings
    pub warnings: Vec<String>,
    /// Guest validation metadata
    pub metadata: GuestValidationMetadata,
}

/// Guest validation metadata
#[derive(Debug, Clone)]
pub struct GuestValidationMetadata {
    /// Structure validation metadata
    pub structure_metadata: crate::bundle_validation::ValidationMetadata,
    /// Cryptographic validation metadata
    pub crypto_metadata: crate::cryptographic_validator::CryptographicValidationMetadata,
    /// Total validation time in milliseconds
    pub validation_time_ms: u64,
}

/// Guest validator for complete zktls validation
pub struct GuestValidator<P: CryptoProvider> {
    bundle_validator: BundleValidator,
    crypto_validator: CryptographicValidator<P>,
    strict_mode: bool,
}

impl<P: CryptoProvider> GuestValidator<P> {
    /// Create a new guest validator
    pub fn new(crypto_provider: P) -> Self {
        Self {
            bundle_validator: BundleValidator::new(),
            crypto_validator: CryptographicValidator::new(crypto_provider),
            strict_mode: false,
        }
    }

    /// Create a validator in strict mode
    pub fn new_strict(crypto_provider: P) -> Self {
        Self {
            bundle_validator: BundleValidator::new_strict(),
            crypto_validator: CryptographicValidator::new_strict(crypto_provider),
            strict_mode: true,
        }
    }

    /// Perform complete guest validation
    pub fn validate_complete(&self, bundle: &VefasCanonicalBundle) -> Result<GuestValidationReport> {
        let start_time = std::time::Instant::now();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // 1. Structure validation
        let structure_report = self.bundle_validator.validate_bundle(bundle)?;
        if !structure_report.is_valid {
            errors.push(GuestValidationError::StructureValidationFailed {
                message: "Bundle structure validation failed".to_string(),
            });
        }

        // 2. Cryptographic validation
        let crypto_report = self.crypto_validator.validate_cryptographic(bundle)?;
        if !crypto_report.is_valid {
            errors.push(GuestValidationError::CryptographicValidationFailed {
                message: "Cryptographic validation failed".to_string(),
            });
        }

        let validation_time = start_time.elapsed().as_millis() as u64;

        Ok(GuestValidationReport {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            metadata: GuestValidationMetadata {
                structure_metadata: structure_report.metadata,
                crypto_metadata: crypto_report.metadata,
                validation_time_ms: validation_time,
            },
        })
    }

    /// Validate only structure (without cryptographic validation)
    pub fn validate_structure_only(&self, bundle: &VefasCanonicalBundle) -> Result<ValidationReport> {
        self.bundle_validator.validate_bundle(bundle)
    }

    /// Validate only cryptographic operations (without structure validation)
    pub fn validate_cryptographic_only(&self, bundle: &VefasCanonicalBundle) -> Result<CryptographicValidationReport> {
        self.crypto_validator.validate_cryptographic(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptographic_validator::MockCryptoProvider;

    #[test]
    fn test_guest_validator_creation() {
        let crypto_provider = MockCryptoProvider;
        let validator = GuestValidator::new(crypto_provider);
        assert!(!validator.strict_mode);
    }

    #[test]
    fn test_guest_validator_strict_mode() {
        let crypto_provider = MockCryptoProvider;
        let validator = GuestValidator::new_strict(crypto_provider);
        assert!(validator.strict_mode);
    }
}
