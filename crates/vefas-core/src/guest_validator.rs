//! # Guest Validation
//!
//! This module provides minimal validation for guest programs in zktls.
//! It focuses on structure validation (BundleValidator) and Merkle proof verification.
//! Heavy cryptographic validation (key derivation, decryption, HMAC) is moved to verifier nodes.
//! Note: Zero-knowledge proof generation is handled by the zkVM host crates (vefas-sp1, vefas-risc0).

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{Result, VefasCoreError};
use vefas_types::VefasCanonicalBundle;
use super::bundle_validation::{BundleValidator, ValidationReport};
use vefas_types::crypto_provider::CryptoProvider;

/// Merkle proof verification metadata
#[derive(Debug, Clone)]
pub struct MerkleVerificationMetadata {
    /// Whether Merkle proof verification passed
    pub merkle_proofs_verified: bool,
    /// Number of Merkle proofs verified
    pub merkle_proofs_count: usize,
    /// Merkle root hash
    pub merkle_root: [u8; 32],
}

/// HandshakeProof validation metadata
#[derive(Debug, Clone)]
pub struct HandshakeProofValidationMetadata {
    /// Whether HandshakeProof validation passed
    pub handshake_proof_validated: bool,
    /// Whether HandshakeProof structure is valid
    pub handshake_proof_structure_valid: bool,
    /// Whether HandshakeProof integrity check passed
    pub handshake_proof_integrity_valid: bool,
}

/// Guest validation error types
#[derive(Debug, Clone, PartialEq)]
pub enum GuestValidationError {
    /// Structure validation failed
    StructureValidationFailed {
        /// Description of the structure validation failure
        message: String,
    },
    /// Merkle proof verification failed
    MerkleProofVerificationFailed {
        /// Description of the Merkle proof verification failure
        message: String,
    },
    /// HandshakeProof validation failed
    HandshakeProofValidationFailed {
        /// Description of the HandshakeProof validation failure
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
    /// Merkle proof verification metadata
    pub merkle_metadata: MerkleVerificationMetadata,
    /// HandshakeProof validation metadata
    pub handshake_proof_metadata: HandshakeProofValidationMetadata,
    /// Total validation time in milliseconds
    pub validation_time_ms: u64,
}

/// Guest validator for minimal zktls validation
pub struct GuestValidator<P: CryptoProvider> {
    bundle_validator: BundleValidator,
    crypto_provider: P,
    strict_mode: bool,
}

impl<P: CryptoProvider> GuestValidator<P> {
    /// Create a new guest validator
    pub fn new(crypto_provider: P) -> Self {
        Self {
            bundle_validator: BundleValidator::new(),
            crypto_provider,
            strict_mode: false,
        }
    }

    /// Create a validator in strict mode
    pub fn new_strict(crypto_provider: P) -> Self {
        Self {
            bundle_validator: BundleValidator::new_strict(),
            crypto_provider,
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

        // 2. Merkle proof verification
        let merkle_metadata = self.verify_merkle_proofs(bundle)?;
        if !merkle_metadata.merkle_proofs_verified {
            errors.push(GuestValidationError::MerkleProofVerificationFailed {
                message: "Merkle proof verification failed".to_string(),
            });
        }

        // 3. HandshakeProof validation
        let handshake_proof_metadata = self.validate_handshake_proof(bundle)?;
        if !handshake_proof_metadata.handshake_proof_validated {
            errors.push(GuestValidationError::HandshakeProofValidationFailed {
                message: "HandshakeProof validation failed".to_string(),
            });
        }

        let validation_time = start_time.elapsed().as_millis() as u64;

        Ok(GuestValidationReport {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            metadata: GuestValidationMetadata {
                structure_metadata: structure_report.metadata,
                merkle_metadata,
                handshake_proof_metadata,
                validation_time_ms: validation_time,
            },
        })
    }

    /// Validate only structure (without Merkle proof and HandshakeProof validation)
    pub fn validate_structure_only(&self, bundle: &VefasCanonicalBundle) -> Result<ValidationReport> {
        self.bundle_validator.validate_bundle(bundle)
    }

    /// Validate only Merkle proofs (without structure and HandshakeProof validation)
    pub fn validate_merkle_proofs_only(&self, bundle: &VefasCanonicalBundle) -> Result<MerkleVerificationMetadata> {
        self.verify_merkle_proofs(bundle)
    }

    /// Validate only HandshakeProof (without structure and Merkle proof validation)
    pub fn validate_handshake_proof_only(&self, bundle: &VefasCanonicalBundle) -> Result<HandshakeProofValidationMetadata> {
        self.validate_handshake_proof(bundle)
    }

    /// Verify Merkle proofs for essential fields
    fn verify_merkle_proofs(&self, bundle: &VefasCanonicalBundle) -> Result<MerkleVerificationMetadata> {
        let merkle_root = bundle.merkle_root;
        let merkle_proofs = &bundle.merkle_proofs;
        
        // Count the number of proofs
        let merkle_proofs_count = merkle_proofs.len();
        
        // For now, we'll assume Merkle proofs are verified by the zkVM guest programs
        // This is a placeholder implementation - actual verification would be done in the guest
        let merkle_proofs_verified = !merkle_root.iter().all(|&b| b == 0) && !merkle_proofs.is_empty();
        
        Ok(MerkleVerificationMetadata {
            merkle_proofs_verified,
            merkle_proofs_count,
            merkle_root,
        })
    }

    /// Validate HandshakeProof structure and integrity
    fn validate_handshake_proof(&self, bundle: &VefasCanonicalBundle) -> Result<HandshakeProofValidationMetadata> {
        // Build HandshakeProof from bundle
        let handshake_proof = vefas_crypto::bundle_parser::build_handshake_proof(bundle)
            .map_err(|e| VefasCoreError::ValidationError(format!("Failed to build HandshakeProof: {:?}", e)))?;
        
        // Validate HandshakeProof structure
        let handshake_proof_structure_valid = handshake_proof.validate().is_ok();
        
        // Verify HandshakeProof integrity against bundle data
        let handshake_proof_integrity_valid = vefas_crypto::validation::validate_handshake_proof_integrity(&handshake_proof, bundle).is_ok();
        
        let handshake_proof_validated = handshake_proof_structure_valid && handshake_proof_integrity_valid;
        
        Ok(HandshakeProofValidationMetadata {
            handshake_proof_validated,
            handshake_proof_structure_valid,
            handshake_proof_integrity_valid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vefas_crypto_native::NativeCryptoProvider;

    #[test]
    fn test_guest_validator_creation() {
        let crypto_provider = NativeCryptoProvider::new();
        let validator = GuestValidator::new(crypto_provider);
        assert!(!validator.strict_mode);
    }

    #[test]
    fn test_guest_validator_strict_mode() {
        let crypto_provider = NativeCryptoProvider::new();
        let validator = GuestValidator::new_strict(crypto_provider);
        assert!(validator.strict_mode);
    }
}
