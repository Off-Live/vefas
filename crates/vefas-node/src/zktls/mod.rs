//! # VEFAS zkTLS Module
//!
//! This module provides ZK proof generation, validation and verification capabilities
//! for the VEFAS node.

pub mod attestation;
pub mod certificate;
pub mod ocsp;
pub mod prover;
pub mod transparency;
pub mod verifier;

// Re-export main types
pub use attestation::{
    VerifierAttestation, AttestationSigner, AttestationVerifier, AttestationConfig,
    CertificateValidationResult, OcspValidationResult, CtValidationResult, CtLogEntry,
};
pub use certificate::{CertificateValidator, CertificateConfig};
pub use ocsp::{OcspChecker, OcspConfig};
pub use prover::ProverService;
pub use transparency::{CtLogVerifier, CtConfig};
pub use verifier::{
    VerifierService, ZkProofValidationResult, ZkProofValidationMetadata,
};
