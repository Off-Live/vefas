//! # Attestation System
//!
//! This module implements the attestation system for VEFAS Node.
//! Attestations are Ed25519-signed statements confirming the validity of TLS trust checks.
//!
//! Architecture note: Attestations are host-only operations and always use NativeCryptoProvider.
//! zkVM proof verification uses separate ELF ID & VK verification, not attestations.

use crate::error::{VefasNodeError, VefasNodeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vefas_types::VefasCanonicalBundle;
use chrono::{DateTime, Utc};
use vefas_crypto::Signature as SignatureTrait;
use vefas_crypto_native::NativeCryptoProvider;

/// Verifier attestation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifierAttestation {
    /// Attestation ID (UUID)
    pub id: String,
    /// Verifier node ID
    pub verifier_id: String,
    /// Proof ID this attestation refers to
    pub proof_id: [u8; 32],
    /// Domain name
    pub domain: String,
    /// Certificate fingerprint
    pub cert_fingerprint: [u8; 32],
    /// Timestamp when attestation was created
    pub timestamp: DateTime<Utc>,
    /// Attestation validity duration
    pub validity_duration_secs: u64,
    /// Certificate validation result
    pub certificate_validation: CertificateValidationResult,
    /// OCSP validation result (optional)
    pub ocsp_validation: Option<OcspValidationResult>,
    /// Certificate Transparency validation result (optional)
    pub ct_validation: Option<CtValidationResult>,
    /// Attestation signature
    pub signature: Vec<u8>,
    /// Verifier public key
    pub verifier_public_key: Vec<u8>,
}

/// Certificate validation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertificateValidationResult {
    /// Whether certificate chain is valid
    pub is_valid: bool,
    /// Certificate chain length
    pub chain_length: usize,
    /// Certificate expiration date
    pub expiration_date: DateTime<Utc>,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate subject
    pub subject: String,
    /// Validation errors (if any)
    pub errors: Vec<String>,
}

/// OCSP validation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OcspValidationResult {
    /// Whether OCSP check passed
    pub is_valid: bool,
    /// OCSP response status
    pub status: String,
    /// OCSP response timestamp
    pub timestamp: DateTime<Utc>,
    /// OCSP response next update time
    pub next_update: Option<DateTime<Utc>>,
    /// OCSP validation errors (if any)
    pub errors: Vec<String>,
}

/// Certificate Transparency validation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CtValidationResult {
    /// Whether CT validation passed
    pub is_valid: bool,
    /// Number of CT logs checked
    pub logs_checked: usize,
    /// Number of CT logs that confirmed the certificate
    pub logs_confirmed: usize,
    /// CT log entries
    pub log_entries: Vec<CtLogEntry>,
    /// CT validation errors (if any)
    pub errors: Vec<String>,
}

/// Certificate Transparency log entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CtLogEntry {
    /// CT log ID
    pub log_id: String,
    /// Log entry index
    pub index: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// SCT (Signed Certificate Timestamp)
    pub sct: Vec<u8>,
}

/// Attestation configuration
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// Private key path
    pub private_key_path: std::path::PathBuf,
    /// Validity duration
    pub validity_duration: std::time::Duration,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            private_key_path: std::path::PathBuf::from("attestation_key.pem"),
            validity_duration: std::time::Duration::from_secs(86400), // 24 hours
        }
    }
}

/// Attestation signer using native Ed25519 implementation
#[derive(Debug)]
pub struct AttestationSigner {
    /// Signing configuration
    config: AttestationConfig,
    /// Ed25519 private key (32-byte seed)
    private_key: [u8; 32],
    /// Ed25519 public key (32-byte compressed point)
    public_key: [u8; 32],
    /// Verifier node ID (hex-encoded public key)
    verifier_id: String,
    /// Native crypto provider (for signing operations)
    crypto_provider: NativeCryptoProvider,
}

/// Attestation verifier using native Ed25519 implementation
#[derive(Debug)]
pub struct AttestationVerifier {
    /// Trusted verifier public keys (verifier_id -> 32-byte Ed25519 public key)
    trusted_verifiers: HashMap<String, [u8; 32]>,
    /// Native crypto provider (for verification operations)
    crypto_provider: NativeCryptoProvider,
}

impl AttestationSigner {
    /// Create a new attestation signer using NativeCryptoProvider
    pub async fn new(config: AttestationConfig) -> VefasNodeResult<Self> {
        let crypto_provider = NativeCryptoProvider::new();

        // Load or generate Ed25519 key pair
        let (private_key, public_key) = if config.private_key_path.exists() {
            // Load existing key
            let key_data = std::fs::read(&config.private_key_path)
                .map_err(|e| VefasNodeError::Configuration(format!("Failed to read private key: {}", e)))?;

            // Parse PEM format
            let pem = pem::parse(key_data)
                .map_err(|e| VefasNodeError::Configuration(format!("Failed to parse private key PEM: {}", e)))?;

            if pem.tag() != "PRIVATE KEY" {
                return Err(VefasNodeError::Configuration("Private key must be in PEM format".to_string()));
            }

            let private_key: [u8; 32] = pem.contents()[..32].try_into()
                .map_err(|_| VefasNodeError::Configuration("Invalid private key length".to_string()))?;

            // Load corresponding public key
            let public_key_path = config.private_key_path.with_extension("pub");
            if public_key_path.exists() {
                let pub_key_data = std::fs::read(&public_key_path)
                    .map_err(|e| VefasNodeError::Configuration(format!("Failed to read public key: {}", e)))?;
                let pub_pem = pem::parse(pub_key_data)
                    .map_err(|e| VefasNodeError::Configuration(format!("Failed to parse public key PEM: {}", e)))?;
                let public_key: [u8; 32] = pub_pem.contents()[..32].try_into()
                    .map_err(|_| VefasNodeError::Configuration("Invalid public key length".to_string()))?;
                (private_key, public_key)
            } else {
                return Err(VefasNodeError::Configuration(
                    "Public key file not found. Both private and public keys are required.".to_string()
                ));
            }
        } else {
            // Generate new key pair using vefas-crypto trait
            let (private_key, public_key) = crypto_provider.ed25519_generate_keypair();

            // Save private key to file
            let private_key_pem = pem::Pem::new("PRIVATE KEY", private_key.to_vec());
            std::fs::write(&config.private_key_path, pem::encode(&private_key_pem))
                .map_err(|e| VefasNodeError::Configuration(format!("Failed to save private key: {}", e)))?;

            // Save public key to file
            let public_key_path = config.private_key_path.with_extension("pub");
            let public_key_pem = pem::Pem::new("PUBLIC KEY", public_key.to_vec());
            std::fs::write(public_key_path, pem::encode(&public_key_pem))
                .map_err(|e| VefasNodeError::Configuration(format!("Failed to save public key: {}", e)))?;

            (private_key, public_key)
        };

        // Generate verifier ID from public key (hex-encoded)
        let verifier_id = hex::encode(public_key);

        Ok(Self {
            config,
            private_key,
            public_key,
            verifier_id,
            crypto_provider,
        })
    }

    /// Create an attestation for a VEFAS bundle
    pub async fn create_attestation(
        &self,
        bundle: &VefasCanonicalBundle,
        cert_validation: &CertificateValidationResult,
        ocsp_validation: Option<&OcspValidationResult>,
        ct_validation: Option<&CtValidationResult>,
    ) -> VefasNodeResult<VerifierAttestation> {
        let now = Utc::now();
        let id = uuid::Uuid::new_v4().to_string();

        // Create attestation
        let mut attestation = VerifierAttestation {
            id,
            verifier_id: self.verifier_id.clone(),
            proof_id: [0u8; 32], // Will be set when proof is available
            domain: bundle.domain.clone(),
            cert_fingerprint: bundle.cert_fingerprint,
            timestamp: now,
            validity_duration_secs: self.config.validity_duration.as_secs(),
            certificate_validation: cert_validation.clone(),
            ocsp_validation: ocsp_validation.cloned(),
            ct_validation: ct_validation.cloned(),
            signature: Vec::new(), // Will be set after signing
            verifier_public_key: self.public_key.to_vec(),
        };

        // Sign the attestation
        let signature = self.sign_attestation(&attestation)?;
        attestation.signature = signature;

        Ok(attestation)
    }

    /// Sign an attestation using vefas-crypto Ed25519
    fn sign_attestation(&self, attestation: &VerifierAttestation) -> VefasNodeResult<Vec<u8>> {
        // Serialize attestation for signing (excluding signature field)
        let mut attestation_for_signing = attestation.clone();
        attestation_for_signing.signature = Vec::new();

        let serialized = serde_json::to_vec(&attestation_for_signing)
            .map_err(|e| VefasNodeError::Serialization(format!("Failed to serialize attestation: {}", e)))?;

        // Sign using vefas-crypto trait
        let signature = self.crypto_provider.ed25519_sign(&self.private_key, &serialized);

        Ok(signature.to_vec())
    }

    /// Get the verifier ID
    pub fn verifier_id(&self) -> &str {
        &self.verifier_id
    }

    /// Get the public key (32-byte Ed25519 public key)
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

impl AttestationVerifier {
    /// Create a new attestation verifier using NativeCryptoProvider
    pub async fn new() -> VefasNodeResult<Self> {
        Ok(Self {
            trusted_verifiers: HashMap::new(),
            crypto_provider: NativeCryptoProvider::new(),
        })
    }

    /// Add a trusted verifier with their Ed25519 public key
    pub fn add_trusted_verifier(&mut self, verifier_id: String, public_key: [u8; 32]) {
        self.trusted_verifiers.insert(verifier_id, public_key);
    }

    /// Verify an attestation using vefas-crypto Ed25519
    pub fn verify_attestation(&self, attestation: &VerifierAttestation) -> VefasNodeResult<bool> {
        // Check if verifier is trusted
        let verifier_public_key = self.trusted_verifiers.get(&attestation.verifier_id)
            .ok_or_else(|| VefasNodeError::InvalidRequest(
                format!("Unknown verifier: {}", attestation.verifier_id)
            ))?;

        // Verify the public key matches
        if attestation.verifier_public_key != *verifier_public_key {
            return Err(VefasNodeError::InvalidRequest(
                "Public key mismatch".to_string()
            ));
        }

        // Check attestation expiration
        let now = Utc::now();
        let expiration = attestation.timestamp + chrono::Duration::seconds(attestation.validity_duration_secs as i64);
        if now > expiration {
            return Err(VefasNodeError::InvalidRequest(
                "Attestation has expired".to_string()
            ));
        }

        // Verify signature using vefas-crypto trait
        let mut attestation_for_verification = attestation.clone();
        attestation_for_verification.signature = Vec::new();

        let serialized = serde_json::to_vec(&attestation_for_verification)
            .map_err(|e| VefasNodeError::Serialization(format!("Failed to serialize attestation: {}", e)))?;

        let signature: [u8; 64] = attestation.signature[..64].try_into()
            .map_err(|_| VefasNodeError::InvalidRequest("Invalid signature length".to_string()))?;

        let is_valid = self.crypto_provider.ed25519_verify(verifier_public_key, &serialized, &signature);

        Ok(is_valid)
    }

    /// Verify multiple attestations (k-of-n validation)
    pub fn verify_attestations(&self, attestations: &[VerifierAttestation], k: usize) -> VefasNodeResult<bool> {
        if attestations.len() < k {
            return Err(VefasNodeError::InvalidRequest(
                format!("Not enough attestations: need {}, got {}", k, attestations.len())
            ));
        }

        let mut valid_count = 0;
        for attestation in attestations {
            if self.verify_attestation(attestation)? {
                valid_count += 1;
            }
        }

        Ok(valid_count >= k)
    }
}

impl VerifierAttestation {
    /// Check if the attestation is expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let expiration = self.timestamp + chrono::Duration::seconds(self.validity_duration_secs as i64);
        now > expiration
    }

    /// Get the expiration time
    pub fn expiration_time(&self) -> DateTime<Utc> {
        self.timestamp + chrono::Duration::seconds(self.validity_duration_secs as i64)
    }

    /// Check if the attestation is valid (not expired and has valid signature)
    pub fn is_valid(&self, verifier: &AttestationVerifier) -> VefasNodeResult<bool> {
        if self.is_expired() {
            return Ok(false);
        }

        verifier.verify_attestation(self)
    }
}
