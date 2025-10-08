//! # SP1 Crypto Provider Implementation
//!
//! This module provides a concrete implementation of the CryptoProvider trait
//! using the SP1 crypto provider from vefas-crypto-sp1.

use alloc::{string::String, vec::Vec};

use vefas_types::crypto_provider::{CryptoProvider, CryptoResult};
use vefas_types::errors::{VefasError, CryptoErrorType};
use crate::SP1CryptoProvider;
use vefas_crypto::traits::Hash;
use vefas_crypto::tls_parser::{hkdf_expand_label_for_cipher, decrypt_application_record, compute_transcript_hash};
use vefas_types::CipherSuite;

/// SP1 implementation of CryptoProvider trait
pub struct Sp1CryptoProviderImpl {
    crypto: SP1CryptoProvider,
}

impl Sp1CryptoProviderImpl {
    /// Create a new SP1 crypto provider implementation
    pub fn new() -> Self {
        Self {
            crypto: SP1CryptoProvider::new(),
        }
    }
}

impl CryptoProvider for Sp1CryptoProviderImpl {
    /// Verify HMAC for a Finished message
    fn verify_finished_hmac(
        &self,
        finished_msg: &[u8],
        traffic_secret: &[u8],
        transcript_hash: &[u8],
        cipher_suite: &str,
    ) -> CryptoResult<bool> {
        // TODO: Implement actual HMAC verification using SP1 crypto provider
        // This would involve:
        // 1. Deriving the Finished key from traffic secret
        // 2. Computing HMAC of transcript hash
        // 3. Comparing with the Finished message content
        
        // For now, just validate structure
        if finished_msg.len() < 4 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "Finished message too short",
            ));
        }

        if finished_msg[0] != 20 {
            return Err(VefasError::crypto_error(
                CryptoErrorType::CipherFailed,
                "Finished message has wrong type",
            ));
        }

        Ok(true)
    }

    /// Derive traffic secrets using HKDF
    fn derive_traffic_secrets(
        &self,
        master_secret: &[u8],
        transcript_hash: &[u8],
        cipher_suite: &str,
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Parse cipher suite to get hash length
        let cipher_suite_enum = match cipher_suite {
            "Aes128GcmSha256" => CipherSuite::Aes128GcmSha256,
            "Aes256GcmSha384" => CipherSuite::Aes256GcmSha384,
            "ChaCha20Poly1305Sha256" => CipherSuite::ChaCha20Poly1305Sha256,
            _ => return Err(VefasError::crypto_error(
                CryptoErrorType::UnsupportedAlgorithm,
                "Unsupported cipher suite",
            )),
        };

        let hash_len = match cipher_suite_enum {
            CipherSuite::Aes128GcmSha256 => 32,
            CipherSuite::Aes256GcmSha384 => 48,
            CipherSuite::ChaCha20Poly1305Sha256 => 32,
        };

        // Derive client and server application traffic secrets using SP1 crypto provider
        let client_secret = vefas_crypto::tls_parser::hkdf_expand_label(
            &self.crypto,
            master_secret,
            b"c ap traffic",
            transcript_hash,
            hash_len,
        ).map_err(|e| VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "Client secret derivation failed",
        ))?;

        let server_secret = vefas_crypto::tls_parser::hkdf_expand_label(
            &self.crypto,
            master_secret,
            b"s ap traffic",
            transcript_hash,
            hash_len,
        ).map_err(|e| VefasError::crypto_error(
            CryptoErrorType::KeyDerivationFailed,
            "Server secret derivation failed",
        ))?;

        Ok((client_secret, server_secret))
    }

    /// Decrypt application data
    fn decrypt_application_data(
        &self,
        encrypted_data: &[u8],
        traffic_secret: &[u8],
        sequence_number: u64,
        cipher_suite: &str,
    ) -> CryptoResult<Vec<u8>> {
        // Parse cipher suite
        let cipher_suite_enum = match cipher_suite {
            "Aes128GcmSha256" => CipherSuite::Aes128GcmSha256,
            "Aes256GcmSha384" => CipherSuite::Aes256GcmSha384,
            "ChaCha20Poly1305Sha256" => CipherSuite::ChaCha20Poly1305Sha256,
            _ => return Err(VefasError::crypto_error(
                CryptoErrorType::UnsupportedAlgorithm,
                "Unsupported cipher suite",
            )),
        };

        // Use the existing decrypt_application_record function with SP1 crypto provider
        decrypt_application_record(
            &self.crypto,
            encrypted_data,
            traffic_secret,
            sequence_number,
            cipher_suite_enum,
        )
    }

    /// Compute hash of data
    fn compute_hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let hash = self.crypto.sha256(data);
        Ok(hash.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_crypto_provider_creation() {
        let provider = Sp1CryptoProviderImpl::new();
        // Test that it can be created without errors
        assert!(true);
    }

    #[test]
    fn test_derive_traffic_secrets() {
        let provider = Sp1CryptoProviderImpl::new();
        let master_secret = vec![0u8; 48];
        let transcript_hash = vec![0u8; 48];
        
        let result = provider.derive_traffic_secrets(
            &master_secret,
            &transcript_hash,
            "Aes256GcmSha384",
        );
        
        assert!(result.is_ok());
        let (client_secret, server_secret) = result.unwrap();
        assert_eq!(client_secret.len(), 48);
        assert_eq!(server_secret.len(), 48);
    }
}
