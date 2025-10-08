//! TLS 1.3 utility functions
//!
//! This module provides TLS 1.3 specific utility functions that are used
//! by the native crypto provider for session key derivation and nonce generation.

use vefas_crypto::traits::{Hash, Kdf, KeyExchange};
use vefas_types::{
    tls::{CipherSuite, SessionKeys},
    VefasError, VefasResult,
};

use crate::traits::VefasCrypto;

/// Verify TLS 1.3 session keys derivation
pub fn verify_session_keys(
    provider: &impl VefasCrypto,
    handshake_transcript: &[u8],
    shared_secret: &[u8],
    cipher_suite: CipherSuite,
) -> VefasResult<SessionKeys> {
    // Minimal support for TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
    match cipher_suite {
        CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => {}
        _ => {
            return Err(VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::UnsupportedAlgorithm,
                "Unsupported cipher suite in verify_session_keys",
            ));
        }
    }

    let key_len: usize = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => 16,
        CipherSuite::Aes256GcmSha384 => 32,
        _ => 16,
    }; // AES-128/256
    let iv_len: usize = 12; // 96-bit IV
    let handshake_hash_vec = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => provider.sha256(handshake_transcript).to_vec(),
        CipherSuite::Aes256GcmSha384 => provider.sha384(handshake_transcript).to_vec(),
        _ => provider.sha256(handshake_transcript).to_vec(),
    };

    let early_secret = provider.hkdf_extract(&[], &[]);
    let empty_hash_vec = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => provider.sha256(&[]).to_vec(),
        CipherSuite::Aes256GcmSha384 => provider.sha384(&[]).to_vec(),
        _ => provider.sha256(&[]).to_vec(),
    };
    let hash_len: u8 = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => 32,
        CipherSuite::Aes256GcmSha384 => 48,
        _ => 32,
    };
    let derived =
        provider.hkdf_expand_label(&early_secret, b"derived", &empty_hash_vec, hash_len)?;

    // Use correct HKDF extract based on cipher suite
    let handshake_secret = match cipher_suite {
        CipherSuite::Aes256GcmSha384 => {
            // SHA-384: 48-byte secrets
            let mut derived_arr = [0u8; 48];
            derived_arr.copy_from_slice(&derived);
            provider.hkdf_extract_sha384(&derived_arr, shared_secret).to_vec()
        }
        _ => {
            // SHA-256: 32-byte secrets (default for AES-128 and ChaCha20)
            let mut derived_arr = [0u8; 32];
            let take = core::cmp::min(32, derived.len());
            derived_arr[..take].copy_from_slice(&derived[..take]);
            provider.hkdf_extract(&derived_arr, shared_secret).to_vec()
        }
    };

    let _c_hs = provider.hkdf_expand_label(
        &handshake_secret,
        b"c hs traffic",
        &handshake_hash_vec,
        hash_len,
    )?;
    let _s_hs = provider.hkdf_expand_label(
        &handshake_secret,
        b"s hs traffic",
        &handshake_hash_vec,
        hash_len,
    )?;

    let derived2 =
        provider.hkdf_expand_label(&handshake_secret, b"derived", &empty_hash_vec, hash_len)?;

    // Use correct HKDF extract based on cipher suite
    let master_secret = match cipher_suite {
        CipherSuite::Aes256GcmSha384 => {
            // SHA-384: 48-byte secrets
            let mut derived2_arr = [0u8; 48];
            derived2_arr.copy_from_slice(&derived2);
            provider.hkdf_extract_sha384(&derived2_arr, &[]).to_vec()
        }
        _ => {
            // SHA-256: 32-byte secrets (default for AES-128 and ChaCha20)
            let mut derived2_arr = [0u8; 32];
            let take2 = core::cmp::min(32, derived2.len());
            derived2_arr[..take2].copy_from_slice(&derived2[..take2]);
            provider.hkdf_extract(&derived2_arr, &[]).to_vec()
        }
    };

    let c_ap = provider.hkdf_expand_label(
        &master_secret,
        b"c ap traffic",
        &handshake_hash_vec,
        hash_len,
    )?;
    let s_ap = provider.hkdf_expand_label(
        &master_secret,
        b"s ap traffic",
        &handshake_hash_vec,
        hash_len,
    )?;

    let c_key = provider.hkdf_expand_label(&c_ap, b"key", &[], key_len as u8)?;
    let s_key = provider.hkdf_expand_label(&s_ap, b"key", &[], key_len as u8)?;
    let c_iv = provider.hkdf_expand_label(&c_ap, b"iv", &[], iv_len as u8)?;
    let s_iv = provider.hkdf_expand_label(&s_ap, b"iv", &[], iv_len as u8)?;

    let res_master =
        provider.hkdf_expand_label(&master_secret, b"res master", &handshake_hash_vec, hash_len)?;

    let mut out = SessionKeys::new(cipher_suite);
    out.client_application_secret = c_ap;
    out.server_application_secret = s_ap;
    out.client_application_key = c_key;
    out.server_application_key = s_key;
    out.client_application_iv = c_iv;
    out.server_application_iv = s_iv;
    out.handshake_secret = handshake_secret.to_vec();
    out.master_secret = master_secret.to_vec();
    out.resumption_master_secret = res_master;
    out.validate(cipher_suite)?;
    Ok(out)
}

/// Derive TLS 1.3 per-record AEAD nonce (RFC 8446 §5.3) by XOR'ing the static IV with the big-endian sequence number.
pub fn derive_aead_nonce(static_iv: &[u8], sequence_number: u64) -> VefasResult<[u8; 12]> {
    if static_iv.len() != 12 {
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidNonceLength,
            "TLS 1.3 IV must be 12 bytes",
        ));
    }

    // Create 12-byte nonce with seq in the last 8 bytes (big-endian), first 4 bytes zero
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&sequence_number.to_be_bytes());

    // XOR with static IV
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = static_iv[i] ^ nonce[i];
    }
    Ok(out)
}

/// Compute ECDHE shared secret from client private key and server public key
///
/// This function performs the ECDHE key exchange to compute the shared secret
/// that is used for TLS 1.3 key derivation.
///
/// # Arguments
/// * `crypto` - Cryptographic provider implementing KeyExchange trait
/// * `client_private_key` - 32-byte client private key
/// * `server_public_key` - Server's public key (32 bytes for X25519, 65 bytes for P-256)
/// * `key_share_group` - TLS key share group identifier (0x001d for X25519, 0x0017 for P-256)
///
/// # Returns
/// 32-byte shared secret or error if computation fails
pub fn compute_ecdhe_shared_secret<C: KeyExchange>(
    crypto: &C,
    client_private_key: &[u8; 32],
    server_public_key: &[u8],
    key_share_group: u16,
) -> VefasResult<[u8; 32]> {
    match key_share_group {
        0x001d => {
            // X25519 key exchange
            if server_public_key.len() != 32 {
                return Err(VefasError::invalid_input(
                    "server_public_key",
                    "X25519 public key must be 32 bytes",
                ));
            }
            
            let mut server_pub_key = [0u8; 32];
            server_pub_key.copy_from_slice(server_public_key);
            
            crypto.x25519_compute_shared_secret(client_private_key, &server_pub_key)
        }
        0x0017 => {
            // P-256 key exchange
            if server_public_key.len() != 65 {
                return Err(VefasError::invalid_input(
                    "server_public_key",
                    "P-256 public key must be 65 bytes",
                ));
            }
            
            let mut server_pub_key = [0u8; 65];
            server_pub_key.copy_from_slice(server_public_key);
            
            crypto.p256_compute_shared_secret(client_private_key, &server_pub_key)
        }
        _ => Err(VefasError::invalid_input(
            "key_share_group",
            "Unsupported key share group",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeCryptoProvider;

    #[test]
    fn test_derive_aead_nonce() {
        let static_iv = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let sequence_number = 0x1234567890abcdef;
        
        let nonce = derive_aead_nonce(&static_iv, sequence_number).unwrap();
        
        // Expected: static_iv XOR [0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
        // static_iv: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]
        // nonce:     [0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
        // result:    [0x01, 0x02, 0x03, 0x04, 0x17, 0x32, 0x51, 0x70, 0x99, 0xa1, 0xc6, 0xe3]
        let expected = [
            0x01, 0x02, 0x03, 0x04, 0x17, 0x32, 0x51, 0x70, 0x99, 0xa1, 0xc6, 0xe3
        ];
        assert_eq!(nonce, expected);
    }

    #[test]
    fn test_derive_aead_nonce_invalid_length() {
        let static_iv = [0x01, 0x02, 0x03]; // Too short
        let sequence_number = 0x1234567890abcdef;
        
        let result = derive_aead_nonce(&static_iv, sequence_number);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_session_keys() {
        let provider = NativeCryptoProvider::new();
        let handshake_transcript = b"test handshake transcript";
        let shared_secret = b"test shared secret";
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        
        let session_keys = verify_session_keys(&provider, handshake_transcript, shared_secret, cipher_suite).unwrap();
        
        // Verify the session keys are properly populated
        assert!(!session_keys.client_application_secret.is_empty());
        assert!(!session_keys.server_application_secret.is_empty());
        assert!(!session_keys.client_application_key.is_empty());
        assert!(!session_keys.server_application_key.is_empty());
        assert!(!session_keys.client_application_iv.is_empty());
        assert!(!session_keys.server_application_iv.is_empty());
        assert!(!session_keys.handshake_secret.is_empty());
        assert!(!session_keys.master_secret.is_empty());
        assert!(!session_keys.resumption_master_secret.is_empty());
    }
}
