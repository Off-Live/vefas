//! Integration tests for crypto implementations with VefasCanonicalBundle format

use vefas_crypto::traits::{Aead, Hash, Kdf, KeyExchange, Signature, VefasCrypto};
use vefas_types::bundle::VefasCanonicalBundle;

/// Mock crypto provider for testing bundle integration
#[derive(Debug, Clone, Default)]
struct MockCrypto;

impl Hash for MockCrypto {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        // Simple test hash - just use first 32 bytes repeated
        let mut result = [0u8; 32];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte = input.get(i % input.len()).copied().unwrap_or(0);
        }
        result
    }

    fn sha384(&self, _input: &[u8]) -> [u8; 48] {
        [0u8; 48]
    }

    fn hmac_sha256(&self, _key: &[u8], _data: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn hmac_sha384(&self, _key: &[u8], _data: &[u8]) -> [u8; 48] {
        [0u8; 48]
    }
}

impl Aead for MockCrypto {
    fn aes_128_gcm_encrypt(
        &self,
        _key: &[u8; 16],
        _nonce: &[u8; 12],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        let mut result = plaintext.to_vec();
        result.extend_from_slice(&[0u8; 16]); // Append "auth tag"
        Ok(result)
    }

    fn aes_128_gcm_decrypt(
        &self,
        _key: &[u8; 16],
        _nonce: &[u8; 12],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(vefas_types::VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::CipherFailed,
                "ciphertext too short",
            ));
        }
        Ok(ciphertext[..ciphertext.len() - 16].to_vec())
    }

    fn aes_256_gcm_encrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        let mut result = plaintext.to_vec();
        result.extend_from_slice(&[0u8; 16]);
        Ok(result)
    }

    fn aes_256_gcm_decrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(vefas_types::VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::CipherFailed,
                "ciphertext too short",
            ));
        }
        Ok(ciphertext[..ciphertext.len() - 16].to_vec())
    }

    fn chacha20_poly1305_encrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        let mut result = plaintext.to_vec();
        result.extend_from_slice(&[0u8; 16]);
        Ok(result)
    }

    fn chacha20_poly1305_decrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(vefas_types::VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::CipherFailed,
                "ciphertext too short",
            ));
        }
        Ok(ciphertext[..ciphertext.len() - 16].to_vec())
    }
}

impl KeyExchange for MockCrypto {
    fn x25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32])
    }

    fn x25519_compute_shared_secret(
        &self,
        _private_key: &[u8; 32],
        _public_key: &[u8; 32],
    ) -> vefas_types::VefasResult<[u8; 32]> {
        Ok([3u8; 32])
    }

    fn p256_generate_keypair(&self) -> vefas_types::VefasResult<([u8; 32], [u8; 65])> {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        Ok(([1u8; 32], public_key))
    }

    fn p256_compute_shared_secret(
        &self,
        _private_key: &[u8; 32],
        _public_key: &[u8; 65],
    ) -> vefas_types::VefasResult<[u8; 32]> {
        Ok([3u8; 32])
    }
}

impl Signature for MockCrypto {
    fn p256_generate_keypair(&self) -> vefas_types::VefasResult<([u8; 32], [u8; 65])> {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        Ok(([1u8; 32], public_key))
    }

    fn p256_sign(
        &self,
        _private_key: &[u8; 32],
        _message: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; 64])
    }

    fn p256_verify(&self, _public_key: &[u8; 65], _message: &[u8], _signature: &[u8]) -> bool {
        true
    }

    fn secp256k1_generate_keypair(&self) -> vefas_types::VefasResult<([u8; 32], [u8; 65])> {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        Ok(([1u8; 32], public_key))
    }

    fn secp256k1_sign(
        &self,
        _private_key: &[u8; 32],
        _message: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; 64])
    }

    fn secp256k1_verify(&self, _public_key: &[u8; 65], _message: &[u8], _signature: &[u8]) -> bool {
        true
    }

    fn ed25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32])
    }

    fn ed25519_sign(&self, _private_key: &[u8; 32], _message: &[u8]) -> [u8; 64] {
        [0u8; 64]
    }

    fn ed25519_verify(
        &self,
        _public_key: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> bool {
        true
    }

    fn rsa_2048_generate_keypair(&self) -> vefas_types::VefasResult<(Vec<u8>, Vec<u8>)> {
        Ok((vec![0u8; 256], vec![0u8; 256]))
    }

    fn rsa_pkcs1_sha256_sign(
        &self,
        _private_key_der: &[u8],
        _message: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; 256])
    }

    fn rsa_pkcs1_sha256_verify(
        &self,
        _public_key_der: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> bool {
        true
    }

    fn rsa_pss_sha256_sign(
        &self,
        _private_key_der: &[u8],
        _message: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; 256])
    }

    fn rsa_pss_sha256_verify(
        &self,
        _public_key_der: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> bool {
        true
    }
}

impl Kdf for MockCrypto {
    fn hkdf_extract(&self, _salt: &[u8], _ikm: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn hkdf_expand(
        &self,
        _prk: &[u8; 32],
        _info: &[u8],
        length: usize,
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; length])
    }

    fn hkdf_extract_sha384(&self, _salt: &[u8], _ikm: &[u8]) -> [u8; 48] {
        [0u8; 48]
    }

    fn hkdf_expand_sha384(
        &self,
        _prk: &[u8; 48],
        _info: &[u8],
        length: usize,
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; length])
    }
}

impl vefas_crypto::traits::PrecompileDetection for MockCrypto {
    // All defaults (false)
}

impl VefasCrypto for MockCrypto {
    fn provider_name(&self) -> &'static str {
        "mock"
    }

    fn provider_version(&self) -> &'static str {
        "test"
    }
}

/// Test that creates a minimal canonical bundle and processes it with crypto operations
#[test]
fn test_bundle_crypto_integration() {
    let provider = MockCrypto;
    let bundle = create_test_bundle();

    // Test hash operations on bundle components
    let client_hello_hash = provider.sha256(&bundle.client_hello().unwrap());
    assert_eq!(client_hello_hash.len(), 32);

    let server_hello_hash = provider.sha256(&bundle.server_hello().unwrap());
    assert_eq!(server_hello_hash.len(), 32);

    // Test transcript hash calculation (TLS 1.3 handshake)
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&bundle.client_hello().unwrap());
    transcript.extend_from_slice(&bundle.server_hello().unwrap());
    transcript.extend_from_slice(&bundle.certificate_msg().unwrap());

    let transcript_hash = provider.sha256(&transcript);
    assert_eq!(transcript_hash.len(), 32);

    // Test HKDF key derivation using shared secret
    let handshake_secret = provider.hkdf_extract(&[0u8; 32], &bundle.client_private_key().unwrap());
    assert_eq!(handshake_secret.len(), 32);

    // Test derive handshake secrets using TLS 1.3 pattern
    let (client_hs_secret, server_hs_secret) = provider
        .derive_handshake_secrets(&bundle.client_private_key().unwrap(), &transcript_hash)
        .expect("handshake secret derivation should succeed");

    assert_eq!(client_hs_secret.len(), 32);
    assert_eq!(server_hs_secret.len(), 32);

    // Test key expansion for TLS keys
    let client_key = provider
        .hkdf_expand_label(&client_hs_secret, b"key", &[], 16)
        .expect("key expansion should succeed");
    assert_eq!(client_key.len(), 16);

    // Test AES-GCM operations with derived keys
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad = b"TLS 1.3 record";
    let plaintext = b"HTTP/1.1 200 OK\r\n\r\n";

    let ciphertext = provider
        .aes_128_gcm_encrypt(&key, &nonce, aad, plaintext)
        .expect("encryption should succeed");

    let decrypted = provider
        .aes_128_gcm_decrypt(&key, &nonce, aad, &ciphertext)
        .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);

    // Test that we can process certificate verification data
    for cert_der in &bundle.certificate_chain().unwrap() {
        let cert_hash = provider.sha256(cert_der);
        assert_eq!(cert_hash.len(), 32);
    }

    // Test X25519 key exchange with bundle key
    let (x25519_private, x25519_public) = provider.x25519_generate_keypair();
    let shared_secret = provider
        .x25519_compute_shared_secret(&x25519_private, &x25519_public)
        .expect("X25519 key exchange should succeed");
    assert_eq!(shared_secret.len(), 32);
}

/// Create a minimal test bundle for crypto integration testing
fn create_test_bundle() -> VefasCanonicalBundle {
    // Minimal TLS handshake messages
    let client_hello = vec![
        0x16, 0x03, 0x03, 0x00, 0x20, // TLS record header
        0x01, 0x00, 0x00, 0x1c, // ClientHello header
        0x03, 0x03, // TLS version
        // Client random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let server_hello = vec![
        0x16, 0x03, 0x03, 0x00, 0x20, // TLS record header
        0x02, 0x00, 0x00, 0x1c, // ServerHello header
        0x03, 0x03, // TLS version
        // Server random (32 bytes)
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];

    let certificate_msg = vec![
        0x16, 0x03, 0x03, 0x00, 0x10, // TLS record header
        0x0b, 0x00, 0x00, 0x0c, // Certificate header
        0x00, 0x00, 0x09, // Certificate list length
        0x00, 0x00, 0x06, // First certificate length
        0x30, 0x82, 0x01, 0x02, // Minimal certificate DER
    ];

    let certificate_verify_msg = vec![
        0x16, 0x03, 0x03, 0x00, 0x08, // TLS record header
        0x0f, 0x00, 0x00, 0x04, // CertificateVerify header
        0x04, 0x03, 0x00, 0x00, // Signature algorithm and signature
    ];

    let server_finished_msg = vec![
        0x16, 0x03, 0x03, 0x00, 0x14, // TLS record header
        0x14, 0x00, 0x00, 0x10, // Finished header
        // Finished verify data (12 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    let encrypted_extensions = vec![
        0x16, 0x03, 0x03, 0x00, 0x08, // TLS record header
        0x08, 0x00, 0x00, 0x04, // EncryptedExtensions header
        0x00, 0x00, 0x00, 0x00, // Empty extensions
    ];

    let client_finished_msg = vec![
        0x16, 0x03, 0x03, 0x00, 0x14, // TLS record header
        0x14, 0x00, 0x00, 0x10, // Finished header
        // Finished verify data (12 bytes)
        0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ];

    // Cryptographic materials
    let client_private_key = [0x42; 32]; // Test private key
    let certificate_chain = vec![
        // Minimal test certificate
        vec![
            0x30, 0x82, 0x01, 0x02, 0x30, 0x82, 0x00, 0xaa, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
            0x01, 0x01,
        ],
    ];

    // Application data
    let encrypted_request = vec![
        0x17, 0x03, 0x03, 0x00, 0x20, // Application data record
        // Encrypted HTTP request
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let encrypted_response = vec![
        0x17, 0x03, 0x03, 0x00, 0x30, // Application data record
        // Encrypted HTTP response
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
        0x4e, 0x4f, 0x50,
    ];

    // Use the proper constructor
    let mut bundle = VefasCanonicalBundle::new(
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate_msg,
        certificate_verify_msg,
        server_finished_msg,
        client_finished_msg,
        client_private_key,
        certificate_chain,
        encrypted_request,
        encrypted_response,
        "example.com".to_string(),
        1234567890,
        200,
        [0x5a; 32],
        #[cfg(debug_assertions)]
        None,
    )
    .expect("Failed to create test bundle");
    
    // Add mock Merkle proofs for testing
    bundle.set_merkle_proofs(
        [0x90u8; 32], // Mock Merkle root
        vec![
            (1, vec![0x01u8; 100]), // ClientHello proof
            (2, vec![0x02u8; 100]), // ServerHello proof
            (6, vec![0x06u8; 100]), // ServerFinished proof
            (12, vec![0x0cu8; 100]), // HttpRequestCanonical proof
            (13, vec![0x0du8; 100]), // HttpResponseCanonical proof
        ],
    );
    
    bundle
}

/// Test Merkle proof functionality
#[test]
fn test_merkle_proofs() {
    let bundle = create_test_bundle();
    
    // Test that Merkle root is set
    assert!(bundle.merkle_root().is_some());
    let merkle_root = bundle.merkle_root().unwrap();
    assert_eq!(merkle_root.len(), 32);
    
    // Test that Merkle proofs are available
    assert!(bundle.get_merkle_proof(1).is_some()); // ClientHello
    assert!(bundle.get_merkle_proof(2).is_some()); // ServerHello
    assert!(bundle.get_merkle_proof(6).is_some()); // ServerFinished
    assert!(bundle.get_merkle_proof(12).is_some()); // HttpRequestCanonical
    assert!(bundle.get_merkle_proof(13).is_some()); // HttpResponseCanonical
    
    // Test that non-existent proof returns None
    assert!(bundle.get_merkle_proof(99).is_none());
}

/// Test serialization/deserialization compatibility
#[test]
fn test_bundle_serialization() {
    let bundle = create_test_bundle();

    // Test that we can serialize and deserialize the bundle
    let serialized = serde_json::to_string(&bundle).expect("Bundle should serialize to JSON");

    let deserialized: VefasCanonicalBundle =
        serde_json::from_str(&serialized).expect("Bundle should deserialize from JSON");

    assert_eq!(bundle, deserialized);

    // Test that the bundle has expected structure
    assert_eq!(bundle.version, 1);
    assert!(!bundle.client_hello().unwrap().is_empty());
    assert!(!bundle.server_hello().unwrap().is_empty());
    assert!(!bundle.certificate_msg().unwrap().is_empty());
    assert!(!bundle.encrypted_request().unwrap().is_empty());
    assert!(!bundle.encrypted_response().unwrap().is_empty());
    assert_eq!(bundle.domain, "example.com");
    assert_eq!(bundle.client_private_key().unwrap().len(), 32);
    assert_eq!(bundle.verifier_nonce.len(), 32);
}

/// Test that crypto providers can process bundle data deterministically
#[test]
fn test_deterministic_processing() {
    let bundle = create_test_bundle();
    let provider = MockCrypto;

    // Process the same bundle multiple times
    let hash1 = provider.sha256(&bundle.client_hello().unwrap());
    let hash2 = provider.sha256(&bundle.client_hello().unwrap());
    let hash3 = provider.sha256(&bundle.client_hello().unwrap());

    // Results should be identical (deterministic)
    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);

    // Test with HKDF
    let secret1 = provider.hkdf_extract(&[0u8; 32], &bundle.client_private_key().unwrap());
    let secret2 = provider.hkdf_extract(&[0u8; 32], &bundle.client_private_key().unwrap());
    assert_eq!(secret1, secret2);
}
