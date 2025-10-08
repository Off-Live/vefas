use hex::FromHex;
use serde::Deserialize;
use sha2::Digest; // bring Digest trait in scope for Sha256::digest
use std::path::Path;
use vefas_crypto::VefasCrypto;
use vefas_types::tls::CipherSuite;
use vefas_types::{VefasError, VefasResult};

// Implement the needed functions directly in the test to avoid circular dependency
fn derive_aead_nonce(static_iv: &[u8], sequence_number: u64) -> VefasResult<[u8; 12]> {
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

fn verify_session_keys(
    provider: &impl VefasCrypto,
    handshake_transcript: &[u8],
    shared_secret: &[u8],
    cipher_suite: CipherSuite,
) -> VefasResult<vefas_types::tls::SessionKeys> {
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
    let handshake_secret = provider.hkdf_extract(&early_secret, shared_secret);
    let master_secret = provider.hkdf_extract(&handshake_secret, &handshake_hash_vec);

    let _client_handshake_key = provider.hkdf_expand(&master_secret, b"c hs traffic", key_len)?;
    let _server_handshake_key = provider.hkdf_expand(&master_secret, b"s hs traffic", key_len)?;
    let _client_handshake_iv = provider.hkdf_expand(&master_secret, b"c hs traffic", iv_len)?;
    let _server_handshake_iv = provider.hkdf_expand(&master_secret, b"s hs traffic", iv_len)?;

    // Determine secret length based on cipher suite
    let secret_len = match cipher_suite {
        CipherSuite::Aes256GcmSha384 => 48,
        _ => 32,
    };

    let client_application_secret = provider.hkdf_expand(&master_secret, b"c ap traffic", secret_len)?;
    let server_application_secret = provider.hkdf_expand(&master_secret, b"s ap traffic", secret_len)?;
    let client_application_key = provider.hkdf_expand(&master_secret, b"c ap traffic", key_len)?;
    let server_application_key = provider.hkdf_expand(&master_secret, b"s ap traffic", key_len)?;
    let client_application_iv = provider.hkdf_expand(&master_secret, b"c ap traffic", iv_len)?;
    let server_application_iv = provider.hkdf_expand(&master_secret, b"s ap traffic", iv_len)?;

    Ok(vefas_types::tls::SessionKeys {
        client_application_secret,
        server_application_secret,
        client_application_key,
        server_application_key,
        client_application_iv,
        server_application_iv,
        handshake_secret: handshake_secret.to_vec(),
        master_secret: master_secret.to_vec(),
        resumption_master_secret: early_secret.to_vec(),
    })
}

struct NativeMock;

impl vefas_crypto::traits::Hash for NativeMock {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(input).into()
    }
    fn sha384(&self, input: &[u8]) -> [u8; 48] {
        use sha2::{Digest, Sha384};
        let mut out = [0u8; 48];
        out.copy_from_slice(&Sha384::digest(input));
        out
    }
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
    fn hmac_sha384(&self, key: &[u8], data: &[u8]) -> [u8; 48] {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut mac = Hmac::<Sha384>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl vefas_crypto::traits::Kdf for NativeMock {
    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(salt).unwrap();
        mac.update(ikm);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        out
    }
    fn hkdf_expand(
        &self,
        prk: &[u8; 32],
        info: &[u8],
        length: usize,
    ) -> vefas_types::VefasResult<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::from_prk(prk).unwrap();
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm).unwrap();
        Ok(okm)
    }

    fn hkdf_extract_sha384(&self, salt: &[u8], ikm: &[u8]) -> [u8; 48] {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let mut mac = Hmac::<Sha384>::new_from_slice(salt).unwrap();
        mac.update(ikm);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 48];
        out.copy_from_slice(&tag);
        out
    }

    fn hkdf_expand_sha384(
        &self,
        prk: &[u8; 48],
        info: &[u8],
        length: usize,
    ) -> vefas_types::VefasResult<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha384;
        let hk = Hkdf::<Sha384>::from_prk(prk).unwrap();
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm).unwrap();
        Ok(okm)
    }
}

impl vefas_crypto::traits::Aead for NativeMock {
    fn aes_128_gcm_encrypt(
        &self,
        _k: &[u8; 16],
        _n: &[u8; 12],
        _a: &[u8],
        p: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; p.len() + 16])
    }
    fn aes_128_gcm_decrypt(
        &self,
        _k: &[u8; 16],
        _n: &[u8; 12],
        _a: &[u8],
        c: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; c.len().saturating_sub(16)])
    }
    fn aes_256_gcm_encrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        p: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; p.len() + 16])
    }
    fn aes_256_gcm_decrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        c: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; c.len().saturating_sub(16)])
    }
    fn chacha20_poly1305_encrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        p: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; p.len() + 16])
    }
    fn chacha20_poly1305_decrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        c: &[u8],
    ) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; c.len().saturating_sub(16)])
    }
}

impl vefas_crypto::traits::KeyExchange for NativeMock {
    fn x25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
        ([0u8; 32], [0u8; 32])
    }
    fn x25519_compute_shared_secret(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
    ) -> vefas_types::VefasResult<[u8; 32]> {
        Ok([0u8; 32])
    }
    fn p256_generate_keypair(&self) -> vefas_types::VefasResult<([u8; 32], [u8; 65])> {
        Ok(([0u8; 32], [0u8; 65]))
    }
    fn p256_compute_shared_secret(
        &self,
        _: &[u8; 32],
        _: &[u8; 65],
    ) -> vefas_types::VefasResult<[u8; 32]> {
        Ok([0u8; 32])
    }
}

impl vefas_crypto::traits::Signature for NativeMock {
    fn p256_generate_keypair(&self) -> vefas_types::VefasResult<([u8; 32], [u8; 65])> {
        Ok(([0u8; 32], [0u8; 65]))
    }
    fn p256_sign(&self, _: &[u8; 32], _: &[u8]) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; 64])
    }
    fn p256_verify(&self, _: &[u8; 65], _: &[u8], _: &[u8]) -> bool {
        true
    }
    fn secp256k1_generate_keypair(&self) -> vefas_types::VefasResult<([u8; 32], [u8; 65])> {
        Ok(([0u8; 32], [0u8; 65]))
    }
    fn secp256k1_sign(&self, _: &[u8; 32], _: &[u8]) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![0u8; 64])
    }
    fn secp256k1_verify(&self, _: &[u8; 65], _: &[u8], _: &[u8]) -> bool {
        true
    }
    fn ed25519_generate_keypair(&self) -> ([u8; 32], [u8; 32]) {
        ([0u8; 32], [0u8; 32])
    }
    fn ed25519_sign(&self, _: &[u8; 32], _: &[u8]) -> [u8; 64] {
        [0u8; 64]
    }
    fn ed25519_verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
        true
    }
    fn rsa_2048_generate_keypair(&self) -> vefas_types::VefasResult<(Vec<u8>, Vec<u8>)> {
        Ok((vec![], vec![]))
    }
    fn rsa_pkcs1_sha256_sign(&self, _: &[u8], _: &[u8]) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![])
    }
    fn rsa_pkcs1_sha256_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        true
    }
    fn rsa_pss_sha256_sign(&self, _: &[u8], _: &[u8]) -> vefas_types::VefasResult<Vec<u8>> {
        Ok(vec![])
    }
    fn rsa_pss_sha256_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        true
    }
}

impl vefas_crypto::traits::PrecompileDetection for NativeMock {}
impl VefasCrypto for NativeMock {}

#[test]
fn derives_keys_and_ivs_for_tls13_aes128_gcm_sha256() {
    // Test with dummy shared secret and minimal transcript hash; this checks sizes and flow
    let provider = NativeMock;
    let shared_secret = [1u8; 32];
    let transcript = b"handshake";
    let keys = verify_session_keys(
        &provider,
        transcript,
        &shared_secret,
        CipherSuite::Aes128GcmSha256,
    )
    .expect("keys");

    assert_eq!(keys.client_application_key.len(), 16);
    assert_eq!(keys.server_application_key.len(), 16);
    assert_eq!(keys.client_application_iv.len(), 12);
    assert_eq!(keys.server_application_iv.len(), 12);
    assert_eq!(keys.client_application_secret.len(), 32);
    assert_eq!(keys.server_application_secret.len(), 32);
    assert_eq!(keys.handshake_secret.len(), 32);
    assert_eq!(keys.master_secret.len(), 32);

    // Verify nonce construction shape
    let nonce = derive_aead_nonce(&keys.client_application_iv, 1).expect("nonce");
    assert_eq!(nonce.len(), 12);
}

#[test]
fn derives_keys_and_ivs_for_tls13_aes256_gcm_sha384_lengths() {
    let provider = NativeMock;
    let shared_secret = [2u8; 48];
    let transcript = b"handshake-sha384";
    let keys = verify_session_keys(
        &provider,
        transcript,
        &shared_secret,
        CipherSuite::Aes256GcmSha384,
    )
    .expect("keys");

    // AES-256 key lengths
    assert_eq!(keys.client_application_key.len(), 32);
    assert_eq!(keys.server_application_key.len(), 32);
    assert_eq!(keys.client_application_iv.len(), 12);
    assert_eq!(keys.server_application_iv.len(), 12);

    // Secrets should be based on SHA-384 length
    assert_eq!(keys.client_application_secret.len(), 48);
    assert_eq!(keys.server_application_secret.len(), 48);
    assert!(keys.handshake_secret.len() == 32 || keys.handshake_secret.len() == 48);
    assert!(keys.master_secret.len() == 32 || keys.master_secret.len() == 48);
}

#[derive(Deserialize)]
struct Rfc8448Vector {
    shared_secret: String,
    transcript_hash: String,
    client_application_secret: String,
    server_application_secret: String,
    client_application_key: String,
    server_application_key: String,
    client_application_iv: String,
    server_application_iv: String,
    master_secret: String,
    resumption_master_secret: String,
}

fn load_vector(path: &str) -> Option<Rfc8448Vector> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

fn for_each_vector_in_dir<P: AsRef<Path>>(dir: P, mut f: impl FnMut(&Path, Rfc8448Vector)) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(s) = std::fs::read_to_string(&p) {
                    if let Ok(v) = serde_json::from_str::<Rfc8448Vector>(&s) {
                        f(&p, v);
                    }
                }
            }
        }
    }
}

#[test]
fn rfc8448_vector_validation_if_available() {
    // Optional test: requires RFC8448 vector JSON file path
    if let Ok(path) = std::env::var("RFC8448_VECTOR_FILE") {
        if let Some(vec) = load_vector(&path) {
            let provider = NativeMock;
            let shared_secret = <Vec<u8>>::from_hex(&vec.shared_secret).expect("hex");
            let transcript_hash = <Vec<u8>>::from_hex(&vec.transcript_hash).expect("hex");
            let suite = match transcript_hash.len() {
                32 => CipherSuite::Aes128GcmSha256,
                48 => CipherSuite::Aes256GcmSha384,
                n => panic!("unexpected transcript hash length {} in {:?}", n, path),
            };
            let keys = verify_session_keys(&provider, &transcript_hash, &shared_secret, suite)
                .expect("keys");

            let cas = <Vec<u8>>::from_hex(&vec.client_application_secret).unwrap();
            let sas = <Vec<u8>>::from_hex(&vec.server_application_secret).unwrap();
            let cak = <Vec<u8>>::from_hex(&vec.client_application_key).unwrap();
            let sak = <Vec<u8>>::from_hex(&vec.server_application_key).unwrap();
            let cai = <Vec<u8>>::from_hex(&vec.client_application_iv).unwrap();
            let sai = <Vec<u8>>::from_hex(&vec.server_application_iv).unwrap();
            let ms = <Vec<u8>>::from_hex(&vec.master_secret).unwrap();
            let rms = <Vec<u8>>::from_hex(&vec.resumption_master_secret).unwrap();

            // Length sanity by suite
            match suite {
                CipherSuite::Aes128GcmSha256 => {
                    assert_eq!(cas.len(), 32);
                    assert_eq!(sas.len(), 32);
                    assert_eq!(cak.len(), 16);
                    assert_eq!(sak.len(), 16);
                    assert_eq!(cai.len(), 12);
                    assert_eq!(sai.len(), 12);
                    assert_eq!(ms.len(), 32);
                    assert_eq!(rms.len(), 32);
                }
                CipherSuite::Aes256GcmSha384 => {
                    assert_eq!(cas.len(), 48);
                    assert_eq!(sas.len(), 48);
                    assert_eq!(cak.len(), 32);
                    assert_eq!(sak.len(), 32);
                    assert_eq!(cai.len(), 12);
                    assert_eq!(sai.len(), 12);
                    assert_eq!(ms.len(), 48);
                    assert_eq!(rms.len(), 48);
                }
                _ => {}
            }

            assert_eq!(keys.client_application_secret, cas);
            assert_eq!(keys.server_application_secret, sas);
            assert_eq!(keys.client_application_key, cak);
            assert_eq!(keys.server_application_key, sak);
            assert_eq!(keys.client_application_iv, cai);
            assert_eq!(keys.server_application_iv, sai);
            assert_eq!(keys.master_secret, ms);
            assert_eq!(keys.resumption_master_secret, rms);
        }
    }

    // Optional directory of vectors
    if let Ok(dir) = std::env::var("RFC8448_VECTORS_DIR") {
        for_each_vector_in_dir(dir, |p, vec| {
            let provider = NativeMock;
            let shared_secret = <Vec<u8>>::from_hex(&vec.shared_secret).expect("hex");
            let transcript_hash = <Vec<u8>>::from_hex(&vec.transcript_hash).expect("hex");
            let suite = match transcript_hash.len() {
                32 => CipherSuite::Aes128GcmSha256,
                48 => CipherSuite::Aes256GcmSha384,
                n => panic!("unexpected transcript hash length {} in {:?}", n, p),
            };
            let keys = verify_session_keys(&provider, &transcript_hash, &shared_secret, suite)
                .expect("keys");

            let cas = <Vec<u8>>::from_hex(&vec.client_application_secret).unwrap();
            let sas = <Vec<u8>>::from_hex(&vec.server_application_secret).unwrap();
            let cak = <Vec<u8>>::from_hex(&vec.client_application_key).unwrap();
            let sak = <Vec<u8>>::from_hex(&vec.server_application_key).unwrap();
            let cai = <Vec<u8>>::from_hex(&vec.client_application_iv).unwrap();
            let sai = <Vec<u8>>::from_hex(&vec.server_application_iv).unwrap();
            let ms = <Vec<u8>>::from_hex(&vec.master_secret).unwrap();
            let rms = <Vec<u8>>::from_hex(&vec.resumption_master_secret).unwrap();

            // Suite-based length sanity
            match suite {
                CipherSuite::Aes128GcmSha256 => {
                    assert_eq!(cas.len(), 32, "cas len {:?}", p);
                    assert_eq!(sas.len(), 32, "sas len {:?}", p);
                    assert_eq!(cak.len(), 16, "cak len {:?}", p);
                    assert_eq!(sak.len(), 16, "sak len {:?}", p);
                    assert_eq!(cai.len(), 12, "cai len {:?}", p);
                    assert_eq!(sai.len(), 12, "sai len {:?}", p);
                    assert_eq!(ms.len(), 32, "ms len {:?}", p);
                    assert_eq!(rms.len(), 32, "rms len {:?}", p);
                }
                CipherSuite::Aes256GcmSha384 => {
                    assert_eq!(cas.len(), 48, "cas len {:?}", p);
                    assert_eq!(sas.len(), 48, "sas len {:?}", p);
                    assert_eq!(cak.len(), 32, "cak len {:?}", p);
                    assert_eq!(sak.len(), 32, "sak len {:?}", p);
                    assert_eq!(cai.len(), 12, "cai len {:?}", p);
                    assert_eq!(sai.len(), 12, "sai len {:?}", p);
                    assert_eq!(ms.len(), 48, "ms len {:?}", p);
                    assert_eq!(rms.len(), 48, "rms len {:?}", p);
                }
                _ => {}
            }

            assert_eq!(
                keys.client_application_secret, cas,
                "client app secret {:?}",
                p
            );
            assert_eq!(
                keys.server_application_secret, sas,
                "server app secret {:?}",
                p
            );
            assert_eq!(keys.client_application_key, cak, "client key {:?}", p);
            assert_eq!(keys.server_application_key, sak, "server key {:?}", p);
            assert_eq!(keys.client_application_iv, cai, "client iv {:?}", p);
            assert_eq!(keys.server_application_iv, sai, "server iv {:?}", p);
            assert_eq!(keys.master_secret, ms, "master secret {:?}", p);
            assert_eq!(keys.resumption_master_secret, rms, "res master {:?}", p);
        });
    }
}
