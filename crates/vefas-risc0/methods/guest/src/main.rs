//! VEFAS RISC0 Guest Program
//!
//! This program runs inside the RISC0 zkVM and verifies VEFAS canonical bundles.
//! It performs cryptographic verification of TLS sessions captured by vefas-core.
//!
//! ## What this program verifies:
//!
//! 1. **TLS Handshake Validity**: Verifies that the TLS 1.3 handshake is cryptographically valid
//! 2. **Certificate Chain**: Validates the server certificate chain
//! 3. **Key Derivation**: Verifies that session keys were derived correctly from the handshake
//! 4. **Record Decryption**: Decrypts TLS application data to extract HTTP content
//! 5. **HTTP Integrity**: Ensures HTTP request/response data is consistent and unmodified
//! 6. **Domain Binding**: Verifies the request was actually sent to the claimed domain
//!
//! ## Architecture:
//!
//! ```text
//! Host (vefas-core) → VefasCanonicalBundle → RISC0 zkVM (this program) → VefasProofClaim
//! ```
//!
//! This follows the host-rustls + guest-verifier pattern where:
//! - Host captures real TLS session data using production rustls
//! - Guest verifies the captured data cryptographically in zkVM
//! - Result is a zero-knowledge proof of the TLS session

#![no_std]

extern crate alloc;

use vefas_types::{VefasCanonicalBundle, VefasResult, VefasError, tls::CipherSuite, compression::CompressedBundle, VefasProofClaim, VefasPerformanceMetrics, VefasExecutionMetadata, errors::CryptoErrorType};
use risc0_zkvm::guest::env;
use alloc::{string::{String, ToString}, vec::Vec};
use bincode;
use vefas_crypto::{
    traits::{Hash, Kdf, KeyExchange},
    parse_server_cipher_suite, parse_server_hello_key_share,
    validate_certificate_message, parse_http_data, HttpData, hex_lower,
    hkdf_expand_label, decrypt_application_record, compute_transcript_hash,
    verify_session_keys as verify_session_keys_common,
    tls_parser::{cipher_suite_name, validate_client_hello, validate_server_hello,
                 validate_certificate_verify, validate_finished_message},
    validation::{validate_certificate_domain_binding},
};
use vefas_crypto_risc0::create_risc0_provider;

// Provide a no-op eprintln! for no_std environment to satisfy macro expansion
macro_rules! eprintln { ($($tt:tt)*) => { () } }


fn main() {
    // Read input data from the host (could be compressed or uncompressed bundle)
    let input_data: Vec<u8> = env::read();

    // Track execution cycles for metadata
    let start_cycles = env::cycle_count();

    // Attempt to deserialize as compressed bundle first, then as regular bundle
    let (bundle, compression_metrics) = match bincode::deserialize::<CompressedBundle>(&input_data) {
        Ok(compressed_bundle) => {
            // Handle compressed bundle
            let decompression_start = env::cycle_count();

            match vefas_types::compression::BundleCompressor::decompress(&compressed_bundle) {
                Ok(decompressed_data) => {
                    let decompression_cycles = env::cycle_count() - decompression_start;
                    eprintln!("RISC0: Decompressed bundle in {} cycles", decompression_cycles);

                    match bincode::deserialize::<VefasCanonicalBundle>(&decompressed_data) {
                        Ok(bundle) => {
                            let metrics = (
                                decompression_cycles,
                                Some(compressed_bundle.compression_ratio()),
                                Some(compressed_bundle.original_size as usize),
                                Some(decompressed_data.len()),
                            );
                            (bundle, Some(metrics))
                        }
                        Err(_) => {
                            eprintln!("RISC0: Failed to deserialize decompressed bundle");
                            // Create empty bundle to trigger verification failure
                            let empty_bundle = create_empty_bundle();
                            (empty_bundle, None)
                        }
                    }
                }
                Err(_) => {
                    eprintln!("RISC0: Failed to decompress bundle");
                    let empty_bundle = create_empty_bundle();
                    (empty_bundle, None)
                }
            }
        }
        Err(_) => {
            // Try to deserialize as uncompressed bundle
            match bincode::deserialize::<VefasCanonicalBundle>(&input_data) {
                Ok(bundle) => {
                    eprintln!("RISC0: Processing uncompressed bundle");
                    (bundle, None)
                }
                Err(_) => {
                    eprintln!("RISC0: Failed to deserialize input as bundle");
                    let empty_bundle = create_empty_bundle();
                    (empty_bundle, None)
                }
            }
        }
    };

    // Verify the bundle and generate claim - panic on verification failure to match SP1 security behavior
    let claim = match verify_vefas_bundle(&bundle, start_cycles, compression_metrics) {
        Ok(claim) => {
            // Log successful verification for audit trail
            eprintln!("VEFAS RISC0 guest verification succeeded");
            claim
        },
        Err(e) => {
            // Log detailed error information before panic
            eprintln!("VEFAS RISC0 guest verification failed with error: {:?}", e);
            eprintln!("Error category: {}", e.category());

            // Ensure zkVM execution fails with clear verification failure (matches SP1 behavior)
            match e {
                VefasError::InvalidInput { field, reason } => {
                    panic!("VERIFICATION_FAILURE: Invalid input in field '{}': {}", field, reason)
                },
                VefasError::CryptoError { error_type, message } => {
                    panic!("VERIFICATION_FAILURE: Cryptographic error ({:?}): {}", error_type, message)
                },
                VefasError::TlsError { error_type, message } => {
                    panic!("VERIFICATION_FAILURE: TLS error ({:?}): {}", error_type, message)
                },
                VefasError::CertificateError { error_type, message } => {
                    panic!("VERIFICATION_FAILURE: Certificate error ({:?}): {}", error_type, message)
                },
                _ => {
                    panic!("VERIFICATION_FAILURE: Unexpected error: {:?}", e)
                }
            }
        }
    };

    // Log detailed performance metrics
    eprintln!("RISC0 VEFAS verification completed in {} total cycles", claim.performance.total_cycles);
    eprintln!("  - Decompression: {} cycles", claim.performance.decompression_cycles);
    eprintln!("  - Validation: {} cycles", claim.performance.validation_cycles);
    eprintln!("  - Handshake: {} cycles", claim.performance.handshake_cycles);
    eprintln!("  - Certificate validation: {} cycles", claim.performance.certificate_validation_cycles);
    eprintln!("  - Key derivation: {} cycles", claim.performance.key_derivation_cycles);
    eprintln!("  - Decryption: {} cycles", claim.performance.decryption_cycles);
    eprintln!("  - HTTP parsing: {} cycles", claim.performance.http_parsing_cycles);
    eprintln!("  - Crypto ops: {} cycles", claim.performance.crypto_operations_cycles);
    eprintln!("  - Memory usage: {} bytes", claim.performance.memory_usage);
    if let Some(_ratio) = claim.performance.compression_ratio {
        eprintln!("  - Compression ratio: {:.1}%", _ratio);
    }

    // Commit the claim to the journal
    env::commit(&claim);
}

/// Verify VEFAS canonical bundle and extract proof claim
///
/// This function performs the core verification logic that proves:
/// 1. The TLS handshake is cryptographically valid
/// 2. The HTTP data was actually exchanged over the verified TLS connection
/// 3. The domain, timing, and content claims are accurate
fn verify_vefas_bundle(
    bundle: &VefasCanonicalBundle,
    start_cycles: u64,
    compression_metrics: Option<(u64, Option<f32>, Option<usize>, Option<usize>)>
) -> VefasResult<VefasProofClaim> {
    let mut performance = VefasPerformanceMetrics {
        total_cycles: 0,
        decompression_cycles: compression_metrics.as_ref().map(|(cycles, _, _, _)| *cycles).unwrap_or(0),
        validation_cycles: 0,
        handshake_cycles: 0,
        certificate_validation_cycles: 0,
        key_derivation_cycles: 0,
        decryption_cycles: 0,
        http_parsing_cycles: 0,
        crypto_operations_cycles: 0,
        memory_usage: 0,
        compression_ratio: compression_metrics.as_ref().and_then(|(_, ratio, _, _)| *ratio),
        original_bundle_size: compression_metrics.as_ref().and_then(|(_, _, size, _)| *size),
        decompressed_bundle_size: compression_metrics.as_ref().and_then(|(_, _, _, size)| *size),
    };
    let crypto = create_risc0_provider();

    // Step 1: Validate bundle structure
    let validation_start = env::cycle_count();
    bundle.validate()?;
    performance.validation_cycles = env::cycle_count() - validation_start;

    // Step 2: Verify TLS 1.3 handshake messages
    let handshake_start = env::cycle_count();
    let cert_validation_cycles = verify_tls_handshake(bundle, &crypto)?;
    performance.handshake_cycles = env::cycle_count() - handshake_start;
    performance.certificate_validation_cycles = cert_validation_cycles;

    // Step 3: Derive session keys from handshake
    let key_derivation_start = env::cycle_count();
    let session_keys = derive_session_keys(bundle, &crypto)?;
    performance.key_derivation_cycles = env::cycle_count() - key_derivation_start;

    // Step 4: Decrypt application data to extract HTTP content
    let decryption_start = env::cycle_count();
    let http_data = decrypt_application_data(bundle, &session_keys, &crypto)?;
    performance.decryption_cycles = env::cycle_count() - decryption_start;

    // Step 5: Parse and validate HTTP request/response
    let http_parsing_start = env::cycle_count();
    let (method, path, status_code) = parse_http_data(&http_data)?;
    performance.http_parsing_cycles = env::cycle_count() - http_parsing_start;

    // Step 6: Compute content hashes
    let crypto_start = env::cycle_count();
    let request_hash = hex_lower(crypto.sha256(&http_data.request).as_slice());
    let response_hash = hex_lower(crypto.sha256(&http_data.response).as_slice());

    // Extended claims - extract bundle data using accessor methods
    let server_hello = bundle.server_hello()?;
    let client_hello = bundle.client_hello()?;
    let certificate_msg = bundle.certificate_msg()?;
    let certificate_verify_msg = bundle.certificate_verify_msg()?;
    let certificate_chain = bundle.certificate_chain()?;

    let suite_id = parse_server_cipher_suite(&server_hello)?;
    let cipher_suite = cipher_suite_name(suite_id).to_string();
    let tls_version = "1.3".to_string();

    let mut cert_concat: Vec<u8> = Vec::new();
    for cert in &certificate_chain {
        cert_concat.extend_from_slice(cert);
    }
    let certificate_chain_hash_bytes = crypto.sha256(&cert_concat);
    let certificate_chain_hash: [u8; 32] = certificate_chain_hash_bytes.try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Certificate chain hash conversion failed"))?;

    let mut hs_msgs: Vec<&[u8]> = Vec::new();
    hs_msgs.push(&client_hello);
    hs_msgs.push(&server_hello);
    if !certificate_msg.is_empty() { hs_msgs.push(&certificate_msg); }
    if !certificate_verify_msg.is_empty() { hs_msgs.push(&certificate_verify_msg); }

    let handshake_transcript_hash_bytes = compute_transcript_hash(&crypto, &hs_msgs, CipherSuite::Aes128GcmSha256);
    let handshake_transcript_hash: [u8; 32] = handshake_transcript_hash_bytes.try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Handshake transcript hash conversion failed"))?;
    performance.crypto_operations_cycles = env::cycle_count() - crypto_start;

    // Calculate total cycles and estimate memory usage
    performance.total_cycles = env::cycle_count() - start_cycles;
    performance.memory_usage = estimate_memory_usage(bundle);

    // Step 7: Create verified claim
    // Generate default commitments for now - these should be computed from actual request/response
    let request_commitment: [u8; 32] = crypto.sha256(request_hash.as_bytes()).try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Request commitment generation failed"))?;
    let response_commitment: [u8; 32] = crypto.sha256(response_hash.as_bytes()).try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Response commitment generation failed"))?;

    // Create execution metadata
    let execution_metadata = VefasExecutionMetadata {
        cycles: 0, // Will be filled by host
        memory_usage: performance.memory_usage as u64,
        execution_time_ms: 0, // Will be filled by host
        platform: "risc0".to_string(),
        proof_time_ms: 0, // Will be filled by host
    };

    VefasProofClaim::new(
        bundle.domain.clone(),                           // domain
        method,                                          // method
        path,                                           // path
        request_commitment,                             // request_commitment
        response_commitment,                            // response_commitment
        request_hash,                                   // request_hash
        response_hash,                                  // response_hash
        status_code,                                    // status_code
        tls_version,                                    // tls_version
        cipher_suite,                                   // cipher_suite
        certificate_chain_hash,                         // certificate_chain_hash
        handshake_transcript_hash,                      // handshake_transcript_hash
        bundle.timestamp,                               // timestamp
        performance,                                    // performance
        execution_metadata,                             // execution_metadata
    )
}

/// Verify TLS 1.3 handshake cryptographic validity
fn verify_tls_handshake(bundle: &VefasCanonicalBundle, crypto: &vefas_crypto_risc0::RISC0CryptoProvider) -> VefasResult<u64> {
    let cert_validation_start = env::cycle_count();

    // Extract bundle data using accessor methods
    let client_hello = bundle.client_hello()?;
    let server_hello = bundle.server_hello()?;
    let certificate_msg = bundle.certificate_msg()?;
    let certificate_chain = bundle.certificate_chain()?;
    let certificate_verify_msg = bundle.certificate_verify_msg()?;

    // Verify ClientHello message structure
    validate_client_hello(&client_hello)?;

    // Verify ServerHello message structure and cipher suite
    validate_server_hello(&server_hello)?;
    let suite = parse_server_cipher_suite(&server_hello)?;
    if suite != 0x1301 { // TLS_AES_128_GCM_SHA256
        return Err(VefasError::invalid_input("server_hello", "Unsupported cipher suite (only TLS_AES_128_GCM_SHA256)"));
    }

    // Verify Certificate message and chain
    validate_certificate_message(&certificate_msg, &certificate_chain)?;

    // Enforce leaf certificate domain binding
    validate_certificate_domain_binding(&certificate_chain, &bundle.domain)?;

    // Verify CertificateVerify message
    validate_certificate_verify(&certificate_verify_msg)?;

    // Verify ServerFinished (requires secrets)
    verify_server_finished(bundle, crypto)?;

    let cert_validation_cycles = env::cycle_count() - cert_validation_start;
    eprintln!("RISC0: Certificate validation completed in {} cycles", cert_validation_cycles);

    Ok(cert_validation_cycles)
}

/// Session keys derived from TLS handshake
struct SessionKeys {
    client_application_traffic_secret: [u8; 32],
    server_application_traffic_secret: [u8; 32],
}

/// Derive TLS 1.3 session keys from handshake data
fn derive_session_keys(bundle: &VefasCanonicalBundle, crypto: &vefas_crypto_risc0::RISC0CryptoProvider) -> VefasResult<SessionKeys> {
    // Extract bundle data using accessor methods
    let server_hello = bundle.server_hello()?;
    let client_hello = bundle.client_hello()?;
    let certificate_msg = bundle.certificate_msg()?;
    let certificate_verify_msg = bundle.certificate_verify_msg()?;
    let client_private_key = bundle.client_private_key()?;

    let key_share = parse_server_hello_key_share(&server_hello)?;

    let shared = match key_share.group {
        0x001D => { // x25519
            if key_share.key_exchange.len() != 32 {
                return Err(VefasError::invalid_input("server_hello", "Invalid X25519 key"));
            }
            let mut pub_arr = [0u8; 32];
            pub_arr.copy_from_slice(&key_share.key_exchange);
            crypto.x25519_compute_shared_secret(&client_private_key, &pub_arr)?
        }
        0x0017 => { // secp256r1
            if key_share.key_exchange.len() != 65 {
                return Err(VefasError::invalid_input("server_hello", "Invalid P-256 key"));
            }
            let mut pub_arr = [0u8; 65];
            pub_arr.copy_from_slice(&key_share.key_exchange);
            crypto.p256_compute_shared_secret(&client_private_key, &pub_arr)?
        }
        _ => return Err(VefasError::invalid_input("server_hello", "Unsupported key_share group")),
    };

    // Build application transcript (ClientHello, ServerHello, [Certificate], [CertificateVerify])
    let mut transcript: Vec<u8> = Vec::new();
    transcript.extend_from_slice(&client_hello);
    transcript.extend_from_slice(&server_hello);
    if !certificate_msg.is_empty() {
        transcript.extend_from_slice(&certificate_msg);
    }
    if !certificate_verify_msg.is_empty() {
        transcript.extend_from_slice(&certificate_verify_msg);
    }

    // Use shared implementation validated against RFC8448 vectors
    let keys = verify_session_keys_common(
        crypto,
        &transcript,
        &shared,
        CipherSuite::Aes128GcmSha256,
    )?;

    let mut c = [0u8; 32];
    let mut s = [0u8; 32];
    if keys.client_application_secret.len() != 32 || keys.server_application_secret.len() != 32 {
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidKeyLength,
            "unexpected secret length"
        ));
    }
    c.copy_from_slice(&keys.client_application_secret);
    s.copy_from_slice(&keys.server_application_secret);

    Ok(SessionKeys {
        client_application_traffic_secret: c,
        server_application_traffic_secret: s
    })
}

/// Decrypt TLS application data to extract HTTP content
fn decrypt_application_data(bundle: &VefasCanonicalBundle, keys: &SessionKeys, crypto: &vefas_crypto_risc0::RISC0CryptoProvider) -> VefasResult<HttpData> {
    // Extract bundle data using accessor methods
    let server_hello = bundle.server_hello()?;
    let encrypted_request = bundle.encrypted_request()?;
    let encrypted_response = bundle.encrypted_response()?;

    // Only TLS_AES_128_GCM_SHA256 supported
    let suite = parse_server_cipher_suite(&server_hello)?;
    if suite != 0x1301 {
        return Err(VefasError::invalid_input("server_hello", "Unsupported cipher suite"));
    }

    // For the first application record in each direction, the sequence number must be 0.
    let request = decrypt_application_record(
        crypto,
        &encrypted_request,
        &keys.client_application_traffic_secret,
        0
    )?;

    let response = decrypt_application_record(
        crypto,
        &encrypted_response,
        &keys.server_application_traffic_secret,
        0
    )?;

    Ok(HttpData::new(request, response))
}

/// Verify ServerFinished message using transcript hash
fn verify_server_finished(bundle: &VefasCanonicalBundle, crypto: &vefas_crypto_risc0::RISC0CryptoProvider) -> VefasResult<()> {
    // Extract bundle data using accessor methods
    let server_hello = bundle.server_hello()?;
    let client_hello = bundle.client_hello()?;
    let certificate_msg = bundle.certificate_msg()?;
    let certificate_verify_msg = bundle.certificate_verify_msg()?;
    let server_finished_msg = bundle.server_finished_msg()?;
    let client_private_key = bundle.client_private_key()?;

    // Recompute handshake secret and server handshake traffic secret
    let key_share = parse_server_hello_key_share(&server_hello)?;

    let shared = match key_share.group {
        0x001D => { // X25519
            if key_share.key_exchange.len() != 32 {
                return Err(VefasError::invalid_input("server_hello", "Invalid X25519 key length"));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&key_share.key_exchange);
            crypto.x25519_compute_shared_secret(&client_private_key, &pk)?
        }
        0x0017 => { // P-256
            if key_share.key_exchange.len() != 65 {
                return Err(VefasError::invalid_input("server_hello", "Invalid P-256 key length"));
            }
            let mut pk = [0u8; 65];
            pk.copy_from_slice(&key_share.key_exchange);
            crypto.p256_compute_shared_secret(&client_private_key, &pk)?
        }
        _ => return Err(VefasError::invalid_input("server_hello", "Unsupported key_share group")),
    };

    let zeros = [0u8; 32];
    let early_secret = crypto.hkdf_extract(&zeros, &[]);
    let derived = hkdf_expand_label(crypto, &early_secret, b"derived", &[], 32)?;
    let handshake_secret = crypto.hkdf_extract(&to_array_32(&derived)?, &shared);

    // Transcript hash up to (but excluding) Finished
    let mut msgs: Vec<&[u8]> = Vec::new();
    msgs.push(&client_hello);
    msgs.push(&server_hello);
    if !certificate_msg.is_empty() { msgs.push(&certificate_msg); }
    if !certificate_verify_msg.is_empty() { msgs.push(&certificate_verify_msg); }
    let th = compute_transcript_hash(crypto, &msgs, CipherSuite::Aes128GcmSha256);

    // Derive server handshake traffic secret and finished_key
    let s_hs = hkdf_expand_label(crypto, &handshake_secret, b"s hs traffic", &th, 32)?;
    let s_hs_arr = to_array_32(&s_hs)?;
    let finished_key = hkdf_expand_label(crypto, &s_hs_arr, b"finished", &[], 32)?;
    let finished_key_arr = to_array_32(&finished_key)?;

    // Expected verify_data
    let verify_expected = crypto.hmac_sha256(&finished_key_arr, &th);

    // Parse Finished handshake
    validate_finished_message(&server_finished_msg)?;
    let fin = &server_finished_msg;
    if fin.len() < 4 { return Err(VefasError::invalid_input("server_finished", "Too short")); }
    if fin[0] != 0x14 { return Err(VefasError::invalid_input("server_finished", "Wrong handshake type")); }
    let len = ((fin[1] as usize) << 16) | ((fin[2] as usize) << 8) | (fin[3] as usize);
    if 4 + len != fin.len() { return Err(VefasError::invalid_input("server_finished", "Length mismatch")); }
    if len != verify_expected.len() { return Err(VefasError::invalid_input("server_finished", "Unexpected verify_data length")); }
    if &fin[4..] != verify_expected {
        return Err(VefasError::invalid_input("server_finished", "verify_data mismatch"));
    }
    Ok(())
}

fn to_array_32(v: &Vec<u8>) -> VefasResult<[u8; 32]> {
    if v.len() != 32 { return Err(VefasError::invalid_input("kdf", "length")); }
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    Ok(a)
}

/// Estimate memory usage for the bundle
fn estimate_memory_usage(bundle: &VefasCanonicalBundle) -> usize {
    let mut total = core::mem::size_of::<VefasCanonicalBundle>();

    // Safely access bundle data through accessor methods
    if let Ok(client_hello) = bundle.client_hello() { total += client_hello.len(); }
    if let Ok(server_hello) = bundle.server_hello() { total += server_hello.len(); }
    if let Ok(certificate_msg) = bundle.certificate_msg() { total += certificate_msg.len(); }
    if let Ok(certificate_verify_msg) = bundle.certificate_verify_msg() { total += certificate_verify_msg.len(); }
    if let Ok(server_finished_msg) = bundle.server_finished_msg() { total += server_finished_msg.len(); }
    if let Ok(encrypted_request) = bundle.encrypted_request() { total += encrypted_request.len(); }
    if let Ok(encrypted_response) = bundle.encrypted_response() { total += encrypted_response.len(); }
    total += bundle.domain.len();

    if let Ok(certificate_chain) = bundle.certificate_chain() {
        for cert in &certificate_chain {
            total += cert.len();
        }
    }

    total
}

/// Create an empty bundle for error cases
fn create_empty_bundle() -> VefasCanonicalBundle {
    // Create minimal bundle structure
    use vefas_types::bundle::{BundleStorage, UncompressedBundleData};
    VefasCanonicalBundle {
        version: vefas_types::VEFAS_PROTOCOL_VERSION,
        compression_version: 0,
        storage: BundleStorage::Uncompressed(UncompressedBundleData {
            client_hello: Vec::new(),
            server_hello: Vec::new(),
            certificate_msg: Vec::new(),
            certificate_verify_msg: Vec::new(),
            server_finished_msg: Vec::new(),
            client_private_key: [0u8; 32],
            certificate_chain: Vec::new(),
            encrypted_request: Vec::new(),
            encrypted_response: Vec::new(),
        }),
        domain: String::new(),
        timestamp: 0,
        expected_status: 500,
        verifier_nonce: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};

    #[test]
    fn error_handling_provides_detailed_context() {
        // Test that verification errors provide detailed context
        let bundle = VefasCanonicalBundle {
            version: vefas_types::VEFAS_PROTOCOL_VERSION,
            compression_version: 0, // Uncompressed
            storage: vefas_types::bundle::BundleStorage::Uncompressed(vefas_types::bundle::UncompressedBundleData {
                client_hello: vec![0x01, 0x00, 0x00, 0x01, 0xFF], // Malformed ClientHello
                server_hello: vec![0x02, 0x00, 0x00, 0x01, 0xFF], // Malformed ServerHello
                certificate_msg: Vec::new(),
                certificate_verify_msg: Vec::new(),
                server_finished_msg: Vec::new(),
                client_private_key: [0u8; 32],
                certificate_chain: Vec::new(),
                encrypted_request: {
                    let mut v = vec![23, 3, 3, 0, 16];
                    v.extend_from_slice(&[0u8; 16]); // Minimal valid-looking record
                    v
                },
                encrypted_response: {
                    let mut v = vec![23, 3, 3, 0, 16];
                    v.extend_from_slice(&[0u8; 16]); // Minimal valid-looking record
                    v
                },
            }),
            domain: "example.com".to_string(), // Valid domain
            timestamp: 1234567890,
            expected_status: 200,
            verifier_nonce: [0u8; 32],
        };

        // This should fail during bundle validation or TLS handshake verification
        let result = verify_vefas_bundle(&bundle, 0, None);
        assert!(result.is_err());

        // Verify error provides meaningful context
        let error = result.unwrap_err();
        match error {
            VefasError::InvalidInput { field, reason } => {
                assert!(!field.is_empty());
                assert!(!reason.is_empty());
            },
            VefasError::CryptoError { error_type, message } => {
                assert!(!message.is_empty());
            },
            VefasError::SerializationError { message } => {
                assert!(!message.is_empty());
            },
            _ => {
                // Other error types are also acceptable as long as they're specific
            }
        }
    }

    // NOTE: The verification_failure_returns_empty_claim test has been removed
    // because RISC0 now panics on verification failure to match SP1 security behavior.
    // This ensures consistent security guarantees across both zkVM implementations.
}