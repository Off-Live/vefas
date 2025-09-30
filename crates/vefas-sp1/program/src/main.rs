//! VEFAS SP1 Guest Program
//!
//! This program runs inside the SP1 zkVM and verifies VEFAS canonical bundles.
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
//! Host (vefas-core) → VefasCanonicalBundle → SP1 zkVM (this program) → VefasProofClaim
//! ```
//!
//! This follows the host-rustls + guest-verifier pattern where:
//! - Host captures real TLS session data using production rustls
//! - Guest verifies the captured data cryptographically in zkVM
//! - Result is a zero-knowledge proof of the TLS session
//!
//! ## Performance Tracking:
//!
//! This program implements comprehensive SP1 cycle tracking following the official
//! SP1 documentation patterns. Each verification stage is tracked separately:
//! - Bundle decompression and validation
//! - TLS handshake parsing and validation
//! - Certificate chain validation
//! - Cryptographic operations (ECDHE, HKDF, AES-GCM)
//! - HTTP extraction and parsing

#![no_main]
#![no_std]

extern crate alloc;
use alloc::{string::ToString, vec::Vec};
use vefas_types::{
    VefasCanonicalBundle, VefasResult, VefasError, tls::CipherSuite,
    compression::CompressionStats, VefasProofClaim, VefasPerformanceMetrics, VefasExecutionMetadata,
    errors::CryptoErrorType
};
use vefas_crypto_sp1::create_sp1_provider;
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

// Provide a no-op eprintln! for no_std environment to satisfy macro expansion
macro_rules! eprintln { ($($tt:tt)*) => { () } }

// Provide a no-op println! for cycle tracking in no_std environment
macro_rules! println { ($($tt:tt)*) => { () } }


sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Start total performance tracking using SP1 official cycle tracking
    println!("cycle-tracker-start: total_execution");

    // Read the VEFAS canonical bundle from stdin
    let bundle: VefasCanonicalBundle = sp1_zkvm::io::read::<VefasCanonicalBundle>();

    // Verify the bundle and generate claim with comprehensive performance tracking
    let claim = verify_or_panic(&bundle);

    // End total performance tracking
    println!("cycle-tracker-end: total_execution");

    // Log comprehensive performance summary following SP1 patterns
    eprintln!("SP1 VEFAS verification completed with comprehensive cycle tracking:");
    eprintln!("  - Total execution: {} cycles", claim.performance.total_cycles);
    eprintln!("  - Bundle decompression: {} cycles", claim.performance.decompression_cycles);
    eprintln!("  - Bundle validation: {} cycles", claim.performance.validation_cycles);
    eprintln!("  - TLS handshake: {} cycles", claim.performance.handshake_cycles);
    eprintln!("  - Certificate validation: {} cycles", claim.performance.certificate_validation_cycles);
    eprintln!("  - Key derivation: {} cycles", claim.performance.key_derivation_cycles);
    eprintln!("  - Application decryption: {} cycles", claim.performance.decryption_cycles);
    eprintln!("  - HTTP parsing: {} cycles", claim.performance.http_parsing_cycles);
    eprintln!("  - Crypto operations: {} cycles", claim.performance.crypto_operations_cycles);
    eprintln!("  - Memory usage: {} bytes", claim.performance.memory_usage);

    if let Some(_ratio) = claim.performance.compression_ratio {
        eprintln!("  - Compression ratio: {:.1}%", _ratio);
        eprintln!("  - Original size: {} bytes", claim.performance.original_bundle_size.unwrap_or(0));
        eprintln!("  - Decompressed size: {} bytes", claim.performance.decompressed_bundle_size.unwrap_or(0));
    }

    // Commit the claim to the public outputs
    sp1_zkvm::io::commit(&claim);
}

/// Verify VEFAS canonical bundle and extract proof claim
///
/// This function performs the core verification logic that proves:
/// 1. The TLS handshake is cryptographically valid
/// 2. The HTTP data was actually exchanged over the verified TLS connection
/// 3. The domain, timing, and content claims are accurate
///
/// Uses comprehensive SP1 cycle tracking for detailed performance analysis.
fn verify_vefas_bundle(bundle: &VefasCanonicalBundle) -> VefasResult<VefasProofClaim> {
    let mut performance = VefasPerformanceMetrics {
        total_cycles: 0,
        decompression_cycles: 0,
        validation_cycles: 0,
        handshake_cycles: 0,
        certificate_validation_cycles: 0,
        key_derivation_cycles: 0,
        decryption_cycles: 0,
        http_parsing_cycles: 0,
        crypto_operations_cycles: 0,
        memory_usage: 0,
        compression_ratio: None,
        original_bundle_size: None,
        decompressed_bundle_size: None,
    };
    let crypto = create_sp1_provider();

    // Step 1: Handle bundle decompression with cycle tracking
    println!("cycle-tracker-start: bundle_decompression");
    let (decompressed_bundle, compression_stats) = decompress_bundle_if_needed(bundle)?;
    println!("cycle-tracker-end: bundle_decompression");

    // Update compression statistics
    if let Some(stats) = compression_stats {
        performance.compression_ratio = Some(stats.compression_ratio());
        performance.original_bundle_size = Some(stats.compressed_size);
        performance.decompressed_bundle_size = Some(stats.original_size);
    }

    // Step 2: Validate bundle structure with cycle tracking
    println!("cycle-tracker-start: bundle_validation");
    decompressed_bundle.validate()?;
    println!("cycle-tracker-end: bundle_validation");

    // Step 3: Verify TLS 1.3 handshake messages with cycle tracking
    println!("cycle-tracker-start: tls_handshake_validation");
    verify_tls_handshake(&decompressed_bundle, &crypto)?;
    println!("cycle-tracker-end: tls_handshake_validation");

    // Step 4: Derive session keys from handshake with cycle tracking
    println!("cycle-tracker-start: key_derivation");
    let session_keys = derive_session_keys(&decompressed_bundle, &crypto)?;
    println!("cycle-tracker-end: key_derivation");

    // Step 5: Decrypt application data to extract HTTP content with cycle tracking
    println!("cycle-tracker-start: application_data_decryption");
    let http_data = decrypt_application_data(&decompressed_bundle, &session_keys, &crypto)?;
    println!("cycle-tracker-end: application_data_decryption");

    // Step 6: Parse and validate HTTP request/response with cycle tracking
    println!("cycle-tracker-start: http_parsing");
    let (method, path, status_code) = parse_http_data(&http_data)?;
    println!("cycle-tracker-end: http_parsing");

    // Step 7: Compute content hashes and additional claims with cycle tracking
    println!("cycle-tracker-start: crypto_operations");
    let request_hash = hex_lower(crypto.sha256(&http_data.request).as_slice());
    let response_hash = hex_lower(crypto.sha256(&http_data.response).as_slice());

    // Additional claims: TLS info and transcript/cert hashes
    let suite_id = parse_server_cipher_suite(&decompressed_bundle.server_hello()?)?;
    let cipher_suite = cipher_suite_name(suite_id).to_string();
    let tls_version = "1.3".to_string(); // TLS 1.3 only

    let mut cert_concat: Vec<u8> = Vec::new();
    for cert in &decompressed_bundle.certificate_chain()? {
        cert_concat.extend_from_slice(cert);
    }
    let certificate_chain_hash_bytes = crypto.sha256(&cert_concat);
    let certificate_chain_hash: [u8; 32] = certificate_chain_hash_bytes.try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Certificate chain hash conversion failed"))?;

    let client_hello = decompressed_bundle.client_hello()?;
    let server_hello = decompressed_bundle.server_hello()?;
    let certificate_msg = decompressed_bundle.certificate_msg()?;
    let certificate_verify_msg = decompressed_bundle.certificate_verify_msg()?;

    let mut hs_msgs: Vec<&[u8]> = Vec::new();
    hs_msgs.push(&client_hello);
    hs_msgs.push(&server_hello);
    if !certificate_msg.is_empty() { hs_msgs.push(&certificate_msg); }
    if !certificate_verify_msg.is_empty() { hs_msgs.push(&certificate_verify_msg); }

    let handshake_transcript_hash_bytes = compute_transcript_hash(&crypto, &hs_msgs, CipherSuite::Aes128GcmSha256);
    let handshake_transcript_hash: [u8; 32] = handshake_transcript_hash_bytes.try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Handshake transcript hash conversion failed"))?;
    println!("cycle-tracker-end: crypto_operations");

    // Estimate memory usage (works with both compressed and decompressed bundles)
    performance.memory_usage = estimate_memory_usage(&decompressed_bundle);

    // Note: Total cycles will be populated by the host from cycle tracker data
    // Individual stage cycles are tracked via println! statements

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
        platform: "sp1".to_string(),
        proof_time_ms: 0, // Will be filled by host
    };

    Ok(VefasProofClaim {
        version: 1, // VEFAS protocol version
        domain: decompressed_bundle.domain.clone(),
        method,
        path,
        request_commitment,
        response_commitment,
        request_hash,
        response_hash,
        status_code,
        tls_version,
        cipher_suite,
        certificate_chain_hash,
        handshake_transcript_hash,
        timestamp: decompressed_bundle.timestamp,
        performance,
        execution_metadata,
    })
}

/// Verify bundle and panic on failure to ensure proving aborts on invalid inputs
///
/// This function ensures that verification failures result in explicit zkVM abort
/// with detailed error information for proper debugging and security auditing.
fn verify_or_panic(bundle: &VefasCanonicalBundle) -> VefasProofClaim {
    match verify_vefas_bundle(bundle) {
        Ok(claim) => {
            // Log successful verification for audit trail
            eprintln!("VEFAS SP1 guest verification succeeded");
            claim
        },
        Err(e) => {
            // Log detailed error information before panic
            eprintln!("VEFAS SP1 guest verification failed with error: {:?}", e);
            eprintln!("Error category: {}", e.category());

            // Ensure zkVM execution fails with clear verification failure
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
    }
}

/// Handle bundle decompression if needed, with cycle tracking
/// Returns the decompressed bundle and optional compression statistics
fn decompress_bundle_if_needed(bundle: &VefasCanonicalBundle) -> VefasResult<(VefasCanonicalBundle, Option<CompressionStats>)> {
    if bundle.is_compressed() {
        let mut decompressed_bundle = bundle.clone();
        let compression_stats = bundle.compression_stats().cloned();
        decompressed_bundle.decompress()?;
        Ok((decompressed_bundle, compression_stats))
    } else {
        Ok((bundle.clone(), None))
    }
}

/// Verify TLS 1.3 handshake cryptographic validity with cycle tracking
#[sp1_derive::cycle_tracker]
fn verify_tls_handshake(bundle: &VefasCanonicalBundle, crypto: &vefas_crypto_sp1::SP1CryptoProvider) -> VefasResult<()> {
    // Step 1: Verify ClientHello message structure
    println!("cycle-tracker-start: client_hello_validation");
    validate_client_hello(&bundle.client_hello()?)?;
    println!("cycle-tracker-end: client_hello_validation");

    // Step 2: Verify ServerHello message structure and cipher suite
    println!("cycle-tracker-start: server_hello_validation");
    validate_server_hello(&bundle.server_hello()?)?;
    let suite = parse_server_cipher_suite(&bundle.server_hello()?)?;
    if suite != 0x1301 { // TLS_AES_128_GCM_SHA256
        return Err(VefasError::invalid_input("server_hello", "Unsupported cipher suite (only TLS_AES_128_GCM_SHA256)"));
    }
    println!("cycle-tracker-end: server_hello_validation");

    // Step 3: Verify Certificate message and chain
    println!("cycle-tracker-start: certificate_validation");
    validate_certificate_message(&bundle.certificate_msg()?, &bundle.certificate_chain()?)?;
    println!("cycle-tracker-end: certificate_validation");

    // Step 4: Enforce leaf certificate domain binding
    println!("cycle-tracker-start: domain_binding_validation");
    validate_certificate_domain_binding(&bundle.certificate_chain()?, &bundle.domain)?;
    println!("cycle-tracker-end: domain_binding_validation");

    // Step 5: Verify CertificateVerify message
    println!("cycle-tracker-start: certificate_verify_validation");
    validate_certificate_verify(&bundle.certificate_verify_msg()?)?;
    println!("cycle-tracker-end: certificate_verify_validation");

    // Step 6: Verify Finished using derived handshake secrets
    println!("cycle-tracker-start: server_finished_validation");
    let result = verify_server_finished(bundle, crypto);
    println!("cycle-tracker-end: server_finished_validation");
    result
}

/// Session keys derived from TLS handshake
struct SessionKeys {
    client_application_traffic_secret: [u8; 32],
    server_application_traffic_secret: [u8; 32],
}

/// Derive TLS 1.3 session keys from handshake data with cycle tracking
#[sp1_derive::cycle_tracker]
fn derive_session_keys(bundle: &VefasCanonicalBundle, crypto: &vefas_crypto_sp1::SP1CryptoProvider) -> VefasResult<SessionKeys> {
    // Step 1: Parse server key share
    println!("cycle-tracker-start: key_share_parsing");
    let key_share = parse_server_hello_key_share(&bundle.server_hello()?)?;
    println!("cycle-tracker-end: key_share_parsing");

    // Step 2: Compute shared secret (ECDHE)
    println!("cycle-tracker-start: ecdhe_shared_secret");
    let shared = match key_share.group {
        0x001D => { // x25519
            if key_share.key_exchange.len() != 32 {
                return Err(VefasError::invalid_input("server_hello", "Invalid X25519 key"));
            }
            let mut pub_arr = [0u8; 32];
            pub_arr.copy_from_slice(&key_share.key_exchange);
            crypto.x25519_compute_shared_secret(&bundle.client_private_key()?, &pub_arr)?
        }
        0x0017 => { // secp256r1
            if key_share.key_exchange.len() != 65 {
                return Err(VefasError::invalid_input("server_hello", "Invalid P-256 key"));
            }
            let mut pub_arr = [0u8; 65];
            pub_arr.copy_from_slice(&key_share.key_exchange);
            crypto.p256_compute_shared_secret(&bundle.client_private_key()?, &pub_arr)?
        }
        _ => return Err(VefasError::invalid_input("server_hello", "Unsupported key_share group")),
    };
    println!("cycle-tracker-end: ecdhe_shared_secret");

    // Build application transcript (ClientHello, ServerHello, [Certificate], [CertificateVerify])
    let client_hello_data = bundle.client_hello()?;
    let server_hello_data = bundle.server_hello()?;
    let certificate_msg_data = bundle.certificate_msg()?;
    let certificate_verify_msg_data = bundle.certificate_verify_msg()?;

    let mut transcript: Vec<u8> = Vec::new();
    transcript.extend_from_slice(&client_hello_data);
    transcript.extend_from_slice(&server_hello_data);
    if !certificate_msg_data.is_empty() {
        transcript.extend_from_slice(&certificate_msg_data);
    }
    if !certificate_verify_msg_data.is_empty() {
        transcript.extend_from_slice(&certificate_verify_msg_data);
    }

    // Step 3: Derive application traffic secrets using HKDF
    println!("cycle-tracker-start: hkdf_key_derivation");
    let keys = verify_session_keys_common(
        crypto,
        &transcript,
        &shared,
        CipherSuite::Aes128GcmSha256,
    )?;
    println!("cycle-tracker-end: hkdf_key_derivation");

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

/// Decrypt TLS application data to extract HTTP content with cycle tracking
#[sp1_derive::cycle_tracker]
fn decrypt_application_data(bundle: &VefasCanonicalBundle, keys: &SessionKeys, crypto: &vefas_crypto_sp1::SP1CryptoProvider) -> VefasResult<HttpData> {
    // Only TLS_AES_128_GCM_SHA256 supported
    let suite = parse_server_cipher_suite(&bundle.server_hello()?)?;
    if suite != 0x1301 {
        return Err(VefasError::invalid_input("server_hello", "Unsupported cipher suite"));
    }

    // Step 1: Decrypt client request (AES-GCM)
    println!("cycle-tracker-start: aes_gcm_request_decryption");
    let request = decrypt_application_record(
        crypto,
        &bundle.encrypted_request()?,
        &keys.client_application_traffic_secret,
        0
    )?;
    println!("cycle-tracker-end: aes_gcm_request_decryption");

    // Step 2: Decrypt server response (AES-GCM)
    println!("cycle-tracker-start: aes_gcm_response_decryption");
    let response = decrypt_application_record(
        crypto,
        &bundle.encrypted_response()?,
        &keys.server_application_traffic_secret,
        0
    )?;
    println!("cycle-tracker-end: aes_gcm_response_decryption");

    Ok(HttpData::new(request, response))
}

/// Verify ServerFinished message using transcript hash with cycle tracking
#[sp1_derive::cycle_tracker]
fn verify_server_finished(bundle: &VefasCanonicalBundle, crypto: &vefas_crypto_sp1::SP1CryptoProvider) -> VefasResult<()> {
    // Recompute handshake secret and server handshake traffic secret
    let key_share = parse_server_hello_key_share(&bundle.server_hello()?)?;

    let shared = match key_share.group {
        0x001D => { // X25519
            if key_share.key_exchange.len() != 32 {
                return Err(VefasError::invalid_input("server_hello", "Invalid X25519 key length"));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&key_share.key_exchange);
            crypto.x25519_compute_shared_secret(&bundle.client_private_key()?, &pk)?
        }
        0x0017 => { // P-256
            if key_share.key_exchange.len() != 65 {
                return Err(VefasError::invalid_input("server_hello", "Invalid P-256 key length"));
            }
            let mut pk = [0u8; 65];
            pk.copy_from_slice(&key_share.key_exchange);
            crypto.p256_compute_shared_secret(&bundle.client_private_key()?, &pk)?
        }
        _ => return Err(VefasError::invalid_input("server_hello", "Unsupported key_share group")),
    };

    let zeros = [0u8; 32];
    let early_secret = crypto.hkdf_extract(&zeros, &[]);
    let derived = hkdf_expand_label(crypto, &early_secret, b"derived", &[], 32)?;
    let handshake_secret = crypto.hkdf_extract(&to_array_32(&derived)?, &shared);

    // Transcript hash up to (but excluding) Finished
    let client_hello_fin = bundle.client_hello()?;
    let server_hello_fin = bundle.server_hello()?;
    let certificate_msg_fin = bundle.certificate_msg()?;
    let certificate_verify_msg_fin = bundle.certificate_verify_msg()?;

    let mut msgs: Vec<&[u8]> = Vec::new();
    msgs.push(&client_hello_fin);
    msgs.push(&server_hello_fin);
    if !certificate_msg_fin.is_empty() { msgs.push(&certificate_msg_fin); }
    if !certificate_verify_msg_fin.is_empty() { msgs.push(&certificate_verify_msg_fin); }
    let th = compute_transcript_hash(crypto, &msgs, CipherSuite::Aes128GcmSha256);

    // Derive server handshake traffic secret and finished_key
    let s_hs = hkdf_expand_label(crypto, &handshake_secret, b"s hs traffic", &th, 32)?;
    let s_hs_arr = to_array_32(&s_hs)?;
    let finished_key = hkdf_expand_label(crypto, &s_hs_arr, b"finished", &[], 32)?;
    let finished_key_arr = to_array_32(&finished_key)?;

    // Expected verify_data
    let verify_expected = crypto.hmac_sha256(&finished_key_arr, &th);

    // Parse Finished handshake
    let server_finished = bundle.server_finished_msg()?;
    validate_finished_message(&server_finished)?;
    let fin = &server_finished;
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

/// Estimate memory usage for the bundle (works with both compressed and uncompressed)
fn estimate_memory_usage(bundle: &VefasCanonicalBundle) -> usize {
    // Use the bundle's own memory footprint calculation which handles compression
    bundle.memory_footprint()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};

    #[test]
    #[should_panic(expected = "VERIFICATION_FAILURE")]
    fn verify_or_panic_panics_with_verification_failure_prefix() {
        // Construct a minimally invalid bundle (empty domain triggers validation error)
        // Create test bundle using the VefasCanonicalBundle constructor
        let bundle = VefasCanonicalBundle::new(
            vec![0x01], // client_hello
            vec![0x02], // server_hello
            Vec::new(), // certificate_msg
            Vec::new(), // certificate_verify_msg
            Vec::new(), // server_finished_msg
            [0u8; 32], // client_private_key
            Vec::new(), // certificate_chain
            {
                let mut v = vec![23, 3, 3, 0, 1];
                v.extend_from_slice(&[0u8; 1]);
                v
            }, // encrypted_request
            {
                let mut v = vec![23, 3, 3, 0, 1];
                v.extend_from_slice(&[0u8; 1]);
                v
            }, // encrypted_response
            String::new(), // domain (empty - should cause validation error)
            0, // timestamp
            200, // expected_status
            [0u8; 32], // verifier_nonce
        ).unwrap_or_else(|_| {
            // If bundle creation fails due to validation, create manually for test
            use vefas_types::bundle::{VefasCanonicalBundle, BundleStorage, UncompressedBundleData};
            VefasCanonicalBundle {
                version: vefas_types::VEFAS_PROTOCOL_VERSION,
                compression_version: 0,
                storage: BundleStorage::Uncompressed(UncompressedBundleData {
                    client_hello: vec![0x01],
                    server_hello: vec![0x02],
                    certificate_msg: Vec::new(),
                    certificate_verify_msg: Vec::new(),
                    server_finished_msg: Vec::new(),
                    client_private_key: [0u8; 32],
                    certificate_chain: Vec::new(),
                    encrypted_request: {
                        let mut v = vec![23, 3, 3, 0, 1];
                        v.extend_from_slice(&[0u8; 1]);
                        v
                    },
                    encrypted_response: {
                        let mut v = vec![23, 3, 3, 0, 1];
                        v.extend_from_slice(&[0u8; 1]);
                        v
                    },
                }),
                domain: String::new(), // Empty domain should trigger validation error
                timestamp: 0,
                expected_status: 200,
                verifier_nonce: [0u8; 32],
            }
        });

        // Should panic with "VERIFICATION_FAILURE" prefix
        let _ = verify_or_panic(&bundle, 0);
    }

    #[test]
    fn error_handling_provides_detailed_context() {
        // Test that verification errors provide detailed context
        // Create test bundle with valid domain but malformed handshake messages
        use vefas_types::bundle::{VefasCanonicalBundle, BundleStorage, UncompressedBundleData};
        let bundle = VefasCanonicalBundle {
            version: vefas_types::VEFAS_PROTOCOL_VERSION,
            compression_version: 0,
            storage: BundleStorage::Uncompressed(UncompressedBundleData {
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
        let result = verify_vefas_bundle(&bundle, 0);
        assert!(result.is_err());

        // Verify error provides meaningful context
        let error = result.unwrap_err();
        match error {
            VefasError::InvalidInput { field, reason } => {
                assert!(!field.is_empty());
                assert!(!reason.is_empty());
            },
            VefasError::CryptoError { error_type: _, message } => {
                assert!(!message.is_empty());
            },
            VefasError::TlsError { error_type: _, message } => {
                assert!(!message.is_empty());
            },
            _ => {
                // Other error types are also acceptable as long as they're specific
            }
        }
    }
}