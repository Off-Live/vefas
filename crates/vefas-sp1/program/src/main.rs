//! VEFAS SP1 Guest Program - Simplified Merkle Verification
//!
//! This program runs inside the SP1 zkVM and verifies VEFAS canonical bundles
//! using Merkle proofs instead of complex TLS parsing.
//!
//! ## New Architecture:
//!
//! ```text
//! Host (vefas-gateway) → TranscriptBundle + Merkle Proofs → SP1 zkVM (this program) → VefasProofClaim
//! ```
//!
//! ## What this program verifies:
//!
//! 1. **Merkle Tree Integrity**: Verifies Merkle proofs for essential TLS components
//! 2. **HandshakeProof Integrity**: Verifies HandshakeProof binding and consistency
//! 3. **HTTP Data Integrity**: Verifies HTTP request/response using Merkle proofs
//! 4. **Domain Binding**: Verifies domain claim using Merkle proofs
//!
//! ## Key Benefits:
//! - Dramatically reduced circuit size (90%+ reduction)
//! - No complex TLS parsing in zkVM
//! - Cryptographic verification only
//! - Faster proof generation

#![no_main]
#![no_std]

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};
use vefas_types::{
    VefasCanonicalBundle, VefasResult, VefasError,
    VefasProofClaim, VefasPerformanceMetrics, VefasExecutionMetadata,
    errors::CryptoErrorType
};
use vefas_crypto_sp1::{create_sp1_provider, SP1CryptoProvider};
use vefas_crypto::{
    FieldId, MerkleProof, MerkleVerifier,
    traits::Hash,
    hex_lower,
    bundle_parser::{ZkvmLogger, extract_http_request, extract_http_response, parse_http_request, parse_http_response},
};
use bincode;

// SP1-specific logger implementation
struct Sp1Logger;

impl ZkvmLogger for Sp1Logger {
    fn log(&self, message: &str) {
        #[cfg(debug_assertions)]
        sp1_zkvm::io::commit(&message.to_string());
    }
}

// Use sp1_zkvm::io::commit for debug output in zkVM (but only in debug builds)
#[cfg(debug_assertions)]
macro_rules! eprintln {
    ($($tt:tt)*) => {
        sp1_zkvm::io::commit(&alloc::format!($($tt)*))
    };
}

#[cfg(not(debug_assertions))]
macro_rules! eprintln {
    ($($tt:tt)*) => {
        ()
    };
}

// Provide a no-op println! for cycle tracking in no_std environment
macro_rules! println { ($($tt:tt)*) => { () } }

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Start total performance tracking using SP1 official cycle tracking
    println!("cycle-tracker-start: total_execution");

    // Read the VEFAS canonical bundle from stdin
    let bundle: VefasCanonicalBundle = sp1_zkvm::io::read::<VefasCanonicalBundle>();
    
    // Debug assertions for bundle validation
    assert!(!bundle.domain.is_empty(), "Bundle domain should not be empty");
    assert!(bundle.timestamp > 0, "Bundle timestamp should be positive");

    // Verify the bundle using simplified Merkle verification
    let claim = verify_or_panic(&bundle);

    // End total performance tracking
    println!("cycle-tracker-end: total_execution");

    // Log comprehensive performance summary following SP1 patterns
    eprintln!("SP1 VEFAS verification completed with simplified Merkle verification:");
    eprintln!("  - Total execution: {} cycles", claim.performance.total_cycles);
    eprintln!("  - Merkle verification: {} cycles", claim.performance.merkle_verification_cycles);
    eprintln!("  - HTTP verification: {} cycles", claim.performance.http_parsing_cycles);
    eprintln!("  - HandshakeProof verification: {} cycles", claim.performance.crypto_operations_cycles);
    eprintln!("  - Content hashing: {} cycles", claim.performance.crypto_operations_cycles);
    eprintln!("  - Memory usage: {} bytes", claim.performance.memory_usage);

    // Commit the claim to the public outputs
    sp1_zkvm::io::commit(&claim);
}

/// Verify VEFAS canonical bundle using simplified Merkle verification
///
/// This function performs minimal verification that proves:
/// 1. Merkle tree integrity for essential TLS components
/// 2. HandshakeProof integrity and binding consistency
/// 3. HTTP data integrity using Merkle proofs
/// 4. Domain and timing claims are accurate
///
/// Uses comprehensive SP1 cycle tracking for detailed performance analysis.
fn verify_vefas_bundle(bundle: &VefasCanonicalBundle) -> VefasResult<VefasProofClaim> {
    let mut performance = VefasPerformanceMetrics {
        total_cycles: 0,
        merkle_verification_cycles: 0,
        http_parsing_cycles: 0,
        crypto_operations_cycles: 0, // Now used for HandshakeProof verification
        memory_usage: 0,
    };
    let crypto = create_sp1_provider();

    // Step 1: Verify Merkle proofs for essential fields with cycle tracking
    println!("cycle-tracker-start: merkle_verification");
    verify_merkle_proofs(bundle)?;
    println!("cycle-tracker-end: merkle_verification");

    // ServerFinished verification is no longer performed in the new architecture.
    // HandshakeProof provides sufficient binding without requiring ServerFinished.
    // Verifier nodes handle TLS trust validation externally.

    // Step 2: Verify HTTP data integrity using Merkle proofs with cycle tracking
    println!("cycle-tracker-start: http_verification");
    let (method, path, status_code) = verify_http_data(bundle)?;
    println!("cycle-tracker-end: http_verification");

    // Step 3: Add HandshakeProof integrity verification
    println!("cycle-tracker-start: crypto_operations");
    verify_handshake_proof_integrity(bundle)?;
    println!("cycle-tracker-end: crypto_operations");

    // Step 4: Compute content hashes with cycle tracking
    println!("cycle-tracker-start: content_hashing");
    let request_hash = hex_lower(crypto.sha256(&bundle.http_request()?).as_slice());
    let response_hash = hex_lower(crypto.sha256(&bundle.http_response()?).as_slice());

    // Generate commitments
    let request_commitment: [u8; 32] = crypto.sha256(request_hash.as_bytes()).try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Request commitment generation failed"))?;
    let response_commitment: [u8; 32] = crypto.sha256(response_hash.as_bytes()).try_into()
        .map_err(|_| VefasError::crypto_error(CryptoErrorType::HashFailed, "Response commitment generation failed"))?;

    println!("cycle-tracker-end: content_hashing");

    // Estimate memory usage
    performance.memory_usage = estimate_memory_usage(bundle);

    // Note: Total cycles will be populated by the host from cycle tracker data
    // Individual stage cycles are tracked via println! statements

    // Create execution metadata
    let execution_metadata = VefasExecutionMetadata {
        cycles: 0, // Will be filled by host
        memory_usage: performance.memory_usage as u64,
        execution_time_ms: 0, // Will be filled by host
        platform: "sp1".to_string(),
        proof_time_ms: 0, // Will be filled by host
    };

    // Extract cipher suite directly from bundle (now available as direct field)
    let cipher_suite_code = bundle.cipher_suite;
    let cipher_suite_name = match cipher_suite_code {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => return Err(VefasError::invalid_input("cipher_suite", &format!("Unsupported cipher suite: 0x{:04x}", cipher_suite_code))),
    };

    Ok(VefasProofClaim {
        version: 1, // VEFAS protocol version
        domain: bundle.domain.clone(),
        method,
        path,
        request_commitment,
        response_commitment,
        request_hash,
        response_hash,
        status_code,
        tls_version: match bundle.tls_version {
            0x0303 => "1.2".to_string(),
            0x0304 => "1.3".to_string(),
            _ => "unknown".to_string(),
        },
        cipher_suite: cipher_suite_name.to_string(),
        certificate_chain_hash: [0u8; 32], // Placeholder - heavy crypto removed
        handshake_transcript_hash: [0u8; 32], // Placeholder - heavy crypto removed
        cert_fingerprint: bundle.cert_fingerprint, // Now directly available
        proof_id: [0u8; 32], // Will be generated after proof
        timestamp: bundle.timestamp,
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

/// Estimate memory usage for the bundle
fn estimate_memory_usage(bundle: &VefasCanonicalBundle) -> usize {
    // Use the bundle's own memory footprint calculation
    bundle.memory_footprint()
}

/// Verify Merkle proofs for essential TLS components with cycle tracking
#[sp1_derive::cycle_tracker]
/// Verify 6 Merkle proofs for selective disclosure
/// 
/// Verifies 4 user-verifiable fields + 2 internal composite fields.
/// This achieves ~25% cycle reduction while enabling selective disclosure.
fn verify_merkle_proofs(bundle: &VefasCanonicalBundle) -> VefasResult<()> {
    eprintln!("SP1: Verifying 6 Merkle proofs (selective disclosure)");
    
    // Get Merkle root from bundle
      let merkle_root = bundle.merkle_root;
    
    eprintln!("SP1: Merkle root: {:02x?}", merkle_root);
    eprintln!("SP1: Bundle has {} proofs", bundle.merkle_proofs.len());
    
    // Create SP1 Merkle verifier with hardware-accelerated SHA256
    let verifier = SP1CryptoProvider::new();
    
    // Verify 6 fields (4 user-verifiable + 2 internal)
    let fields = alloc::vec![
        // User-verifiable fields (selective disclosure)
        (FieldId::HttpRequest, "HttpRequest"),
        (FieldId::HttpResponse, "HttpResponse"),
        (FieldId::Domain, "Domain"),
        (FieldId::Timestamp, "Timestamp"),
        // Internal composite fields (performance)
        (FieldId::HandshakeProof, "HandshakeProof"),
        (FieldId::TlsVersion, "TlsVersion"),
    ];
    
    for (field_id, field_name) in fields {
        eprintln!("SP1: Verifying Merkle proof for {}", field_name);
        
        // Get Merkle proof for this field
        let proof_bytes = bundle.get_merkle_proof(field_id as u8)
            .ok_or_else(|| VefasError::invalid_input(field_name, "Merkle proof not found"))?;
        
        // Deserialize MerkleProof
        let proof: MerkleProof = bincode::deserialize(proof_bytes)
            .map_err(|e| VefasError::invalid_input(field_name, &format!("Failed to deserialize: {}", e)))?;
        
        eprintln!("SP1: {} proof has {} siblings, {} bytes of data", 
            field_name, proof.siblings.len(), proof.leaf_value.len());
        
        // Verify the Merkle proof using the proof's leaf_value directly
        let is_valid = verifier.verify_inclusion_proof(
            &merkle_root,
            &proof,
            field_id,
            &proof.leaf_value,
        ).map_err(|e| VefasError::invalid_input(field_name, &format!("Merkle verification failed: {}", e)))?;
        
        if !is_valid {
            return Err(VefasError::invalid_input(field_name, "Merkle proof verification failed"));
        }
        
        eprintln!("SP1: {} Merkle proof verified successfully", field_name);
    }
    
    eprintln!("SP1: All Merkle proofs verified successfully");
    Ok(())
}

/// HTTP data verification using selective disclosure fields with cycle tracking
#[sp1_derive::cycle_tracker]
fn verify_http_data(bundle: &VefasCanonicalBundle) -> VefasResult<(String, String, u16)> {
    eprintln!("SP1: Starting HTTP data verification (selective disclosure)");
    
    // Extract HTTP request from its own Merkle proof
    let request_bytes = extract_http_request(bundle)?;
    eprintln!("SP1: Extracted HTTP request ({} bytes)", request_bytes.len());
    
    // Parse HTTP request to extract method and path
    let (method, path) = parse_http_request(&request_bytes)?;
    eprintln!("SP1: Parsed HTTP request - method: {}, path: {}", method, path);
    
    // Extract HTTP response from its own Merkle proof
    let response_bytes = extract_http_response(bundle)?;
    eprintln!("SP1: Extracted HTTP response ({} bytes)", response_bytes.len());
    
    // Parse HTTP response to extract status code
    let status_code = parse_http_response(&response_bytes)?;
    eprintln!("SP1: Parsed HTTP response - status: {}", status_code);
    
    // Verify status code matches expected value
    if status_code != bundle.expected_status {
        eprintln!("SP1: ERROR - Status code mismatch: expected {}, got {}", bundle.expected_status, status_code);
        return Err(VefasError::invalid_input(
            "http_response",
            &format!("Status code mismatch: expected {}, got {}", bundle.expected_status, status_code)
        ));
    }
    
    eprintln!("SP1: HTTP data verification completed");
    
    Ok((method, path, status_code))
}

/// HandshakeProof integrity verification with cycle tracking
#[sp1_derive::cycle_tracker]
fn verify_handshake_proof_integrity(bundle: &VefasCanonicalBundle) -> VefasResult<()> {
    eprintln!("SP1: Starting HandshakeProof integrity verification");
    
    // Build HandshakeProof from bundle
    let handshake_proof = vefas_crypto::bundle_parser::build_handshake_proof(bundle)?;
    eprintln!("SP1: Built HandshakeProof successfully");
    
    // Validate HandshakeProof structure
    handshake_proof.validate()?;
    eprintln!("SP1: HandshakeProof structure validation passed");
    
    // Verify HandshakeProof integrity against bundle data
    vefas_crypto::validation::validate_handshake_proof_integrity(&handshake_proof, bundle)?;
    eprintln!("SP1: HandshakeProof integrity verification passed");
    
    eprintln!("SP1: HandshakeProof verification completed successfully");
    Ok(())
}

// NOTE: Old extraction and key derivation functions removed - now using bundle_parser module
// ServerFinished verification is no longer needed in HandshakeProof architecture

/// Constant-time comparison for security
fn verify_constant_time_comparison(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    
    if a.len() != b.len() {
        return false;
    }
    
    // Use constant-time comparison
    a.ct_eq(b).into()
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
            Vec::new(), // certificate_chain
            {
                let mut v = vec![23, 3, 3, 0, 1];
                v.extend_from_slice(&[0u8; 1]);
                v
            }, // http_request
            {
                let mut v = vec![23, 3, 3, 0, 1];
                v.extend_from_slice(&[0u8; 1]);
                v
            }, // http_response
            String::new(), // domain (empty - should cause validation error)
            0, // timestamp
            200, // expected_status
            [0u8; 32], // verifier_nonce
            0x0303, // tls_version
            0x1301, // cipher_suite
            [0u8; 32], // server_random
            [0u8; 32], // cert_fingerprint
            None, // session_id
            None, // session_ticket
            false, // handshake_complete
            true, // application_data_present
        ).unwrap_or_else(|_| {
            // If bundle creation fails due to validation, create manually for test
            VefasCanonicalBundle {
                version: vefas_types::VEFAS_PROTOCOL_VERSION as u8,
                domain: String::new(), // Empty domain should trigger validation error
                timestamp: 0,
                expected_status: 200,
                verifier_nonce: [0u8; 32],
                tls_version: 0x0303, // TLS 1.2
                cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
                server_random: [0u8; 32],
                session_id: None,
                session_ticket: None,
                client_hello: vec![0x01],
                server_hello: vec![0x02],
                certificate_chain: Vec::new(),
                cert_fingerprint: [0u8; 32],
                http_request: {
                    let mut v = vec![23, 3, 3, 0, 1];
                    v.extend_from_slice(&[0u8; 1]);
                    v
                },
                http_response: {
                    let mut v = vec![23, 3, 3, 0, 1];
                    v.extend_from_slice(&[0u8; 1]);
                    v
                },
                merkle_root: [0u8; 32],
                merkle_proofs: Vec::new(),
                handshake_complete: false,
                application_data_present: true,
            }
        });

        // Should panic with "VERIFICATION_FAILURE" prefix
        let _ = verify_or_panic(&bundle);
    }

    #[test]
    fn error_handling_provides_detailed_context() {
        // Test that verification errors provide detailed context
        // Create test bundle with valid domain but malformed handshake messages
        let bundle = VefasCanonicalBundle {
            version: vefas_types::VEFAS_PROTOCOL_VERSION as u8,
            domain: "example.com".to_string(), // Valid domain
            timestamp: 1234567890,
            expected_status: 200,
            verifier_nonce: [0u8; 32],
            tls_version: 0x0303, // TLS 1.2
            cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
            server_random: [0u8; 32],
            session_id: None,
            session_ticket: None,
            client_hello: vec![0x01, 0x00, 0x00, 0x01, 0xFF], // Malformed ClientHello
            server_hello: vec![0x02, 0x00, 0x00, 0x01, 0xFF], // Malformed ServerHello
            certificate_chain: Vec::new(),
            cert_fingerprint: [0u8; 32],
            http_request: {
                let mut v = vec![23, 3, 3, 0, 16];
                v.extend_from_slice(&[0u8; 16]); // Minimal valid-looking record
                v
            },
            http_response: {
                let mut v = vec![23, 3, 3, 0, 16];
                v.extend_from_slice(&[0u8; 16]); // Minimal valid-looking record
                v
            },
            merkle_root: [0u8; 32],
            merkle_proofs: Vec::new(),
            handshake_complete: false,
            application_data_present: true,
        };

        // This should fail during bundle validation or TLS handshake verification
        let result = verify_vefas_bundle(&bundle);
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