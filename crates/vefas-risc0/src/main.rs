//! VEFAS RISC0 example
//!
//! This example demonstrates how to use the VEFAS RISC0 implementation
//! to verify TLS sessions and generate zero-knowledge proofs.

use vefas_risc0::VefasRisc0Prover;
use vefas_risc0_methods::VEFAS_RISC0_GUEST_ID as GUEST_ID;
use vefas_types::VefasCanonicalBundle;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("VEFAS RISC0 Verification Example");
    println!("=================================");

    // Create a mock VEFAS canonical bundle for demonstration
    let mock_bundle = create_mock_bundle();

    // Initialize the RISC0 prover
    let prover = VefasRisc0Prover::new();

    println!("Generating proof for VEFAS canonical bundle verification...");

    // Generate a proof for the VEFAS bundle
    match prover.generate_zk_proof(&mock_bundle) {
        Ok(proof) => {
            println!("✓ Proof generated successfully!");
            println!("  Domain: {}", proof.claim.domain);
            println!("  Method: {}", proof.claim.method);
            println!("  Path: {}", proof.claim.path);
            println!("  Status Code: {}", proof.claim.status_code);
            println!("  Execution Cycles: {}", proof.execution_metadata.cycles);
            println!(
                "  Execution Time: {} ms",
                proof.execution_metadata.execution_time_ms
            );
            println!(
                "  Proof Time: {} ms",
                proof.execution_metadata.proof_time_ms
            );

            // Verify the generated proof
            println!("\nVerifying the generated proof...");
            match prover.verify_proof(&proof) {
                Ok(verified_claim) => {
                    println!("✓ Proof verification successful!");
                    println!("  Verified Domain: {}", verified_claim.domain);
                    println!("  Verified Method: {}", verified_claim.method);
                    println!("  Verified Status: {}", verified_claim.status_code);

                    // Verify using the method ID (following RISC0 examples pattern)
                    println!("\nVerifying with method ID...");
                    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&proof.receipt_data)
                        .expect("Failed to deserialize receipt");

                    match receipt.verify(GUEST_ID) {
                        Ok(_) => println!("✓ Method ID verification successful!"),
                        Err(e) => println!("✗ Method ID verification failed: {}", e),
                    }
                }
                Err(e) => {
                    println!("✗ Proof verification failed: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Proof generation failed: {:?}", e);
        }
    }
}

/// Create a mock VEFAS canonical bundle for demonstration purposes
fn create_mock_bundle() -> VefasCanonicalBundle {
    VefasCanonicalBundle::new(
        vec![0x16, 0x03, 0x03, 0x00, 0x30], // Mock ClientHello
        vec![0x16, 0x03, 0x03, 0x00, 0x30], // Mock ServerHello
        vec![vec![0x30, 0x82, 0x01, 0x00]], // Mock certificate chain
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\n\r\nHello World".to_vec(),
        "example.com".to_string(),
        1678886400,
        200,
        [1u8; 32],
        0x0303, // tls_version (TLS 1.2)
        0x1301, // cipher_suite (TLS_AES_128_GCM_SHA256)
        [42u8; 32], // server_random
        [0u8; 32], // cert_fingerprint
        None, // session_id
        None, // session_ticket
        true, // handshake_complete
        true, // application_data_present
    )
    .expect("Failed to create mock bundle")
}
