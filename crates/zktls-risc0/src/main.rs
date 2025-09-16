//! RISC0 zkTLS example
//!
//! This example demonstrates how to use the unified RISC0 zkTLS implementation
//! to verify TLS sessions and generate zero-knowledge proofs.

use zktls_risc0::RISC0ZkTlsProver;
use zktls_zkvm::types::*;
use zktls_risc0_methods::ZKTL_VERIFY_ID;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("RISC0 zkTLS Verification Example");
    println!("=================================");

    // Create a mock TLS session for demonstration
    let mock_input = create_mock_tls_session();

    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    println!("Generating proof for TLS session verification...");

    // Generate a proof for the TLS session
    match prover.generate_proof(&mock_input) {
        Ok(proof_wrapper) => {
            println!("✓ Proof generated successfully!");
            println!("  Domain: {}", proof_wrapper.claim.domain);
            println!("  Status Code: {}", proof_wrapper.claim.status_code);
            println!("  TLS Version: {}", proof_wrapper.claim.tls_version);
            println!("  Cipher Suite: {}", proof_wrapper.claim.cipher_suite);
            println!("  Execution Cycles: {}", proof_wrapper.execution_metadata.cycles);
            println!("  Execution Time: {} ms", proof_wrapper.execution_metadata.execution_time_ms);
            println!("  Proof Time: {} ms", proof_wrapper.execution_metadata.proof_time_ms);

            // Verify the generated proof
            println!("\nVerifying the generated proof...");
            match prover.verify_proof(&proof_wrapper) {
                Ok(verified_claim) => {
                    println!("✓ Proof verification successful!");
                    println!("  Verified Domain: {}", verified_claim.domain);
                    println!("  Verified Status: {}", verified_claim.status_code);
                    
                    // Verify using the method ID (following RISC0 examples pattern)
                    println!("\nVerifying with method ID...");
                    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&proof_wrapper.receipt)
                        .expect("Failed to deserialize receipt");
                    
                    match receipt.verify(ZKTL_VERIFY_ID) {
                        Ok(_) => println!("✓ Method ID verification successful!"),
                        Err(e) => println!("✗ Method ID verification failed: {}", e),
                    }
                }
                Err(e) => {
                    println!("✗ Proof verification failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Proof generation failed: {}", e);
        }
    }

    // Also demonstrate execution without proof generation
    println!("\nExecuting without proof generation (for testing)...");
    match prover.execute(&mock_input) {
        Ok(result) => {
            if result.success {
                println!("✓ Execution successful!");
                if let Some(claim) = result.claim {
                    println!("  Domain: {}", claim.domain);
                    println!("  Status Code: {}", claim.status_code);
                }
            } else {
                println!("✗ Execution failed: {:?}", result.error);
            }
        }
        Err(e) => {
            println!("✗ Execution error: {}", e);
        }
    }
}

/// Create a mock TLS session for demonstration purposes
fn create_mock_tls_session() -> ZkTlsInput {
    ZkTlsInput {
        domain: "example.com".to_string(),
        handshake_transcript: vec![
            0x16, 0x03, 0x03, 0x00, 0x4a, // TLS 1.3 handshake header
            0x01, 0x00, 0x00, 0x46, // ClientHello
            // ... more handshake data would go here
        ],
        certificates: vec![
            vec![
                0x30, 0x82, 0x02, 0x22, // X.509 certificate DER encoding
                // ... certificate data would go here
            ],
        ],
        http_request: vec![
            0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, // "GET / HTTP/1.1\r\n"
            0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, // "Host: example.com\r\n"
            0x0d, 0x0a, // "\r\n"
        ],
        http_response: vec![
            0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, // "HTTP/1.1 200 OK\r\n"
            0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x31, 0x33, 0x0d, 0x0a, // "Content-Length: 13\r\n"
            0x0d, 0x0a, // "\r\n"
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, // "Hello, World!"
        ],
        timestamp: 1678886400, // Example timestamp
        metadata: ZkTlsMetadata {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            session_id: None,
            extensions: Vec::new(),
        },
    }
}
