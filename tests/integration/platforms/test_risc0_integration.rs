//! RISC0 integration tests
//! 
//! This module contains integration tests for the RISC0 zkVM prover and verifier.
//! It ensures that the RISC0 host-side implementation correctly interacts with the
//! RISC0 guest program and produces valid proofs.

use zktls_risc0::{RISC0ZkTlsProver, RISC0ProofWrapper};
use zktls_zkvm::types::*;

/// Helper function to create a mock ZkTlsInput for testing
fn create_mock_zktls_input() -> ZkTlsInput {
    ZkTlsInput {
        domain: "example.com".to_string(),
        handshake_transcript: vec![0x01, 0x02, 0x03],
        certificates: vec![vec![0x04, 0x05], vec![0x06, 0x07]],
        http_request: vec![0x08, 0x09],
        http_response: vec![0x0a, 0x0b],
        timestamp: 1678886400, // Example timestamp
        metadata: ZkTlsMetadata {
            tls_version: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            session_id: None,
            extensions: vec![],
        },
    }
}

#[test]
fn test_risc0_prover_initialization() {
    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    // Assert that the prover was created successfully (no panic)
    assert!(true, "RISC0ZkTlsProver should initialize without panicking");
}

#[test]
fn test_risc0_proof_generation_and_verification_mock_input() {
    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    // Create a mock input
    let input = create_mock_zktls_input();

    // Generate the proof
    let result = prover.generate_proof(&input);

    // Assert that proof generation was successful
    assert!(result.is_ok(), "Proof generation failed: {:?}", result.err());
    let proof_wrapper = result.unwrap();

    // Assert that the claim is present and has expected values
    assert!(proof_wrapper.claim.domain == input.domain);
    assert!(proof_wrapper.execution_metadata.platform == "risc0");

    // Verify the generated proof
    let verification_result = prover.verify_proof(&proof_wrapper);

    // Assert that proof verification was successful
    assert!(
        verification_result.is_ok(),
        "Proof verification failed: {:?}",
        verification_result.err()
    );
    let verified_claim = verification_result.unwrap();

    // Assert that the verified claim matches the generated claim
    assert_eq!(proof_wrapper.claim.domain, verified_claim.domain);
    assert_eq!(
        proof_wrapper.claim.request_commitment,
        verified_claim.request_commitment
    );
    assert_eq!(
        proof_wrapper.claim.response_commitment,
        verified_claim.response_commitment
    );
    assert_eq!(proof_wrapper.claim.status_code, verified_claim.status_code);
}

#[test]
fn test_risc0_execute_method() {
    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    // Create a mock input
    let input = create_mock_zktls_input();

    // Execute the program (which generates a proof in RISC0's current API)
    let result = prover.execute(&input);

    // Assert that execution was successful
    assert!(result.is_ok(), "Execution failed: {:?}", result.err());
    let verification_result = result.unwrap();

    // Assert that the result indicates success and contains a claim
    assert!(verification_result.is_success());
    assert!(verification_result.claim.is_some());
    assert!(verification_result.error.is_none());
    assert!(verification_result.stats.platform == "risc0");

    // Assert that the claim matches the input domain
    assert_eq!(
        verification_result.claim.unwrap().domain,
        input.domain
    );
}

#[test]
fn test_risc0_proof_serialization_deserialization() {
    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    // Create a mock input
    let input = create_mock_zktls_input();

    // Generate a proof
    let proof_wrapper = prover
        .generate_proof(&input)
        .expect("Proof generation failed");

    // Serialize the proof wrapper
    let serialized_proof =
        bincode::serialize(&proof_wrapper).expect("Failed to serialize proof wrapper");

    // Deserialize the proof wrapper
    let deserialized_proof: RISC0ProofWrapper =
        bincode::deserialize(&serialized_proof)
            .expect("Failed to deserialize proof wrapper");

    // Assert that the deserialized proof matches the original
    assert_eq!(proof_wrapper.claim.domain, deserialized_proof.claim.domain);
    assert_eq!(
        proof_wrapper.execution_metadata.platform,
        deserialized_proof.execution_metadata.platform
    );
    assert_eq!(proof_wrapper.receipt.len(), deserialized_proof.receipt.len());

    // Verify the deserialized proof
    let verification_result = prover.verify_proof(&deserialized_proof);
    assert!(
        verification_result.is_ok(),
        "Deserialized proof verification failed: {:?}",
        verification_result.err()
    );
}

#[test]
fn test_risc0_error_handling() {
    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    // Test with invalid input (empty certificates)
    let mut invalid_input = create_mock_zktls_input();
    invalid_input.certificates = vec![];

    let result = prover.execute(&invalid_input);

    // Should handle error gracefully
    match result {
        Ok(verification_result) => {
            if verification_result.is_failure() {
                assert!(verification_result.error.is_some(), "Should have error message");
                assert!(verification_result.claim.is_none(), "Should not have claim on error");
            }
        }
        Err(e) => {
            // This is also acceptable - error should be properly typed
            assert!(!e.to_string().is_empty(), "Error should have message");
        }
    }
}

#[test]
fn test_risc0_performance_metrics() {
    // Initialize the RISC0 prover
    let prover = RISC0ZkTlsProver::new();

    // Create a mock input
    let input = create_mock_zktls_input();

    let start_time = std::time::Instant::now();
    let result = prover.execute(&input);
    let total_time = start_time.elapsed();

    assert!(result.is_ok(), "Execution should succeed");

    let verification_result = result.unwrap();
    let metadata = verification_result.stats;

    // Verify performance metrics are reasonable
    assert!(metadata.execution_time_ms > 0, "Should have execution time");
    assert!(metadata.execution_time_ms <= total_time.as_millis() as u64 + 100, 
            "Execution time should be reasonable");
    assert!(metadata.cycles > 0, "Should have cycle count");
    assert!(metadata.memory_usage > 0, "Should have memory usage");
    assert_eq!(metadata.platform, "risc0", "Should be RISC0 platform");
}

#[test]
fn test_risc0_deterministic_execution() {
    // Test that identical inputs produce identical outputs
    let prover = RISC0ZkTlsProver::new();
    let input1 = create_mock_zktls_input();
    let input2 = create_mock_zktls_input();

    let result1 = prover.execute(&input1).expect("First execution should succeed");
    let result2 = prover.execute(&input2).expect("Second execution should succeed");

    // Results should be identical for identical inputs
    assert_eq!(result1.is_success(), result2.is_success());
    assert_eq!(result1.claim, result2.claim);
    assert_eq!(result1.error, result2.error);

    // Execution metadata should be similar (allowing for small timing differences)
    let cycles_diff = (result1.stats.cycles as i64 - result2.stats.cycles as i64).abs();
    assert!(cycles_diff < 1000, "Cycle counts should be similar");
}
