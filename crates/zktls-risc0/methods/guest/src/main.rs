//! RISC0 guest program entry point
//! 
//! This is the main entry point for the RISC0 zkVM guest program that performs
//! complete zkTLS verification using the shared business logic.
//! 
//! Based on the official RISC0 ECDSA P256 example pattern.

use zktls_zkvm::guest::verify_zktls_session;
use zktls_zkvm::types::ZkTlsInput;
use zktls_crypto_risc0::RISC0CryptoProvider;
use risc0_zkvm::guest::env;

/// Main RISC0 guest program entry point
/// 
/// This function runs inside the RISC0 zkVM and performs complete zkTLS verification
/// using the shared business logic from the zktls-zkvm crate. It reads the input
/// from the host, performs verification, and commits the proof claim to the journal.
/// 
/// Based on the official RISC0 ECDSA P256 example pattern:
/// 1. Read input from host using env::read()
/// 2. Perform verification logic
/// 3. Commit result to journal using env::commit()
fn main() {
    // Read the complete ZkTlsInput from the host
    let input: ZkTlsInput = env::read();
    
    // Track execution start for metadata
    let start_cycles = get_risc0_cycles();
    
    // Create RISC0-optimized crypto provider
    let crypto_provider = RISC0CryptoProvider::new();
    
    // Perform complete zkTLS verification using shared business logic with RISC0 crypto
    match verify_zktls_session(&input, crypto_provider) {
        Ok(mut claim) => {
            // Update execution metadata with RISC0-specific information
            let end_cycles = get_risc0_cycles();
            claim.execution_metadata.platform = "risc0".to_string();
            claim.execution_metadata.cycles = end_cycles - start_cycles;
            claim.execution_metadata.memory_usage = estimate_risc0_memory_usage(&input);
            claim.execution_metadata.execution_time_ms = estimate_risc0_execution_time(end_cycles - start_cycles);
            
            // Commit the verified claim to the journal
            // This makes it accessible to the host-side verifier
            env::commit(&claim);
        }
        Err(_error) => {
            // If verification fails, we still need to provide some output
            // Create a minimal claim structure indicating failure
            use zktls_zkvm::types::{ZkTlsProofClaim, ExecutionMetadata};
            
            let failure_claim = ZkTlsProofClaim {
                domain: input.domain.clone(),
                request_commitment: [0u8; 32],
                response_commitment: [0u8; 32],
                status_code: 0, // Indicates verification failure
                tls_version: "unknown".to_string(),
                cipher_suite: "unknown".to_string(),
                certificate_chain_hash: [0u8; 32],
                handshake_transcript_hash: [0u8; 32],
                timestamp: input.timestamp,
                execution_metadata: ExecutionMetadata {
                    cycles: 0,
                    memory_usage: 0,
                    execution_time_ms: 0,
                    platform: "risc0".to_string(),
                    proof_time_ms: 0,
                },
            };
            
            // Commit the failure claim
            env::commit(&failure_claim);
            
            // In a production system, we might want to panic here to prevent
            // invalid proofs from being generated. For now, we'll continue
            // to allow the host to handle the failure case.
        }
    }
}

/// Get RISC0 execution cycles
/// 
/// This function provides RISC0-specific cycle counting for execution metadata.
/// In a real implementation, this would use RISC0's cycle counting mechanisms.
fn get_risc0_cycles() -> u64 {
    // RISC0-specific cycle counting implementation
    // For now, return a reasonable estimate based on typical zkTLS operations
    // In production, this would use RISC0's actual cycle counting APIs
    800000 // RISC0 typically has different cycle characteristics than SP1
}

/// Estimate RISC0 memory usage based on input size
/// 
/// This function provides RISC0-specific memory usage estimation for execution metadata.
fn estimate_risc0_memory_usage(input: &ZkTlsInput) -> u64 {
    // Estimate memory usage based on input characteristics
    let base_memory = 1 * 1024 * 1024; // 1MB base (RISC0 typically uses less memory)
    let input_size = input.handshake_transcript.len() + 
                     input.certificates.iter().map(|c| c.len()).sum::<usize>() +
                     input.http_request.len() + 
                     input.http_response.len();
    
    base_memory + input_size as u64
}

/// Estimate RISC0 execution time based on cycles
/// 
/// This function converts RISC0 cycles to estimated execution time in milliseconds.
fn estimate_risc0_execution_time(cycles: u64) -> u64 {
    // RISC0-specific timing estimation
    // Assuming ~1MHz execution frequency for estimation
    cycles / 1000 // Convert cycles to milliseconds
}
